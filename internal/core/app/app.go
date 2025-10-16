package app

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"passive-rec/internal/adapters/sources"
	"passive-rec/internal/core/materializer"
	"passive-rec/internal/core/pipeline"
	"passive-rec/internal/core/runner"
	"passive-rec/internal/platform/config"
	"passive-rec/internal/platform/logx"
)

type sink interface {
	Start(workers int)
	In() chan<- string
	Flush()
	Close() error
	SetStepRecorder(pipeline.StepRecorder)
}

var (
	sinkFactory = func(outdir string, active bool, target string, scopeMode string, lineBuffer int) (sink, error) {
		return pipeline.NewSinkWithConfig(pipeline.SinkConfig{
			Outdir:     outdir,
			Active:     active,
			Target:     target,
			ScopeMode:  scopeMode,
			LineBuffer: lineBuffer,
		})
	}
	sourceSubfinder     = sources.Subfinder
	sourceAssetfinder   = sources.Assetfinder
	sourceRDAP          = sources.RDAP
	sourceAmass         = sources.Amass
	sourceWayback       = sources.Wayback
	sourceGAU           = sources.GAU
	sourceCRTSh         = sources.CRTSH
	sourceCensys        = sources.Censys
	sourceHTTPX         = sources.HTTPX
	sourceSubJS         = sources.SubJS
	sourceLinkFinderEVO = sources.LinkFinderEVO
	sourceDNSX          = sources.DNSX
)

func Run(cfg *config.Config) error {
	outDir, err := prepareOutputDir(cfg.OutDir, cfg.Target)
	if err != nil {
		return err
	}
	cfg.OutDir = outDir

	// Clamp de workers por robustez (evita Start(0)).
	workers := cfg.Workers
	if workers <= 0 {
		workers = 1
	}

	sink, err := sinkFactory(cfg.OutDir, cfg.Active, cfg.Target, cfg.Scope, pipeline.LineBufferSize(workers))
	if err != nil {
		return err
	}
	defer sink.Close()
	sink.Start(workers)

	requested, ordered, unknown := normalizeRequestedTools(cfg)

	cachePath := cachePathFor(cfg.OutDir)
	execCache, err := loadExecutionCache(cachePath)
	if err != nil {
		logx.Warn("Fallo cargar cache de ejecución", logx.Fields{"error": err.Error()})
	}
	if execCache != nil {
		if err := execCache.Prune(cacheMaxAge); err != nil {
			logx.Warn("Fallo depurar cache de ejecución", logx.Fields{"error": err.Error()})
		}
	}

	bar := newProgressBar(len(ordered), nil)
	if bar != nil && len(ordered) > 0 {
		logx.SetOutput(bar.Writer())
		defer logx.SetOutput(nil)
	}

	ctx := context.Background()
	runHash := computeRunHash(cfg, ordered)

	// Inicializar checkpoint manager
	var checkpointMgr *CheckpointManager
	if cfg.CheckpointInterval > 0 {
		interval := time.Duration(cfg.CheckpointInterval) * time.Second
		checkpointMgr = NewCheckpointManager(cfg.OutDir, runHash, cfg.Target, interval)

		// Si resume está habilitado, intentar cargar checkpoint previo
		if cfg.Resume {
			if loaded, err := checkpointMgr.Load(); err != nil {
				logx.Warn("Fallo cargar checkpoint", logx.Fields{"error": err.Error()})
			} else if loaded != nil {
				// Validar que el checkpoint corresponde al mismo target y runHash
				if loaded.Target == cfg.Target && loaded.RunHash == runHash {
					logx.Info("Resumiendo desde checkpoint", logx.Fields{
						"tools_completadas": len(loaded.CompletedTools),
						"progreso":          checkpointMgr.GetProgress(),
					})
				} else {
					logx.Warn("Checkpoint inválido", logx.Fields{"reason": "target o configuración no coinciden"})
					checkpointMgr = NewCheckpointManager(cfg.OutDir, runHash, cfg.Target, interval)
				}
			}
		}

		// Iniciar auto-save
		checkpointMgr.StartAutoSave()
		defer func() {
			checkpointMgr.StopAutoSave()
			// Guardar checkpoint final
			if err := checkpointMgr.Save(); err != nil {
				logx.Warnf("no se pudo guardar checkpoint final: %v", err)
			}
		}()
	}

	opts := orchestratorOptions{
		cfg:        cfg,
		sink:       sink,
		requested:  requested,
		bar:        bar,
		cache:      execCache,
		runHash:    runHash,
		checkpoint: checkpointMgr,
	}

	buildStepsStart := time.Now()
	var steps []toolStep
	for _, name := range ordered {
		if step, ok := defaultSteps[name]; ok {
			steps = append(steps, step)
		}
	}
	buildStepsDuration := time.Since(buildStepsStart)
	logx.Trace("Orquestador: armado de steps", logx.Fields{
		"duration_ms": buildStepsDuration.Milliseconds(),
		"steps_count": len(steps),
	})

	// Informar al usuario sobre optimización de scope
	if strings.ToLower(strings.TrimSpace(cfg.Scope)) == "domain" {
		logx.Debug("Scope configurado como 'domain'", logx.Fields{
			"skip_tools": "amass, subfinder, assetfinder, rdap",
			"reason":     "herramientas de enumeración de subdominios",
		})
		logx.Trace("Certificados del dominio exacto", logx.Fields{
			"tools": "crtsh, censys",
		})
		// Inyectar el dominio target para que las herramientas restantes tengan algo que procesar
		sink.In() <- cfg.Target
		sink.Flush()
		logx.Trace("Dominio target inyectado", logx.Fields{"target": cfg.Target})
	}

	metrics := newPipelineMetrics()
	opts.metrics = metrics
	sink.SetStepRecorder(metrics)
	originalHTTPXHook := sources.HTTPXInputsHook
	sources.HTTPXInputsHook = func(count int) {
		if metrics != nil {
			metrics.RecordInputs(toolHTTPX, "", int64(count))
		}
	}
	defer func() { sources.HTTPXInputsHook = originalHTTPXHook }()

	pipelineStart := time.Now()
	runPipeline(ctx, steps, opts)
	pipelineDuration := time.Since(pipelineStart)
	logx.Info("Pipeline ejecutado", logx.Fields{
		"duration_ms": pipelineDuration.Milliseconds(),
		"steps":       len(steps),
	})

	if metrics != nil {
		logPipelineMetrics(metrics, runHash, pipelineDuration)
		if err := writePipelineMetricsReport(cfg.OutDir, metrics, pipelineDuration); err != nil {
			logx.Warn("Fallo escribir métricas", logx.Fields{"error": err.Error()})
		}
	}

	sink.Flush()
	executePostProcessing(ctx, cfg, sink, bar, unknown)
	sink.Flush()

	if err := materializer.Materialize(cfg.OutDir); err != nil {
		return err
	}

	// Eliminar checkpoint al completar exitosamente
	if checkpointMgr != nil {
		if err := checkpointMgr.Remove(); err != nil {
			logx.Warn("Fallo eliminar checkpoint", logx.Fields{"error": err.Error()})
		} else {
			logx.Trace("Checkpoint eliminado", logx.Fields{"status": "exitoso"})
		}
	}

	logx.Info("Ejecución completada", logx.Fields{"active_mode": cfg.Active})
	return nil
}

func normalizeRequestedTools(cfg *config.Config) (map[string]bool, []string, []string) {
	normalizeTool := func(name string) string {
		return strings.ToLower(strings.TrimSpace(name))
	}

	requested := make(map[string]bool)
	var normalizedOrder []string
	for _, raw := range cfg.Tools {
		tool := normalizeTool(raw)
		if tool == "" {
			continue
		}
		normalizedOrder = append(normalizedOrder, tool)
		requested[tool] = true
	}

	// Si hay fuentes de URLs, fuerza dedupe salvo que ya lo pidan.
	if (requested["waybackurls"] || requested["gau"]) && !requested["dedupe"] {
		requested["dedupe"] = true
	}

	known := make(map[string]struct{}, len(defaultToolOrder))
	for _, tool := range defaultToolOrder {
		known[tool] = struct{}{}
	}

	var ordered []string
	seenOrdered := make(map[string]bool, len(defaultToolOrder))

	// Mantener orden por defecto para las herramientas conocidas seleccionadas.
	for _, tool := range defaultToolOrder {
		if requested[tool] {
			ordered = append(ordered, tool)
			seenOrdered[tool] = true
		}
	}

	// Añadir desconocidas manteniendo el orden en que las pidió el usuario.
	var unknown []string
	for _, tool := range normalizedOrder {
		if seenOrdered[tool] {
			continue
		}
		if _, ok := known[tool]; !ok {
			ordered = append(ordered, tool)
			unknown = append(unknown, tool)
			seenOrdered[tool] = true
		}
	}

	return requested, ordered, unknown
}

type runnerWaitGroup struct{ ch []chan error }

func (w *runnerWaitGroup) Go(fn func() error) {
	errCh := make(chan error, 1)
	w.ch = append(w.ch, errCh)
	go func() {
		// Convertir pánico en error para no tumbar el orquestador.
		defer func() {
			if r := recover(); r != nil {
				// Si hay pánico, devolvemos un error genérico para el logger.
				errCh <- errors.New("source panicked")
				return
			}
		}()
		errCh <- fn()
	}()
}

func (w *runnerWaitGroup) Wait() {
	for _, ch := range w.ch {
		if err := <-ch; err != nil {
			if errors.Is(err, runner.ErrMissingBinary) {
				continue
			}
			logx.Warn("Error en fuente", logx.Fields{"error": err.Error()})
		}
	}
}

func runWithTimeout(parent context.Context, seconds int, fn func(context.Context) error) func() error {
	return func() error {
		ctx, cancel := runner.WithTimeout(parent, seconds)
		defer cancel()
		return fn(ctx)
	}
}

func prepareOutputDir(baseOutDir, target string) (string, error) {
	sanitized := sanitizeTargetDir(target)
	finalOutDir := filepath.Join(baseOutDir, sanitized)
	if err := os.MkdirAll(finalOutDir, 0o755); err != nil {
		return "", err
	}
	return finalOutDir, nil
}

func sanitizeTargetDir(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return "passive_rec"
	}

	if strings.Contains(trimmed, "://") {
		if u, err := url.Parse(trimmed); err == nil {
			if host := u.Hostname(); host != "" {
				trimmed = host
			}
		}
	}

	trimmed = strings.Trim(trimmed, "/")
	if trimmed == "" {
		return "passive_rec"
	}

	replacer := strings.NewReplacer(
		".", "_",
		"/", "_",
		"\\", "_",
	)
	sanitized := replacer.Replace(trimmed)
	sanitized = strings.Trim(sanitized, "_")
	if sanitized == "" {
		return "passive_rec"
	}
	return sanitized
}
