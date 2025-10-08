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
}

var (
	sinkFactory = func(outdir string, active bool, target string, lineBuffer int) (sink, error) {
		return pipeline.NewSink(outdir, active, target, lineBuffer)
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

	sink, err := sinkFactory(cfg.OutDir, cfg.Active, cfg.Target, pipeline.LineBufferSize(cfg.Workers))
	if err != nil {
		return err
	}
	defer sink.Close()
	sink.Start(cfg.Workers)

	requested, ordered, unknown := normalizeRequestedTools(cfg)

	cachePath := cachePathFor(cfg.OutDir)
	execCache, err := loadExecutionCache(cachePath)
	if err != nil {
		logx.Warnf("no se pudo cargar cache de ejecución: %v", err)
	}
	if execCache != nil {
		if err := execCache.Prune(cacheMaxAge); err != nil {
			logx.Warnf("no se pudo depurar cache de ejecución: %v", err)
		}
	}

	bar := newProgressBar(len(ordered), nil)
	if bar != nil && len(ordered) > 0 {
		logx.SetOutput(bar.Writer())
		defer logx.SetOutput(nil)
	}

	ctx := context.Background()
	runHash := computeRunHash(cfg, ordered)
	opts := orchestratorOptions{
		cfg:       cfg,
		sink:      sink,
		requested: requested,
		bar:       bar,
		cache:     execCache,
		runHash:   runHash,
	}

	buildStepsStart := time.Now()
	var steps []toolStep
	for _, name := range ordered {
		if step, ok := defaultSteps[name]; ok {
			steps = append(steps, step)
		}
	}
	buildStepsDuration := time.Since(buildStepsStart)
	logx.Infof("orquestador: armado de steps en %s", buildStepsDuration.Round(time.Millisecond))

	metrics := newPipelineMetrics()
	opts.metrics = metrics

	pipelineStart := time.Now()
	runPipeline(ctx, steps, opts)
	pipelineDuration := time.Since(pipelineStart)
	logx.Infof("orquestador: pipeline ejecutado en %s", pipelineDuration.Round(time.Millisecond))

	if metrics != nil {
		logPipelineMetrics(metrics)
		if err := writePipelineMetricsReport(cfg.OutDir, metrics, pipelineDuration); err != nil {
			logx.Warnf("no se pudo escribir metrics: %v", err)
		}
	}

	sink.Flush()
	executePostProcessing(ctx, cfg, sink, bar, unknown)

	logx.Infof("modo active=%v; terminado", cfg.Active)
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

	if (requested["waybackurls"] || requested["gau"]) && !requested["dedupe"] {
		requested["dedupe"] = true
	}

	known := make(map[string]struct{}, len(defaultToolOrder))
	for _, tool := range defaultToolOrder {
		known[tool] = struct{}{}
	}

	var ordered []string
	seenOrdered := make(map[string]bool)
	for _, tool := range defaultToolOrder {
		if requested[tool] {
			ordered = append(ordered, tool)
			seenOrdered[tool] = true
		}
	}

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
		errCh <- fn()
	}()
}

func (w *runnerWaitGroup) Wait() {
	for _, ch := range w.ch {
		if err := <-ch; err != nil {
			if errors.Is(err, runner.ErrMissingBinary) {
				continue
			}
			logx.Warnf("source error: %v", err)
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
