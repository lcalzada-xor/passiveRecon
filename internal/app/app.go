package app

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"passive-rec/internal/config"
	"passive-rec/internal/logx"
	"passive-rec/internal/pipeline"
	"passive-rec/internal/runner"
	"passive-rec/internal/sources"
)

type sink interface {
	Start(workers int)
	In() chan<- string
	Flush()
	Close() error
}

var (
	sinkFactory = func(outdir string, active bool) (sink, error) {
		return pipeline.NewSink(outdir, active)
	}
	sourceSubfinder   = sources.Subfinder
	sourceAssetfinder = sources.Assetfinder
	sourceAmass       = sources.Amass
	sourceWayback     = sources.Wayback
	sourceGAU         = sources.GAU
	sourceCRTSh       = sources.CRTSH
	sourceCensys      = sources.Censys
	sourceHTTPX       = sources.HTTPX
	sourceSubJS       = sources.SubJS
)

func Run(cfg *config.Config) error {
	outDir, err := prepareOutputDir(cfg.OutDir, cfg.Target)
	if err != nil {
		return err
	}
	cfg.OutDir = outDir

	sink, err := sinkFactory(cfg.OutDir, cfg.Active)
	if err != nil {
		return err
	}
	defer sink.Close()
	sink.Start(cfg.Workers)

	requested, ordered, unknown := normalizeRequestedTools(cfg)

	bar := newProgressBar(len(ordered), nil)
	if bar != nil && len(ordered) > 0 {
		logx.SetOutput(bar.Writer())
		defer logx.SetOutput(nil)
	}

	ctx := context.Background()
	opts := orchestratorOptions{
		cfg:       cfg,
		sink:      sink,
		requested: requested,
		bar:       bar,
	}

	var steps []toolStep
	for _, name := range ordered {
		if step, ok := defaultSteps[name]; ok {
			steps = append(steps, step)
		}
	}

	runPipeline(ctx, steps, opts)

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

	known := map[string]struct{}{
		"amass": {}, "subfinder": {}, "assetfinder": {}, "crtsh": {},
		"censys": {}, "dedupe": {}, "waybackurls": {}, "gau": {},
		"httpx": {}, "subjs": {},
	}

	pipelineOrder := []string{"amass", "subfinder", "assetfinder", "crtsh", "censys", "dedupe", "waybackurls", "gau", "httpx", "subjs"}

	var ordered []string
	seenOrdered := make(map[string]bool)
	for _, tool := range pipelineOrder {
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

	bar := newProgressBar(len(ordered), nil)
	if bar != nil && len(ordered) > 0 {
		logx.SetOutput(bar.Writer())
		defer logx.SetOutput(nil)
	}

	runSequential := func(name string, fn func(context.Context) error) {
		if !requested[name] {
			return
		}
		task := runWithTimeout(ctx, cfg.TimeoutS, fn)
		if bar != nil {
			task = bar.Wrap(name, task)
		}
		if err := task(); err != nil {
			if errors.Is(err, runner.ErrMissingBinary) {
				return
			}
			logx.Warnf("source error: %v", err)
		}
	}

	runConcurrent := func(names []string, builder func(string) func(context.Context) error) {
		var wg runnerWaitGroup
		for _, name := range names {
			if !requested[name] {
				continue
			}
			fn := builder(name)
			if fn == nil {
				continue
			}
			task := runWithTimeout(ctx, cfg.TimeoutS, fn)
			if bar != nil {
				task = bar.Wrap(name, task)
			}
			wg.Go(task)
		}
		wg.Wait()
	}

	runSequential("amass", func(c context.Context) error {
		return sourceAmass(c, cfg.Target, sink.In(), cfg.Active)
	})

	runConcurrent([]string{"subfinder", "assetfinder"}, func(name string) func(context.Context) error {
		switch name {
		case "subfinder":
			return func(c context.Context) error {
				return sourceSubfinder(c, cfg.Target, sink.In())
			}
		case "assetfinder":
			return func(c context.Context) error {
				return sourceAssetfinder(c, cfg.Target, sink.In())
			}
		default:
			return nil
		}
	})

	runConcurrent([]string{"crtsh", "censys"}, func(name string) func(context.Context) error {
		switch name {
		case "crtsh":
			return func(c context.Context) error {
				return sourceCRTSh(c, cfg.Target, sink.In())
			}
		case "censys":
			return func(c context.Context) error {
				return sourceCensys(c, cfg.Target, cfg.CensysAPIID, cfg.CensysAPISecret, sink.In())
			}
		default:
			return nil
		}
	})

	sink.Flush()

	domainListFile := filepath.Join("domains", "domains.passive")
	var (
		dedupedDomains []string
		dedupeExecuted bool
	)
	if requested["dedupe"] {
		runSequential("dedupe", func(context.Context) error {
			domains, err := dedupeDomainList(cfg.OutDir)
			if err != nil {
				return err
			}
			dedupedDomains = domains
			domainListFile = filepath.Join("domains", "domains.dedupe")
			dedupeExecuted = true
			sink.In() <- fmt.Sprintf("meta: dedupe retained %d domains", len(domains))
			return nil
		})
	}

	if dedupeExecuted && len(dedupedDomains) == 0 {
		sink.In() <- "meta: dedupe produced no domains"
	}

	if requested["waybackurls"] || requested["gau"] {
		if len(dedupedDomains) == 0 {
			if requested["waybackurls"] {
				sink.In() <- "meta: waybackurls skipped (no domains after dedupe)"
				if bar != nil {
					bar.StepDone("waybackurls", "omitido")
				}
			}
			if requested["gau"] {
				sink.In() <- "meta: gau skipped (no domains after dedupe)"
				if bar != nil {
					bar.StepDone("gau", "omitido")
				}
			}
		} else {
			var wg runnerWaitGroup
			if requested["waybackurls"] {
				task := runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
					return sourceWayback(c, dedupedDomains, sink.In())
				})
				if bar != nil {
					task = bar.Wrap("waybackurls", task)
				}
				wg.Go(task)
			}
			if requested["gau"] {
				task := runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
					return sourceGAU(c, dedupedDomains, sink.In())
				})
				if bar != nil {
					task = bar.Wrap("gau", task)
				}
				wg.Go(task)
			}
			wg.Wait()
		}
	}

	sink.Flush()

	if requested["httpx"] {
		if !cfg.Active {
			sink.In() <- "meta: httpx skipped (requires --active)"
			if bar != nil {
				bar.StepDone("httpx", "omitido")
			}
		} else {
			sink.Flush()
			inputs := []string{domainListFile, filepath.Join("routes", "routes.passive")}
			task := runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sourceHTTPX(c, inputs, cfg.OutDir, sink.In())
			})
			if bar != nil {
				task = bar.Wrap("httpx", task)
			}
			if err := task(); err != nil {
				if !errors.Is(err, runner.ErrMissingBinary) {
					logx.Warnf("source error: %v", err)
				}
			}
		}
	}

	sink.Flush()

	if requested["subjs"] {
		if !cfg.Active {
			sink.In() <- "meta: subjs skipped (requires --active)"
			if bar != nil {
				bar.StepDone("subjs", "omitido")
			}
		} else {
			task := runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sourceSubJS(c, filepath.Join("routes", "routes.active"), cfg.OutDir, sink.In())
			})
			if bar != nil {
				task = bar.Wrap("subjs", task)
			}
			if err := task(); err != nil {
				if !errors.Is(err, runner.ErrMissingBinary) {
					logx.Warnf("source error: %v", err)
				}
			}
		}
	}

	sink.Flush()

	for _, tool := range unknown {
		sink.In() <- fmt.Sprintf("meta: unknown tool: %s", tool)
		if bar != nil {
			bar.StepDone(tool, "desconocido")
		}
	}

	if cfg.Report {
		sinkFiles := report.DefaultSinkFiles(cfg.OutDir)
		if err := report.Generate(ctx, cfg, sinkFiles); err != nil {
			logx.Warnf("no se pudo generar report.html: %v", err)
		} else {
			logx.Infof("Informe HTML generado en %s", filepath.Join(cfg.OutDir, "report.html"))
		}
	}
	if missing := bar.MissingTools(); len(missing) > 0 {
		logx.Infof("Herramientas faltantes en el sistema: %s", strings.Join(missing, ", "))
	}
	logx.Infof("modo active=%v; terminado", cfg.Active)
	return nil
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
