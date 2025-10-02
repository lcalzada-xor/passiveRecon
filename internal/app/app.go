package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"passive-rec/internal/config"
	"passive-rec/internal/logx"
	"passive-rec/internal/pipeline"
	"passive-rec/internal/report"
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
	sinkFactory = func(outdir string) (sink, error) {
		return pipeline.NewSink(outdir)
	}
	sourceSubfinder   = sources.Subfinder
	sourceAssetfinder = sources.Assetfinder
	sourceAmass       = sources.Amass
	sourceWayback     = sources.Wayback
	sourceGAU         = sources.GAU
	sourceCRTSh       = sources.CRTSH
	sourceCensys      = sources.Censys
	sourceHTTPX       = sources.HTTPX
)

func Run(cfg *config.Config) error {
	outDir, err := prepareOutputDir(cfg.OutDir, cfg.Target)
	if err != nil {
		return err
	}
	cfg.OutDir = outDir

	// preparar sink (writers)
	sink, err := sinkFactory(cfg.OutDir)
	if err != nil {
		return err
	}
	defer sink.Close()
	sink.Start(cfg.Workers)

	// context base
	ctx := context.Background()

	// lanzar fuentes según tools
	bar := newProgressBar(len(cfg.Tools), nil)
	if bar != nil && len(cfg.Tools) > 0 {
		logx.SetOutput(bar.Writer())
		defer logx.SetOutput(nil)
	}
	var (
		wg        runnerWaitGroup
		deferreds []func() error
	)
	for _, t := range cfg.Tools {
		toolName := strings.TrimSpace(t)
		switch strings.ToLower(toolName) {
		case "subfinder":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sourceSubfinder(c, cfg.Target, sink.In())
			})))
		case "assetfinder":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sourceAssetfinder(c, cfg.Target, sink.In())
			})))
		case "amass":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sourceAmass(c, cfg.Target, sink.In())
			})))
		case "waybackurls":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sourceWayback(c, cfg.Target, sink.In())
			})))
		case "gau":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sourceGAU(c, cfg.Target, sink.In())
			})))
		case "crtsh":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sourceCRTSh(c, cfg.Target, sink.In())
			})))
		case "censys":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sourceCensys(c, cfg.Target, cfg.CensysAPIID, cfg.CensysAPISecret, sink.In())
			})))
		case "httpx":
			if cfg.Active {
				deferreds = append(deferreds, bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
					// leer de domains/domains.passive y routes/routes.passive generado
					return sourceHTTPX(c, []string{"domains/domains.passive", "routes/routes.passive"}, cfg.OutDir, sink.In())
				})))
			} else {
				sink.In() <- "meta: httpx skipped (requires --active)"
				bar.StepDone(toolName, "omitido")
			}
		default:
			sink.In() <- fmt.Sprintf("meta: unknown tool: %s", t)
			bar.StepDone(toolName, "desconocido")
		}
	}

	wg.Wait()
	sink.Flush()
	for _, task := range deferreds {
		if err := task(); err != nil {
			if errors.Is(err, runner.ErrMissingBinary) {
				continue
			}
			logx.Warnf("source error: %v", err)
		}
	}
	sink.Flush()
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
