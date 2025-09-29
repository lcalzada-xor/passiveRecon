package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"passive-rec/internal/config"
	"passive-rec/internal/logx"
	"passive-rec/internal/pipeline"
	"passive-rec/internal/sources"
)

func Run(cfg *config.Config) error {
	// preparar sink (writers)
	sink, err := pipeline.NewSink(cfg.OutDir)
	if err != nil {
		return err
	}
	defer sink.Close()
	sink.Start(cfg.Workers)

	// context base
	ctx := context.Background()

	// lanzar fuentes según tools
	bar := newProgressBar(len(cfg.Tools))
	var wg runnerWaitGroup
	for _, t := range cfg.Tools {
		toolName := strings.TrimSpace(t)
		switch strings.ToLower(toolName) {
		case "subfinder":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sources.Subfinder(c, cfg.Target, sink.In())
			})))
		case "assetfinder":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sources.Assetfinder(c, cfg.Target, sink.In())
			})))
		case "amass":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sources.Amass(c, cfg.Target, sink.In())
			})))
		case "waybackurls":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sources.Wayback(c, cfg.Target, sink.In())
			})))
		case "gau":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sources.GAU(c, cfg.Target, sink.In())
			})))
		case "crtsh":
			wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
				return sources.CRTSH(c, cfg.Target, sink.In())
			})))
		case "httpx":
			if cfg.Active {
				wg.Go(bar.Wrap(toolName, runWithTimeout(ctx, cfg.TimeoutS, func(c context.Context) error {
					// leer de domains.passive generado
					return sources.HTTPX(c, "domains.passive", cfg.OutDir, sink.In())
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
	logx.V(1, "modo active=%v; terminado", cfg.Active)
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
			logx.V(1, "source error: %v", err)
		}
	}
}

func runWithTimeout(parent context.Context, seconds int, fn func(context.Context) error) func() error {
	return func() error {
		ctx, cancel := context.WithTimeout(parent, time.Duration(seconds)*time.Second)
		defer cancel()
		return fn(ctx)
	}
}
