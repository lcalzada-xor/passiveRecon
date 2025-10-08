package sources

import (
	"context"
	"runtime"
	"strings"

	"golang.org/x/sync/errgroup"

	"passive-rec/internal/runner"
)

func GAU(ctx context.Context, targets []string, out chan<- string) error {
	if len(targets) == 0 {
		return nil
	}

	bin, ok := runner.FindBin("gau", "getallurls")
	if !ok {
		// Mantener exactamente el mismo mensaje meta
		if out != nil {
			out <- "meta: gau/getallurls not found in PATH"
		}
		return runner.ErrMissingBinary
	}

	group, groupCtx := errgroup.WithContext(ctx)

	// Concurrency sensata
	concurrency := runtime.NumCPU()
	if concurrency <= 0 {
		concurrency = 1
	}
	if n := len(targets); n < concurrency {
		concurrency = n
	}
	sem := make(chan struct{}, concurrency)

	scheduled := false
	for _, raw := range targets {
		target := strings.TrimSpace(raw)
		if target == "" {
			continue
		}
		scheduled = true

		// Captura segura por iteración
		current := target

		group.Go(func() (err error) {
			// Adquirir hueco o abortar por cancelación
			select {
			case sem <- struct{}{}:
			case <-groupCtx.Done():
				return groupCtx.Err()
			}
			// Asegurar liberación del hueco
			defer func() {
				<-sem
				// Protegernos ante un posible pánico en RunCommand/consumo
				if r := recover(); r != nil {
					// Convertimos el pánico en error para errgroup
					err = ctx.Err()
					if err == nil {
						err = context.Canceled
					}
				}
			}()

			return runner.RunCommand(groupCtx, bin, []string{current}, out)
		})
	}

	if !scheduled {
		return nil
	}

	return group.Wait()
}
