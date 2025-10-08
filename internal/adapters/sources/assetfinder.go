package sources

import (
	"context"
	"strings"
	"sync"

	"passive-rec/internal/core/runner"
)

func Assetfinder(ctx context.Context, target string, out chan<- string) error {
	bin, ok := runner.FindBin("assetfinder")
	if !ok {
		out <- "meta: assetfinder not found in PATH"
		return runner.ErrMissingBinary
	}

	// Canal intermedio para desacoplar la lectura de la ejecución del comando.
	// Un pequeño buffer reduce el riesgo de bloqueo si el consumidor se retrasa.
	filtered := make(chan string, 256)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for line := range filtered {
			if isAssetfinderEmpty(line) {
				continue
			}
			out <- line
		}
	}()

	err := runner.RunCommand(ctx, bin, []string{"--subs-only", target}, filtered)
	close(filtered)
	wg.Wait()
	return err
}

func isAssetfinderEmpty(line string) bool {
	return strings.EqualFold(strings.TrimSpace(line), "no assets were discovered")
}
