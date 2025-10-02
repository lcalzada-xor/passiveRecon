package sources

import (
	"context"
	"strings"
	"sync"

	"passive-rec/internal/runner"
)

func Assetfinder(ctx context.Context, target string, out chan<- string) error {
	if !runner.HasBin("assetfinder") {
		out <- "meta: assetfinder not found in PATH"
		return runner.ErrMissingBinary
	}

	filtered := make(chan string)
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

	err := runner.RunCommand(ctx, "assetfinder", []string{"--subs-only", target}, filtered)
	close(filtered)
	wg.Wait()
	return err
}

func isAssetfinderEmpty(line string) bool {
	return strings.EqualFold(strings.TrimSpace(line), "no assets were discovered")
}
