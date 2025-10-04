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
		out <- "meta: gau/getallurls not found in PATH"
		return runner.ErrMissingBinary
	}

	group, groupCtx := errgroup.WithContext(ctx)
	concurrency := runtime.NumCPU()
	if concurrency <= 0 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)

	scheduled := false
	for _, raw := range targets {
		target := strings.TrimSpace(raw)
		if target == "" {
			continue
		}
		scheduled = true
		current := target
		group.Go(func() error {
			select {
			case sem <- struct{}{}:
			case <-groupCtx.Done():
				return groupCtx.Err()
			}
			defer func() { <-sem }()
			return runner.RunCommand(groupCtx, bin, []string{current}, out)
		})
	}

	if !scheduled {
		return nil
	}

	if err := group.Wait(); err != nil {
		return err
	}
	return nil

}
