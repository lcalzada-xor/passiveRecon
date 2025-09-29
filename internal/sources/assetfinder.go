package sources

import (
	"context"

	"passive-rec/internal/runner"
)

func Assetfinder(ctx context.Context, target string, out chan<- string) error {
	if !runner.HasBin("assetfinder") {
		out <- "meta: assetfinder not found in PATH"
		return nil
	}
	return runner.RunCommand(ctx, "assetfinder", []string{"--subs-only", target}, out)
}
