package sources

import (
	"context"

	"passive-rec/internal/runner"
)

func GAU(ctx context.Context, target string, out chan<- string) error {
	if !runner.HasBin("gau") {
		out <- "meta: gau not found in PATH"
		return runner.ErrMissingBinary
	}
	return runner.RunCommand(ctx, "gau", []string{target}, out)
}
