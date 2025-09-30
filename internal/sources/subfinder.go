package sources

import (
	"context"

	"passive-rec/internal/runner"
)

func Subfinder(ctx context.Context, target string, out chan<- string) error {
	if !runner.HasBin("subfinder") {
		out <- "meta: subfinder not found in PATH"
		return runner.ErrMissingBinary
	}
	return runner.RunCommand(ctx, "subfinder", []string{"-d", target, "-silent"}, out)
}
