package sources

import (
	"context"

	"passive-rec/internal/runner"
)

func Wayback(ctx context.Context, target string, out chan<- string) error {
	if !runner.HasBin("waybackurls") {
		out <- "meta: waybackurls not found in PATH"
		return runner.ErrMissingBinary
	}
	return runner.RunCommand(ctx, "waybackurls", []string{target}, out)
}
