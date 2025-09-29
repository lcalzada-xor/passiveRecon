package sources

import (
	"context"
	"fmt"

	"passive-rec/internal/runner"
)

func Wayback(ctx context.Context, target string, out chan<- string) error {
	if !runner.HasBin("waybackurls") {
		out <- "meta: waybackurls not found in PATH"
		return nil
	}
	// echo target | waybackurls
	return runner.RunCommand(ctx, "sh", []string{"-c", fmt.Sprintf("echo %s | waybackurls", target)}, out)
}
