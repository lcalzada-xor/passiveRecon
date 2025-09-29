package sources

import (
	"context"
	"fmt"

	"passive-rec/internal/runner"
)

func GAU(ctx context.Context, target string, out chan<- string) error {
	if !runner.HasBin("gau") {
		out <- "meta: gau not found in PATH"
		return nil
	}
	return runner.RunCommand(ctx, "sh", []string{"-c", fmt.Sprintf("echo %s | gau", target)}, out)
}
