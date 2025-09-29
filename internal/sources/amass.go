package sources

import (
	"context"

	"passive-rec/internal/runner"
)

func Amass(ctx context.Context, target string, out chan<- string) error {
	if !runner.HasBin("amass") {
		out <- "meta: amass not found in PATH"
		return nil
	}
	return runner.RunCommand(ctx, "amass", []string{"enum", "-passive", "-d", target}, out)
}
