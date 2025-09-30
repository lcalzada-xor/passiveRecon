package sources

import (
	"context"
	"fmt"

	"passive-rec/internal/runner"
)

func GAU(ctx context.Context, target string, out chan<- string) error {
	bin, ok := runner.FindBin("gau", "getallurls")
	if !ok {
		out <- "meta: gau/getallurls not found in PATH"
		return runner.ErrMissingBinary
	}
	cmd := fmt.Sprintf("echo %s | %s", target, bin)
	return runner.RunCommand(ctx, "sh", []string{"-c", cmd}, out)
}
