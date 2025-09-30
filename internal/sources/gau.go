package sources

import (
	"context"

	"passive-rec/internal/runner"
)

func GAU(ctx context.Context, target string, out chan<- string) error {
	bin, ok := runner.FindBin("gau", "getallurls")
	if !ok {
		out <- "meta: gau/getallurls not found in PATH"
		return runner.ErrMissingBinary
	}
	return runner.RunCommand(ctx, bin, []string{target}, out)

}
