package sources

import (
	"context"
	"path/filepath"

	"passive-rec/internal/runner"
)

func HTTPX(ctx context.Context, domainsFile, outdir string, out chan<- string) error {
	bin, err := runner.HTTPXBin()
	if err != nil {
		out <- "meta: httpx not found in PATH"
		return err
	}
	return runner.RunCommand(ctx, bin, []string{
		"-sc",
		"-title",
		"-silent",
		"-l",
		filepath.Join(outdir, domainsFile),
	}, out)
}
