package sources

import (
	"context"
	"path/filepath"

	"passive-rec/internal/runner"
)

func HTTPX(ctx context.Context, domainsFile, outdir string, out chan<- string) error {
	if !runner.HasBin("httpx") {
		out <- "meta: httpx not found in PATH"
		return runner.ErrMissingBinary
	}
	return runner.RunCommand(ctx, "httpx", []string{
		"-status",
		"-title",
		"-silent",
		"-l",
		filepath.Join(outdir, domainsFile),
	}, out)
}
