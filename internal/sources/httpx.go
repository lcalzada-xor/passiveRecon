package sources

import (
	"context"
	"fmt"
	"path/filepath"

	"passive-rec/internal/runner"
)

func HTTPX(ctx context.Context, domainsFile, outdir string, out chan<- string) error {
	if !runner.HasBin("httpx") {
		out <- "meta: httpx not found in PATH"
		return nil
	}
	return runner.RunCommand(ctx, "sh",
		[]string{"-c", fmt.Sprintf("cat %s | httpx -status -title -silent",
			filepath.Join(outdir, domainsFile))},
		out,
	)
}
