package sources

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"passive-rec/internal/runner"
)

var (
	httpxBinFinder = runner.HTTPXBin
	httpxRunCmd    = runner.RunCommand
)

func HTTPX(ctx context.Context, listFiles []string, outdir string, out chan<- string) error {
	bin, err := httpxBinFinder()
	if err != nil {
		out <- "meta: httpx not found in PATH"
		return err
	}

	for _, list := range listFiles {
		list = strings.TrimSpace(list)
		if list == "" {
			continue
		}

		inputPath := filepath.Join(outdir, list)
		if stat, err := os.Stat(inputPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				out <- "meta: httpx skipped missing input " + list
				continue
			}
			return err
		} else if stat.Size() == 0 {
			// Avoid spawning httpx with empty inputs; just skip silently.
			continue
		}

		if err := httpxRunCmd(ctx, bin, []string{
			"-sc",
			"-title",
			"-silent",
			"-l",
			inputPath,
		}, out); err != nil {
			return err
		}
	}

	return nil
}
