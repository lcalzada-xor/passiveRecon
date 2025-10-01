package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"unicode"

	"passive-rec/internal/runner"
)

var (
	httpxBinFinder = runner.HTTPXBin
	httpxRunCmd    = runner.RunCommand
	httpxBatchSize = 5000
)

func HTTPX(ctx context.Context, listFiles []string, outdir string, out chan<- string) error {
	bin, err := httpxBinFinder()
	if err != nil {
		out <- "meta: httpx not found in PATH"
		return err
	}

	var combined []string
	seen := make(map[string]struct{})

	for _, list := range listFiles {
		list = strings.TrimSpace(list)
		if list == "" {
			continue
		}

		inputPath := filepath.Join(outdir, list)
		data, err := os.ReadFile(inputPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				out <- "meta: httpx skipped missing input " + list
				continue
			}
			return err
		}

		scanner := bufio.NewScanner(bytes.NewReader(data))
		scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "#") {
				continue
			}
			if _, ok := seen[line]; ok {
				continue
			}
			seen[line] = struct{}{}
			combined = append(combined, line)
		}
		if err := scanner.Err(); err != nil {
			return fmt.Errorf("scan %s: %w", list, err)
		}
	}

	if len(combined) == 0 {
		return nil
	}

	intermediate := make(chan string)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for line := range intermediate {
			for _, normalized := range normalizeHTTPXLine(line) {
				out <- normalized
			}
		}
	}()

	defer func() {
		close(intermediate)
		wg.Wait()
	}()

	batchSize := httpxBatchSize
	if batchSize <= 0 || batchSize > len(combined) {
		batchSize = len(combined)
	}

	for start := 0; start < len(combined); start += batchSize {
		end := start + batchSize
		if end > len(combined) {
			end = len(combined)
		}

		tmpPath, cleanup, err := writeHTTPXInput(combined[start:end])
		if err != nil {
			return err
		}

		err = httpxRunCmd(ctx, bin, []string{
			"-sc",
			"-title",
			"-silent",
			"-l",
			tmpPath,
		}, intermediate)
		cleanup()
		if err != nil {
			return err
		}
	}

	return nil
}

func writeHTTPXInput(lines []string) (string, func(), error) {
	tmpFile, err := os.CreateTemp("", "passive-rec-httpx-*.txt")
	if err != nil {
		return "", nil, err
	}

	cleanup := func() {
		os.Remove(tmpFile.Name())
	}

	writer := bufio.NewWriter(tmpFile)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			tmpFile.Close()
			cleanup()
			return "", nil, err
		}
	}
	if err := writer.Flush(); err != nil {
		tmpFile.Close()
		cleanup()
		return "", nil, err
	}
	if err := tmpFile.Close(); err != nil {
		cleanup()
		return "", nil, err
	}

	return tmpFile.Name(), cleanup, nil
}

func normalizeHTTPXLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	var (
		urlPart  = line
		metaPart string
	)

	if i := strings.IndexAny(line, " \t"); i != -1 {
		urlPart = strings.TrimSpace(line[:i])
		metaPart = strings.TrimSpace(line[i+1:])
	}

	var out []string
	if urlPart != "" {
		combined := urlPart
		if metaPart != "" {
			combined = strings.TrimSpace(urlPart + " " + metaPart)
		}
		out = append(out, combined)
	}

	if metaPart == "" {
		return out
	}

	for _, meta := range splitHTTPXMeta(metaPart) {
		meta = strings.TrimSpace(meta)
		if meta == "" {
			continue
		}
		out = append(out, "meta: "+meta)
	}

	return out
}

func splitHTTPXMeta(meta string) []string {
	meta = strings.TrimSpace(meta)
	if meta == "" {
		return nil
	}

	var (
		parts      []string
		current    strings.Builder
		inBrackets bool
	)

	flush := func() {
		if current.Len() == 0 {
			return
		}
		parts = append(parts, current.String())
		current.Reset()
	}

	for _, r := range meta {
		switch {
		case r == '[':
			if current.Len() > 0 {
				flush()
			}
			inBrackets = true
			current.WriteRune(r)
		case r == ']':
			current.WriteRune(r)
			flush()
			inBrackets = false
		case unicode.IsSpace(r) && !inBrackets:
			flush()
		default:
			current.WriteRune(r)
		}
	}

	flush()

	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}

	return parts
}
