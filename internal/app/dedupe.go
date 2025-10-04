package app

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"passive-rec/internal/netutil"
)

func dedupeDomainList(outdir string) ([]string, error) {
	inputPath := filepath.Join(outdir, "domains", "domains.passive")
	file, err := os.Open(inputPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := writeDedupeFile(outdir, nil); err != nil {
				return nil, err
			}
			return nil, nil
		}
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	seen := make(map[string]struct{})
	var domains []string
	for scanner.Scan() {
		normalized := netutil.NormalizeDomain(scanner.Text())
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		domains = append(domains, normalized)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	sort.Strings(domains)
	if err := writeDedupeFile(outdir, domains); err != nil {
		return nil, err
	}
	return domains, nil
}

func writeDedupeFile(outdir string, domains []string) error {
	targetDir := filepath.Join(outdir, "domains")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}
	outputPath := filepath.Join(targetDir, "domains.dedupe")

	var builder strings.Builder
	for _, domain := range domains {
		builder.WriteString(domain)
		builder.WriteByte('\n')
	}

	return os.WriteFile(outputPath, []byte(builder.String()), 0o644)
}
