package app

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/platform/netutil"
)

func dedupeDomainList(outdir string) ([]string, error) {
	values, err := artifacts.CollectValues(outdir, "domain", artifacts.AnyState)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := writeDedupeFile(outdir, nil); err != nil {
				return nil, err
			}
			return nil, nil
		}
		return nil, err
	}

	seen := make(map[string]struct{})
	var domains []string
	for _, value := range values {
		normalized := netutil.NormalizeDomain(value)
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		domains = append(domains, normalized)
	}

	sort.Strings(domains)
	if err := writeDedupeFile(outdir, domains); err != nil {
		return nil, err
	}
	return domains, nil
}

func writeDedupeFile(outdir string, domains []string) (err error) {
	targetDir := filepath.Join(outdir, "domains")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}
	outputPath := filepath.Join(targetDir, "domains.dedupe")

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := file.Close(); err == nil && cerr != nil {
			err = cerr
		}
	}()

	writer := bufio.NewWriter(file)
	for _, domain := range domains {
		if _, err := writer.WriteString(domain); err != nil {
			return err
		}
		if err := writer.WriteByte('\n'); err != nil {
			return err
		}
	}

	if err := writer.Flush(); err != nil {
		return err
	}

	return nil
}

func readDedupeFile(outdir string) ([]string, error) {
	path := filepath.Join(outdir, "domains", "domains.dedupe")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	var domains []string
	for scanner.Scan() {
		domain := netutil.NormalizeDomain(scanner.Text())
		if domain == "" {
			continue
		}
		domains = append(domains, domain)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}
