package app

import (
	"bufio"
	"errors"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
		normalized := normalizeDedupeDomain(scanner.Text())
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

func normalizeDedupeDomain(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "#") {
		return ""
	}
	if idx := strings.IndexAny(trimmed, " \t"); idx != -1 {
		trimmed = trimmed[:idx]
	}
	if trimmed == "" {
		return ""
	}

	candidate := trimmed
	var parsed *url.URL
	var err error
	if strings.Contains(candidate, "://") {
		parsed, err = url.Parse(candidate)
	} else {
		parsed, err = url.Parse("http://" + candidate)
	}
	if err == nil && parsed != nil {
		hostPort := parsed.Host
		hostname := parsed.Hostname()
		if hostname != "" && !(strings.Count(hostPort, ":") > 1 && !strings.Contains(hostPort, "[")) {
			candidate = hostname
		} else if hostPort != "" {
			candidate = hostPort
		}
	}

	if candidate == "" {
		return ""
	}

	if at := strings.LastIndex(candidate, "@"); at != -1 {
		candidate = candidate[at+1:]
	}

	if idx := strings.IndexAny(candidate, "/?#"); idx != -1 {
		candidate = candidate[:idx]
	}

	if candidate == "" {
		return ""
	}

	if host, _, err := net.SplitHostPort(candidate); err == nil {
		candidate = host
	}

	if strings.HasPrefix(candidate, "[") && strings.HasSuffix(candidate, "]") {
		candidate = strings.Trim(candidate, "[]")
	}

	lowered := strings.ToLower(candidate)
	if strings.HasPrefix(lowered, "www.") {
		lowered = lowered[4:]
	}

	if strings.Contains(lowered, "*") {
		return ""
	}

	return lowered
}
