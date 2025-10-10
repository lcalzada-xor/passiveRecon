package linkfinderevo

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	maxInputEntries  = 200
	entriesPerSecond = 15
	tmpPrefix        = "passive-rec-linkfinderevo-*"
)

func encodeEntries(entries []string) []byte {
	var buf bytes.Buffer
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		buf.WriteString(trimmed)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func writeInput(tmpDir, label string, data []byte) (string, error) {
	sanitized := sanitizeLabel(label)
	name := fmt.Sprintf("input.%s", sanitized)
	path := filepath.Join(tmpDir, name)
	if err := os.WriteFile(path, data, defaultFilePerm); err != nil {
		return "", fmt.Errorf("write input file: %w", err)
	}
	return path, nil
}

func maybeSampleInput(tmpDir, label string, data []byte, limit int) (string, int, int, error) {
	entries := parseEntries(data)
	total := len(entries)
	if limit <= 0 {
		return "", total, 0, nil
	}
	if total <= limit {
		return "", total, total, nil
	}

	sampled := sampleEntries(entries, limit)
	if len(sampled) == 0 {
		return "", total, 0, nil
	}

	var buf bytes.Buffer
	for _, entry := range sampled {
		buf.Write(entry)
		buf.WriteByte('\n')
	}

	sampleName := fmt.Sprintf("input.%s.sample", sanitizeLabel(label))
	samplePath := filepath.Join(tmpDir, sampleName)
	if err := os.WriteFile(samplePath, buf.Bytes(), defaultFilePerm); err != nil {
		return "", total, len(sampled), fmt.Errorf("write sampled input: %w", err)
	}

	return samplePath, total, len(sampled), nil
}

func parseEntries(data []byte) [][]byte {
	lines := bytes.Split(data, []byte{'\n'})
	entries := make([][]byte, 0, len(lines))
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		entry := make([]byte, len(trimmed))
		copy(entry, trimmed)
		entries = append(entries, entry)
	}
	return entries
}

func sampleEntries(entries [][]byte, limit int) [][]byte {
	if limit <= 0 || len(entries) <= limit {
		return entries
	}
	idxs := rand.Perm(len(entries))[:limit]
	sort.Ints(idxs)
	sampled := make([][]byte, 0, limit)
	for _, idx := range idxs {
		sampled = append(sampled, entries[idx])
	}
	return sampled
}

func sanitizeLabel(label string) string {
	trimmed := strings.TrimSpace(label)
	if trimmed == "" {
		return "input"
	}
	sanitized := strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':':
			return '_'
		default:
			return r
		}
	}, trimmed)
	if sanitized == "" {
		return "input"
	}
	return sanitized
}

func entryBudget(ctx context.Context, maxTotal int) int {
	if maxTotal <= 0 {
		return 0
	}
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		return maxTotal
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}
	budget := int(remaining.Seconds() * entriesPerSecond)
	if budget > maxTotal {
		budget = maxTotal
	}
	if budget < 0 {
		return 0
	}
	return budget
}
