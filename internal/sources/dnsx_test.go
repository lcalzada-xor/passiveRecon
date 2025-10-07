package sources

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"passive-rec/internal/runner"
)

var dnsxTestMu sync.Mutex

func TestDNSXInvokesBinaryAndWritesOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	dnsxTestMu.Lock()
	t.Cleanup(func() { dnsxTestMu.Unlock() })

	originalFinder := dnsxBinFinder
	originalRunCmd := dnsxRunCmd
	originalPTR := dnsxPTRLookup
	dnsxBinFinder = func() (string, error) { return "dnsx", nil }
	var capturedArgs []string
	var inputContents string
	dnsxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		capturedArgs = append([]string{name}, args...)
		if len(args) >= 2 {
			data, err := os.ReadFile(args[len(args)-1])
			if err != nil {
				return err
			}
			inputContents = string(data)
		}
		out <- "vpn.example.com [A] 203.0.113.10"
		out <- "cdn.example.com [CNAME] edge.example.net"
		out <- "vpn.example.com [AAAA] 2001:db8::1"
		return nil
	}
	dnsxPTRLookup = func(ctx context.Context, addr string) ([]string, error) {
		switch addr {
		case "203.0.113.10":
			return []string{"vpn.provider.example."}, nil
		case "2001:db8::1":
			return []string{"vpn6.provider.example."}, nil
		default:
			return nil, nil
		}
	}
	t.Cleanup(func() {
		dnsxBinFinder = originalFinder
		dnsxRunCmd = originalRunCmd
		dnsxPTRLookup = originalPTR
	})

	metaCh := make(chan string, 4)
	if err := DNSX(context.Background(), []string{" vpn.example.com ", "cdn.example.com"}, dir, metaCh); err != nil {
		t.Fatalf("DNSX returned error: %v", err)
	}
	close(metaCh)

	meta := collect(metaCh)
	if len(meta) != 4 {
		t.Fatalf("unexpected meta output count: got %d (%v)", len(meta), meta)
	}
	for i, entry := range meta[:3] {
		if !strings.HasPrefix(entry, "active: dns:") {
			t.Fatalf("expected dns artifact entry, got %q", entry)
		}
		payload := strings.TrimPrefix(entry, "active: dns:")
		var rec dnsxRecord
		if err := json.Unmarshal([]byte(payload), &rec); err != nil {
			t.Fatalf("invalid dns artifact %d: %v", i, err)
		}
	}
	if !strings.Contains(meta[3], "dnsx resolvió 3 registros (2 dominios)") {
		t.Fatalf("unexpected meta output: %v", meta)
	}

	if len(capturedArgs) < 5 || capturedArgs[0] != "dnsx" {
		t.Fatalf("unexpected args: %v", capturedArgs)
	}
	if capturedArgs[1] != "-all" {
		t.Fatalf("expected -all flag, got %v", capturedArgs)
	}
	if capturedArgs[2] != "-json" {
		t.Fatalf("expected -json flag, got %v", capturedArgs)
	}
	if capturedArgs[3] != "-l" {
		t.Fatalf("expected -l flag, got %v", capturedArgs)
	}
	if got, want := inputContents, "vpn.example.com\ncdn.example.com\n"; got != want {
		t.Fatalf("unexpected dnsx input (-want +got):\n-%q\n+%q", want, got)
	}

	output := strings.TrimSpace(readFile(t, filepath.Join(dir, "dns", "dns.active")))
	lines := strings.Split(output, "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 JSON lines, got %d (%q)", len(lines), output)
	}
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			t.Fatalf("unexpected empty JSON line in output: %q", output)
		}
	}
	var records []dnsxRecord
	for _, line := range lines {
		var rec dnsxRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		records = append(records, rec)
	}
	if got := records[0].PTR; len(got) == 0 || got[0] != "vpn.provider.example" {
		t.Fatalf("expected PTR lookup for A record, got %v", records[0].PTR)
	}
	if got := records[2].PTR; len(got) == 0 || got[0] != "vpn6.provider.example" {
		t.Fatalf("expected PTR lookup for AAAA record, got %v", records[2].PTR)
	}
}

func TestDNSXMissingBinary(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	dnsxTestMu.Lock()
	t.Cleanup(func() { dnsxTestMu.Unlock() })

	originalFinder := dnsxBinFinder
	dnsxBinFinder = func() (string, error) { return "", runner.ErrMissingBinary }
	t.Cleanup(func() { dnsxBinFinder = originalFinder })

	metaCh := make(chan string, 1)
	err := DNSX(context.Background(), []string{"example.com"}, dir, metaCh)
	if !errors.Is(err, runner.ErrMissingBinary) {
		t.Fatalf("expected ErrMissingBinary, got %v", err)
	}
	close(metaCh)
	meta := collect(metaCh)
	if len(meta) == 0 || !strings.Contains(meta[0], "dnsx not found") {
		t.Fatalf("expected missing binary meta, got %v", meta)
	}
}

func TestDNSXSkipsWhenNoDomains(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	dnsxTestMu.Lock()
	t.Cleanup(func() { dnsxTestMu.Unlock() })

	originalFinder := dnsxBinFinder
	dnsxBinFinder = func() (string, error) { return "dnsx", nil }
	t.Cleanup(func() { dnsxBinFinder = originalFinder })

	metaCh := make(chan string, 1)
	if err := DNSX(context.Background(), nil, dir, metaCh); err != nil {
		t.Fatalf("DNSX returned error: %v", err)
	}
	close(metaCh)
	meta := collect(metaCh)
	if len(meta) == 0 || !strings.Contains(meta[0], "omitido") {
		t.Fatalf("expected skip meta, got %v", meta)
	}

	output := readFile(t, filepath.Join(dir, "dns", "dns.active"))
	if output != "" {
		t.Fatalf("expected empty output file, got %q", output)
	}
}

func collect(ch <-chan string) []string {
	var out []string
	for v := range ch {
		out = append(out, v)
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("readFile %s: %v", path, err)
	}
	return string(data)
}
