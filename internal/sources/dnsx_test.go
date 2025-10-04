package sources

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"passive-rec/internal/runner"
)

func TestDNSXInvokesBinaryAndWritesOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	originalFinder := dnsxBinFinder
	originalRunCmd := dnsxRunCmd
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
	t.Cleanup(func() {
		dnsxBinFinder = originalFinder
		dnsxRunCmd = originalRunCmd
	})

	metaCh := make(chan string, 4)
	if err := DNSX(context.Background(), []string{" vpn.example.com ", "cdn.example.com"}, dir, metaCh); err != nil {
		t.Fatalf("DNSX returned error: %v", err)
	}
	close(metaCh)

	meta := collect(metaCh)
	if len(meta) == 0 || !strings.Contains(meta[0], "dnsx resolvió 3 registros (2 dominios)") {
		t.Fatalf("unexpected meta output: %v", meta)
	}

	if len(capturedArgs) < 4 || capturedArgs[0] != "dnsx" {
		t.Fatalf("unexpected args: %v", capturedArgs)
	}
	if capturedArgs[1] != "-all" {
		t.Fatalf("expected -all flag, got %v", capturedArgs)
	}
	if capturedArgs[2] != "-l" {
		t.Fatalf("expected -l flag, got %v", capturedArgs)
	}
	if got, want := inputContents, "vpn.example.com\ncdn.example.com\n"; got != want {
		t.Fatalf("unexpected dnsx input (-want +got):\n-%q\n+%q", want, got)
	}

	output := readFile(t, filepath.Join(dir, "dns", "dns.active"))
	if !strings.Contains(output, "vpn.example.com [A] 203.0.113.10") {
		t.Fatalf("expected output to contain dnsx results, got %q", output)
	}
}

func TestDNSXMissingBinary(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

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
