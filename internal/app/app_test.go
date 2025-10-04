package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"passive-rec/internal/config"
)

func TestRunWithTimeoutDefault(t *testing.T) {
	parent := context.Background()
	invoked := false

	err := runWithTimeout(parent, 0, func(ctx context.Context) error {
		invoked = true

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}

		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatalf("expected deadline to be set when timeout is zero")
		}
		if remaining := time.Until(deadline); remaining < time.Second {
			t.Fatalf("expected generous timeout, got remaining=%s", remaining)
		}
		return nil
	})()

	if err != nil {
		t.Fatalf("runWithTimeout returned error: %v", err)
	}
	if !invoked {
		t.Fatalf("expected function to be invoked")
	}
}

func TestNormalizeRequestedToolsAddsDedupeAndOrders(t *testing.T) {
	cfg := &config.Config{Tools: []string{" Subfinder ", "GAU", "custom", "subfinder", "Waybackurls"}}

	requested, ordered, unknown := normalizeRequestedTools(cfg)

	if !requested["dedupe"] {
		t.Fatalf("expected dedupe to be added when gau/waybackurls are requested")
	}

	wantOrdered := append(selectFromOrder(defaultToolOrder, "subfinder", "dedupe", "waybackurls", "gau"), "custom")
	if diff := cmp.Diff(wantOrdered, ordered); diff != "" {
		t.Fatalf("unexpected ordered tools (-want +got):\n%s", diff)
	}

	wantUnknown := []string{"custom"}
	if diff := cmp.Diff(wantUnknown, unknown); diff != "" {
		t.Fatalf("unexpected unknown tools (-want +got):\n%s", diff)
	}
}

func TestNormalizeRequestedToolsTrimsAndDeduplicates(t *testing.T) {
	cfg := &config.Config{Tools: []string{"  ", "Amass", "amass", "SubJS", "httpx"}}

	requested, ordered, unknown := normalizeRequestedTools(cfg)

	if len(unknown) != 0 {
		t.Fatalf("expected no unknown tools, got %v", unknown)
	}

	wantOrdered := selectFromOrder(defaultToolOrder, "amass", "httpx", "subjs")
	if diff := cmp.Diff(wantOrdered, ordered); diff != "" {
		t.Fatalf("unexpected ordered tools (-want +got):\n%s", diff)
	}

	if !requested["amass"] || !requested["httpx"] || !requested["subjs"] {
		t.Fatalf("expected requested map to include normalized tool names, got %v", requested)
	}
}

func selectFromOrder(order []string, names ...string) []string {
	include := make(map[string]struct{}, len(names))
	for _, name := range names {
		include[name] = struct{}{}
	}
	var result []string
	for _, tool := range order {
		if _, ok := include[tool]; ok {
			result = append(result, tool)
		}
	}
	return result
}

func TestRunFlushesBeforeReportForDeferredSources(t *testing.T) {
	originalSinkFactory := sinkFactory
	originalHTTPX := sourceHTTPX
	t.Cleanup(func() {
		sinkFactory = originalSinkFactory
		sourceHTTPX = originalHTTPX
	})

	dir := t.TempDir()

	var (
		mu      sync.Mutex
		flushes int
	)

	sinkFactory = func(outdir string, active bool) (sink, error) {
		ts, err := newTestSink(outdir)
		if err != nil {
			return nil, err
		}
		ts.onFlush = func() {
			mu.Lock()
			flushes++
			mu.Unlock()
		}
		return ts, nil
	}

	sourceHTTPX = func(ctx context.Context, list []string, outdir string, out chan<- string) error {
		out <- "http://deferred.test/path"
		return nil
	}

	cfg := &config.Config{
		Target:  "example.com",
		OutDir:  dir,
		Workers: 1,
		Active:  true,
		Tools:   []string{"httpx"},
		Report:  true,
	}

	if err := Run(cfg); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	mu.Lock()
	flushCount := flushes
	mu.Unlock()
	if flushCount < 2 {
		t.Fatalf("expected at least two flushes, got %d", flushCount)
	}

	reportPath := filepath.Join(dir, sanitizeTargetDir(cfg.Target), "report.html")
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	if !strings.Contains(string(reportData), "deferred.test") {
		t.Fatalf("expected report to include deferred source data, got:\n%s", string(reportData))
	}
}

func TestDedupeDomainListNormalizesAndFilters(t *testing.T) {
	dir := t.TempDir()
	domainsDir := filepath.Join(dir, "domains")
	if err := os.MkdirAll(domainsDir, 0o755); err != nil {
		t.Fatalf("mkdir domains: %v", err)
	}

	contents := strings.Join([]string{
		"Example.com",
		"api.example.com ",
		"*.ignored.example.com",
		"https://WWW.Example.com/path",
		"login.example.com [source]",
		"  # comment",
		"[2001:db8::1]:443",
		"api.example.com",
	}, "\n")

	inputPath := filepath.Join(domainsDir, "domains.passive")
	if err := os.WriteFile(inputPath, []byte(contents), 0o644); err != nil {
		t.Fatalf("write domains.passive: %v", err)
	}

	got, err := dedupeDomainList(dir)
	if err != nil {
		t.Fatalf("dedupeDomainList returned error: %v", err)
	}

	want := []string{"2001:db8::1", "api.example.com", "example.com", "login.example.com"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected dedupe output (-want +got):\n%s", diff)
	}

	dedupePath := filepath.Join(domainsDir, "domains.dedupe")
	data, err := os.ReadFile(dedupePath)
	if err != nil {
		t.Fatalf("read domains.dedupe: %v", err)
	}
	trimmed := strings.TrimSpace(string(data))
	var lines []string
	if trimmed != "" {
		lines = strings.Split(trimmed, "\n")
	}
	if diff := cmp.Diff(want, lines); diff != "" {
		t.Fatalf("unexpected domains.dedupe contents (-want +got):\n%s", diff)
	}
}

type testSink struct {
	outdir  string
	lines   chan string
	pending []string
	mu      sync.Mutex
	onFlush func()
}

func newTestSink(outdir string) (*testSink, error) {
	if err := os.MkdirAll(outdir, 0o755); err != nil {
		return nil, err
	}
	return &testSink{
		outdir: outdir,
		lines:  make(chan string, 32),
	}, nil
}

func (s *testSink) Start(workers int) {
	// No background workers required for the test sink.
}

func (s *testSink) In() chan<- string {
	return s.lines
}

func (s *testSink) Flush() {
	s.mu.Lock()
	for {
		select {
		case line, ok := <-s.lines:
			if !ok {
				break
			}
			s.pending = append(s.pending, line)
		default:
			goto drained
		}
	}
drained:
	pending := s.pending
	s.pending = nil
	onFlush := s.onFlush
	s.mu.Unlock()

	if onFlush != nil {
		onFlush()
	}

	for _, line := range pending {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		isActive := false
		if strings.HasPrefix(trimmed, "active:") {
			isActive = true
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "active:"))
			if trimmed == "" {
				continue
			}
		}

		targetFile := filepath.Join("domains", "domains.passive")
		if isActive {
			targetFile = filepath.Join("domains", "domains.active")
		}

		if strings.HasPrefix(trimmed, "meta: ") {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "meta: "))
			if isActive {
				targetFile = "meta.active"
			} else {
				targetFile = "meta.passive"
			}
		} else if strings.HasPrefix(trimmed, "js: ") {
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "js: "))
			targetFile = filepath.Join("routes", "js", "js.passive")
		} else if strings.Contains(trimmed, "://") || strings.Contains(trimmed, "/") {
			if isActive {
				targetFile = filepath.Join("routes", "routes.active")
			} else {
				targetFile = filepath.Join("routes", "routes.passive")
			}
		}
		appendLine(filepath.Join(s.outdir, targetFile), trimmed)
	}
}

func (s *testSink) Close() error {
	close(s.lines)
	return nil
}

func appendLine(path, line string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		panic(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		panic(err)
	}
}
