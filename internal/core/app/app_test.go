package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/core/runner"
	"passive-rec/internal/platform/config"
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

	sinkFactory = func(outdir string, active bool, target string, lineBuffer int) (sink, error) {
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

	sourceHTTPX = func(ctx context.Context, outdir string, out chan<- string) error {
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

func TestComputeStepTimeoutUsesBaseAndDynamicCalculator(t *testing.T) {
	state := &pipelineState{DedupedDomains: make([]string, 300)}
	opts := orchestratorOptions{cfg: &config.Config{TimeoutS: 150, Workers: 3}}
	base := baseTimeoutSeconds(opts.cfg.TimeoutS)
	clamp := func(v int) int {
		if v < minToolTimeoutSeconds {
			return minToolTimeoutSeconds
		}
		if v > maxToolTimeoutSeconds {
			return maxToolTimeoutSeconds
		}
		return v
	}

	tests := []struct {
		name string
		step toolStep
		want int
	}{
		{
			name: "default base",
			step: toolStep{Name: "noop"},
			want: clamp(base),
		},
		{
			name: "waybackurls dynamic",
			step: toolStep{Name: "waybackurls", Timeout: timeoutWaybackurls},
			want: clamp(base + len(state.DedupedDomains)/20),
		},
		{
			name: "gau dynamic",
			step: toolStep{Name: "gau", Timeout: timeoutGAU},
			want: clamp(base + len(state.DedupedDomains)/15),
		},
		{
			name: "httpx dynamic",
			step: toolStep{Name: "httpx", Timeout: timeoutHTTPX},
			want: clamp(base + len(state.DedupedDomains)/(opts.cfg.Workers*2)),
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tt.name, func(t *testing.T) {
			got := computeStepTimeout(tc.step, state, opts)
			if got != tc.want {
				t.Fatalf("computeStepTimeout() = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestComputeStepTimeoutClampAndFallback(t *testing.T) {
	state := &pipelineState{DedupedDomains: make([]string, 1000)}
	opts := orchestratorOptions{cfg: &config.Config{TimeoutS: 0, Workers: 0}}
	step := toolStep{
		Name: "httpx",
		Timeout: func(state *pipelineState, opts orchestratorOptions) int {
			return maxToolTimeoutSeconds * 2
		},
	}

	got := computeStepTimeout(step, state, opts)
	if got != maxToolTimeoutSeconds {
		t.Fatalf("expected timeout to be clamped to max (%d), got %d", maxToolTimeoutSeconds, got)
	}

	defaultStep := toolStep{Name: "noop"}
	gotBase := computeStepTimeout(defaultStep, state, opts)
	if gotBase != defaultToolTimeoutSeconds {
		t.Fatalf("expected fallback timeout %d, got %d", defaultToolTimeoutSeconds, gotBase)
	}
}

func TestExecuteStepSkipsWhenNotRequested(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sink, err := newTestSink(dir)
	if err != nil {
		t.Fatalf("newTestSink: %v", err)
	}

	step := toolStep{
		Name: "custom",
		Run: func(context.Context, *pipelineState, orchestratorOptions) error {
			t.Fatalf("step should not run when not requested")
			return nil
		},
	}
	opts := orchestratorOptions{
		cfg:       &config.Config{},
		sink:      sink,
		requested: map[string]bool{"custom": false},
	}

	if task, ok := executeStep(ctx, step, &pipelineState{}, opts); ok || task != nil {
		t.Fatalf("expected executeStep to skip when not requested")
	}
}

func TestExecuteStepRespectsPreconditions(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sink, err := newTestSink(dir)
	if err != nil {
		t.Fatalf("newTestSink: %v", err)
	}

	called := false
	step := toolStep{
		Name: "conditional",
		Run: func(context.Context, *pipelineState, orchestratorOptions) error {
			called = true
			return nil
		},
		Precondition: func(*pipelineState, orchestratorOptions) (bool, string) {
			return false, ""
		},
	}
	opts := orchestratorOptions{
		cfg:       &config.Config{},
		sink:      sink,
		requested: map[string]bool{"conditional": true},
	}

	if task, ok := executeStep(ctx, step, &pipelineState{}, opts); ok || task != nil {
		t.Fatalf("expected executeStep to skip when precondition fails")
	}
	if called {
		t.Fatalf("expected step.Run not to be invoked when precondition fails")
	}
}

func TestExecuteStepHandlesErrors(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sink, err := newTestSink(dir)
	if err != nil {
		t.Fatalf("newTestSink: %v", err)
	}

	opts := orchestratorOptions{
		cfg:  &config.Config{},
		sink: sink,
		requested: map[string]bool{
			"failing": true,
			"missing": true,
		},
	}

	step := toolStep{
		Name: "failing",
		Run: func(context.Context, *pipelineState, orchestratorOptions) error {
			return errors.New("boom")
		},
	}

	task, ok := executeStep(ctx, step, &pipelineState{}, opts)
	if !ok || task == nil {
		t.Fatalf("expected executeStep to return runnable task")
	}
	if err := task(); err != nil {
		t.Fatalf("expected task to swallow non-missing errors, got %v", err)
	}

	stepMissing := toolStep{
		Name: "missing",
		Run: func(context.Context, *pipelineState, orchestratorOptions) error {
			return runner.ErrMissingBinary
		},
	}

	taskMissing, ok := executeStep(ctx, stepMissing, &pipelineState{}, opts)
	if !ok || taskMissing == nil {
		t.Fatalf("expected executeStep to return task for missing binary")
	}
	if err := taskMissing(); !errors.Is(err, runner.ErrMissingBinary) {
		t.Fatalf("expected missing binary error to be propagated, got %v", err)
	}
}

func TestDedupeDomainListNormalizesAndFilters(t *testing.T) {
	dir := t.TempDir()
	writeArtifactsFile(t, dir, []artifacts.Artifact{
		{Type: "domain", Value: "Example.com", Up: true},
		{Type: "domain", Value: "api.example.com ", Up: true},
		{Type: "domain", Value: "*.ignored.example.com", Up: true},
		{Type: "domain", Value: "https://WWW.Example.com/path", Up: true},
		{Type: "domain", Value: "login.example.com [source]", Up: true},
		{Type: "domain", Value: "  # comment", Up: true},
		{Type: "domain", Value: "[2001:db8::1]:443", Up: true},
		{Type: "domain", Value: "api.example.com", Up: true},
	})

	got, err := dedupeDomainList(dir)
	if err != nil {
		t.Fatalf("dedupeDomainList returned error: %v", err)
	}

	want := []string{"2001:db8::1", "api.example.com", "example.com", "login.example.com", "www.example.com"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected dedupe output (-want +got):\n%s", diff)
	}

	dedupePath := filepath.Join(dir, "domains", "domains.dedupe")
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

func writeArtifactsFile(t *testing.T, outdir string, records []artifacts.Artifact) {
	t.Helper()
	path := filepath.Join(outdir, "artifacts.jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create artifacts.jsonl: %v", err)
	}
	defer func() {
		_ = file.Close()
	}()

	encoder := json.NewEncoder(file)
	for _, artifact := range records {
		if err := encoder.Encode(artifact); err != nil {
			t.Fatalf("encode artifact: %v", err)
		}
	}
}

func TestDedupeDomainListWriteError(t *testing.T) {
	dir := t.TempDir()
	conflictPath := filepath.Join(dir, "domains", "domains.dedupe")
	if err := os.MkdirAll(conflictPath, 0o755); err != nil {
		t.Fatalf("mkdir conflicting path: %v", err)
	}

	if _, err := dedupeDomainList(dir); err == nil {
		t.Fatalf("expected error when dedupe output path is a directory")
	} else {
		var pathErr *os.PathError
		if !errors.As(err, &pathErr) {
			t.Fatalf("expected *os.PathError, got %T", err)
		}
	}
}

type testSink struct {
	outdir  string
	lines   chan string
	pending []string
	records []artifacts.Artifact
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

		lineData := trimmed
		var records []artifacts.Artifact

		if strings.HasPrefix(trimmed, "meta: ") {
			content := strings.TrimSpace(strings.TrimPrefix(trimmed, "meta: "))
			if content == "" {
				continue
			}
			lineData = content
			if isActive {
				targetFile = "meta.active"
			} else {
				targetFile = "meta.passive"
			}
			records = append(records, artifacts.Artifact{Type: "meta", Value: content, Active: isActive, Up: true})
		} else if strings.Contains(trimmed, "://") {
			if isActive {
				targetFile = filepath.Join("routes", "routes.active")
			} else {
				targetFile = filepath.Join("routes", "routes.passive")
			}
			base := firstField(trimmed)
			metadata := make(map[string]any)
			if base != trimmed {
				metadata["raw"] = trimmed
			}
			if len(metadata) == 0 {
				metadata = nil
			}
			records = append(records, artifacts.Artifact{Type: "route", Value: base, Active: isActive, Up: true, Metadata: metadata})
			if host := extractHost(base); host != "" {
				records = append(records, artifacts.Artifact{Type: "domain", Value: host, Active: isActive, Up: true})
			}
		} else {
			records = append(records, artifacts.Artifact{Type: "domain", Value: trimmed, Active: isActive, Up: true})
		}

		appendLine(filepath.Join(s.outdir, targetFile), lineData)
		s.appendArtifacts(records...)
	}
}

func (s *testSink) Close() error {
	close(s.lines)
	return nil
}

func (s *testSink) appendArtifacts(records ...artifacts.Artifact) {
	if len(records) == 0 {
		return
	}
	s.mu.Lock()
	s.records = append(s.records, records...)
	snapshot := append([]artifacts.Artifact(nil), s.records...)
	s.mu.Unlock()

	var builder strings.Builder
	for _, artifact := range snapshot {
		data, err := json.Marshal(artifact)
		if err != nil {
			panic(err)
		}
		builder.Write(data)
		builder.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(s.outdir, "artifacts.jsonl"), []byte(builder.String()), 0o644); err != nil {
		panic(err)
	}
}

func firstField(input string) string {
	fields := strings.Fields(strings.TrimSpace(input))
	if len(fields) == 0 {
		return strings.TrimSpace(input)
	}
	return fields[0]
}

func extractHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.HasPrefix(raw, "/") {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Hostname())
}

func appendLine(path, line string) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		panic(err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = f.Close()
	}()
	if _, err := f.WriteString(line + "\n"); err != nil {
		panic(err)
	}
}
