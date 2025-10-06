package app

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"passive-rec/internal/config"
	"passive-rec/internal/pipeline"
)

type noopSink struct {
	ch chan string
}

func newNoopSink() *noopSink {
	return &noopSink{ch: make(chan string, 10)}
}

func (s *noopSink) Start(int)         {}
func (s *noopSink) In() chan<- string { return s.ch }
func (s *noopSink) Flush()            {}
func (s *noopSink) Close() error      { close(s.ch); return nil }

func TestRunPipelineConcurrentGroupProgress(t *testing.T) {
	var buf bytes.Buffer
	pb := newProgressBar(3, &buf)

	sink := newNoopSink()
	t.Cleanup(func() { _ = sink.Close() })

	requested := map[string]bool{
		"amass":     true,
		"subfinder": true,
		"dedupe":    true,
	}

	opts := orchestratorOptions{
		cfg:       &config.Config{Target: "example.com"},
		sink:      sink,
		requested: requested,
		bar:       pb,
	}

	started := make(chan string, 2)
	release := make(chan struct{})

	steps := []toolStep{
		{
			Name:  "amass",
			Group: "subdomain-sources",
			Run: func(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
				started <- "amass"
				<-release
				return nil
			},
		},
		{
			Name:  "subfinder",
			Group: "subdomain-sources",
			Run: func(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
				started <- "subfinder"
				<-release
				return nil
			},
		},
		{Name: "dedupe", Run: func(ctx context.Context, state *pipelineState, opts orchestratorOptions) error { return nil }},
	}

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		runPipeline(ctx, steps, opts)
		close(done)
	}()

	observed := make(map[string]bool)
	for i := 0; i < 2; i++ {
		select {
		case name := <-started:
			observed[name] = true
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for concurrent sources to start")
		}
	}
	if len(observed) != 2 {
		t.Fatalf("expected both sources to start, got %v", observed)
	}
	if count := strings.Count(buf.String(), "ejecutando"); count < 2 {
		t.Fatalf("expected progress bar to report running steps, got %q", buf.String())
	}

	close(release)
	<-done

	if pb.current != pb.total {
		t.Fatalf("expected progress bar to finish all steps, got %d/%d", pb.current, pb.total)
	}

	if !strings.Contains(buf.String(), "amass (ok)") {
		t.Fatalf("expected amass completion in progress output, got %q", buf.String())
	}
	if !strings.Contains(buf.String(), "subfinder (ok)") {
		t.Fatalf("expected subfinder completion in progress output, got %q", buf.String())
	}
}

func TestRunPipelineConcurrentSourcesDedupesSink(t *testing.T) {
	dir := t.TempDir()

	sink, err := pipeline.NewSink(dir, true, "example.com", pipeline.LineBufferSize(4))
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	sink.Start(4)
	t.Cleanup(func() {
		sink.Flush()
		_ = sink.Close()
	})

	requested := map[string]bool{
		"amass":       true,
		"subfinder":   true,
		"assetfinder": true,
		"dedupe":      true,
	}

	cfg := &config.Config{Target: "example.com", OutDir: dir}
	opts := orchestratorOptions{cfg: cfg, sink: sink, requested: requested}

	started := make(chan string, 3)
	release := make(chan struct{})

	makeSourceStep := func(name string, lines []string) toolStep {
		return toolStep{
			Name:  name,
			Group: "subdomain-sources",
			Run: func(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
				started <- name
				<-release
				for _, line := range lines {
					opts.sink.In() <- line
				}
				return nil
			},
		}
	}

	steps := []toolStep{
		makeSourceStep("amass", []string{
			"example.com",
			"sub.example.com",
			"https://www.example.com/login",
		}),
		makeSourceStep("subfinder", []string{
			"example.com",
			"api.example.com",
			"https://www.example.com/login",
		}),
		makeSourceStep("assetfinder", []string{
			"example.com",
			"api.example.com",
			"active:https://www.example.com/login",
		}),
		{
			Name: "dedupe",
			Run: func(ctx context.Context, state *pipelineState, opts orchestratorOptions) error {
				opts.sink.Flush()
				return nil
			},
		},
	}

	ctx := context.Background()
	done := make(chan struct{})
	go func() {
		runPipeline(ctx, steps, opts)
		close(done)
	}()

	for i := 0; i < 3; i++ {
		select {
		case name := <-started:
			if name == "" {
				t.Fatalf("unexpected empty source name")
			}
		case <-time.After(time.Second):
			t.Fatal("timeout waiting for concurrent sources to start")
		}
	}
	close(release)
	<-done

	sink.Flush()

	domainsPath := filepath.Join(dir, "domains", "domains.passive")
	domains := readLines(t, domainsPath)
	checkNoDuplicates(t, domains, "domains.passive")
	sort.Strings(domains)
	wantDomains := []string{"api.example.com", "example.com", "sub.example.com"}
	if diff := cmp.Diff(wantDomains, domains); diff != "" {
		t.Fatalf("unexpected domains (-want +got):\n%s", diff)
	}

	routesPassive := readLines(t, filepath.Join(dir, "routes", "routes.passive"))
	checkNoDuplicates(t, routesPassive, "routes.passive")
	if len(routesPassive) != 1 || routesPassive[0] != "https://www.example.com/login" {
		t.Fatalf("unexpected passive routes: %#v", routesPassive)
	}

	routesActive := readLines(t, filepath.Join(dir, "routes", "routes.active"))
	checkNoDuplicates(t, routesActive, "routes.active")
	if len(routesActive) != 1 || routesActive[0] != "https://www.example.com/login" {
		t.Fatalf("unexpected active routes: %#v", routesActive)
	}
}

func TestStepDedupeRunsDNSXWhenActive(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "domains"), 0o755); err != nil {
		t.Fatalf("mkdir domains: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "domains", "domains.passive"), []byte("one.example.com\n"), 0o644); err != nil {
		t.Fatalf("write domains.passive: %v", err)
	}

	originalDNSX := sourceDNSX
	defer func() { sourceDNSX = originalDNSX }()

	called := 0
	sourceDNSX = func(ctx context.Context, domains []string, outDir string, out chan<- string) error {
		called++
		if outDir != dir {
			t.Fatalf("expected outDir %s, got %s", dir, outDir)
		}
		if len(domains) != 1 || strings.TrimSpace(domains[0]) != "one.example.com" {
			t.Fatalf("unexpected domains: %v", domains)
		}
		return nil
	}

	sink := newNoopSink()
	t.Cleanup(func() { _ = sink.Close() })

	cfg := &config.Config{OutDir: dir, Active: true}
	opts := orchestratorOptions{cfg: cfg, sink: sink, requested: map[string]bool{"dedupe": true}}

	state := &pipelineState{}
	if err := stepDedupe(context.Background(), state, opts); err != nil {
		t.Fatalf("stepDedupe returned error: %v", err)
	}
	if called != 1 {
		t.Fatalf("expected dnsx to be invoked once, got %d", called)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	raw := strings.Split(strings.ReplaceAll(string(data), "\r", ""), "\n")
	var out []string
	for _, line := range raw {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return out
}

func checkNoDuplicates(t *testing.T, lines []string, label string) {
	t.Helper()
	seen := make(map[string]struct{}, len(lines))
	for _, line := range lines {
		if _, ok := seen[line]; ok {
			t.Fatalf("found duplicate %q in %s: %#v", line, label, lines)
		}
		seen[line] = struct{}{}
	}
}
