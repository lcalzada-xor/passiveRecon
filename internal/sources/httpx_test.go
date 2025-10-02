package sources

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"passive-rec/internal/pipeline"
)

func TestHTTPXCombinesAllLists(t *testing.T) {
	tmp := t.TempDir()
	mustWrite := func(name, contents string) {
		fullPath := filepath.Join(tmp, name)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(fullPath, []byte(contents), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	mustWrite(filepath.Join("domains", "domains.passive"), "example.com\nsub.example.com\n")
	mustWrite(filepath.Join("routes", "routes.passive"), "https://app.example.com/login\n")

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }

	var mu sync.Mutex
	var gotArgs [][]string
	var inputs [][]string
	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		mu.Lock()
		defer mu.Unlock()
		cp := append([]string{}, args...)
		gotArgs = append(gotArgs, cp)

		if len(args) != 5 {
			t.Fatalf("unexpected arg count %d", len(args))
		}

		data, err := os.ReadFile(args[4])
		if err != nil {
			t.Fatalf("read httpx input: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		inputs = append(inputs, lines)
		return nil
	}

	if err := HTTPX(context.Background(), []string{"domains/domains.passive", "routes/routes.passive"}, tmp, make(chan string, 10)); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	if len(gotArgs) != 1 {
		t.Fatalf("expected 1 call to httpxRunCmd, got %d", len(gotArgs))
	}

	if len(inputs) != 1 {
		t.Fatalf("expected to capture a single input slice, got %d", len(inputs))
	}

	want := []string{"example.com", "sub.example.com", "https://app.example.com/login"}
	if diff := cmp.Diff(want, inputs[0]); diff != "" {
		t.Fatalf("unexpected httpx input (-want +got):\n%s", diff)
	}
}

func TestHTTPXSkipsMissingLists(t *testing.T) {
	tmp := t.TempDir()
	mustWrite := func(name, contents string) {
		fullPath := filepath.Join(tmp, name)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", name, err)
		}
		if err := os.WriteFile(fullPath, []byte(contents), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	mustWrite(filepath.Join("routes", "routes.passive"), "https://app.example.com/login\n")

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }

	var mu sync.Mutex
	var captured [][]string
	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		mu.Lock()
		defer mu.Unlock()
		data, err := os.ReadFile(args[4])
		if err != nil {
			t.Fatalf("read httpx input: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		captured = append(captured, lines)
		return nil
	}

	outCh := make(chan string, 5)
	if err := HTTPX(context.Background(), []string{"domains/domains.passive", "routes/routes.passive"}, tmp, outCh); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	if len(captured) != 1 {
		t.Fatalf("expected httpxRunCmd to be invoked once, got %d", len(captured))
	}

	wantInput := []string{"https://app.example.com/login"}
	if diff := cmp.Diff(wantInput, captured[0]); diff != "" {
		t.Fatalf("unexpected httpx input (-want +got):\n%s", diff)
	}

	var meta []string
	for len(outCh) > 0 {
		meta = append(meta, <-outCh)
	}
	sort.Strings(meta)

	wantMeta := []string{"meta: httpx skipped missing input domains/domains.passive"}
	if diff := cmp.Diff(wantMeta, meta); diff != "" {
		t.Fatalf("unexpected meta lines (-want +got):\n%s", diff)
	}
}

func TestHTTPXNormalizesOutput(t *testing.T) {
	inputDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(inputDir, "routes"), 0o755); err != nil {
		t.Fatalf("mkdir routes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "routes", "routes.passive"), []byte("https://app.example.com\n"), 0644); err != nil {
		t.Fatalf("write routes list: %v", err)
	}

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }

	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		out <- "https://app.example.com [200] [Title]"
		return nil
	}

	outCh := make(chan string, 10)
	if err := HTTPX(context.Background(), []string{"routes/routes.passive"}, inputDir, outCh); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	var forwarded []string
	for len(outCh) > 0 {
		forwarded = append(forwarded, <-outCh)
	}

	wantForwarded := []string{"https://app.example.com [200] [Title]", "app.example.com", "meta: [200]", "meta: [Title]"}
	if diff := cmp.Diff(wantForwarded, forwarded); diff != "" {
		t.Fatalf("unexpected forwarded lines (-want +got):\n%s", diff)
	}

	outputDir := t.TempDir()
	sink, err := pipeline.NewSink(outputDir)
	if err != nil {
		t.Fatalf("new sink: %v", err)
	}
	sink.Start(1)
	in := sink.In()
	for _, line := range forwarded {
		in <- line
	}
	if err := sink.Close(); err != nil {
		t.Fatalf("close sink: %v", err)
	}

	readLines := func(path string) []string {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		trimmed := strings.TrimSpace(string(data))
		if trimmed == "" {
			return nil
		}
		return strings.Split(trimmed, "\n")
	}

	routes := readLines(filepath.Join(outputDir, "routes", "routes.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com [200] [Title]"}, routes); diff != "" {
		t.Fatalf("unexpected routes.passive contents (-want +got):\n%s", diff)
	}

	domains := readLines(filepath.Join(outputDir, "domains", "domains.passive"))
	if diff := cmp.Diff([]string{"app.example.com"}, domains); diff != "" {
		t.Fatalf("unexpected domains.passive contents (-want +got):\n%s", diff)
	}

	meta := readLines(filepath.Join(outputDir, "meta.passive"))
	if diff := cmp.Diff([]string{"[200]", "[Title]"}, meta); diff != "" {
		t.Fatalf("unexpected meta.passive contents (-want +got):\n%s", diff)
	}
}

func TestHTTPXSkipsUnresponsiveResults(t *testing.T) {
	inputDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(inputDir, "routes"), 0o755); err != nil {
		t.Fatalf("mkdir routes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "routes", "routes.passive"), []byte("https://app.example.com\n"), 0644); err != nil {
		t.Fatalf("write routes list: %v", err)
	}

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }

	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		out <- "https://down.example.com [0] [connection refused]"
		out <- "https://up.example.com [200] [OK]"
		return nil
	}

	outCh := make(chan string, 10)
	if err := HTTPX(context.Background(), []string{"routes/routes.passive"}, inputDir, outCh); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	var forwarded []string
	for len(outCh) > 0 {
		forwarded = append(forwarded, <-outCh)
	}

	want := []string{
		"down.example.com",
		"meta: [0]",
		"meta: [connection refused]",
		"https://up.example.com [200] [OK]",
		"up.example.com",
		"meta: [200]",
		"meta: [OK]",
	}
	if diff := cmp.Diff(want, forwarded); diff != "" {
		t.Fatalf("unexpected forwarded lines (-want +got):\n%s", diff)
	}
}

func TestHTTPXBatchesLargeInputs(t *testing.T) {
	inputDir := t.TempDir()
	var builder strings.Builder
	for i := 0; i < 5; i++ {
		builder.WriteString(fmt.Sprintf("https://example.com/path-%d\n", i))
	}
	if err := os.MkdirAll(filepath.Join(inputDir, "routes"), 0o755); err != nil {
		t.Fatalf("mkdir routes: %v", err)
	}
	if err := os.WriteFile(filepath.Join(inputDir, "routes", "routes.passive"), []byte(builder.String()), 0644); err != nil {
		t.Fatalf("write routes list: %v", err)
	}

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	originalBatchSize := httpxBatchSize
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
		httpxBatchSize = originalBatchSize
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }
	httpxBatchSize = 2

	var mu sync.Mutex
	var captured [][]string
	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		data, err := os.ReadFile(args[4])
		if err != nil {
			t.Fatalf("read httpx input: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		mu.Lock()
		captured = append(captured, lines)
		mu.Unlock()
		return nil
	}

	if err := HTTPX(context.Background(), []string{"routes/routes.passive"}, inputDir, make(chan string, 10)); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	if len(captured) != 3 {
		t.Fatalf("expected 3 batches, got %d", len(captured))
	}

	var all []string
	for _, batch := range captured {
		all = append(all, batch...)
	}
	sort.Strings(all)

	want := []string{
		"https://example.com/path-0",
		"https://example.com/path-1",
		"https://example.com/path-2",
		"https://example.com/path-3",
		"https://example.com/path-4",
	}

	if diff := cmp.Diff(want, all); diff != "" {
		t.Fatalf("unexpected combined batch contents (-want +got):\n%s", diff)
	}
}

func TestHTTPXSkipsLowPriorityRoutes(t *testing.T) {
	tmp := t.TempDir()
	contents := strings.Join([]string{
		"https://app.example.com/login",
		"https://app.example.com/favicon.ico",
		"https://app.example.com/favicon.ico?version=2",
		"https://app.example.com/images/logo_thumb.jpg",
		"https://app.example.com/static/sprite.png",
		"https://app.example.com/static/sprite.svg#section",
		"https://app.example.com/img/banner.GIF",
		"https://app.example.com/files/THUMBS.DB",
		"https://app.example.com/assets/raw.pgm",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(tmp, "routes.passive"), []byte(contents), 0644); err != nil {
		t.Fatalf("write routes list: %v", err)
	}

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }

	var mu sync.Mutex
	var inputs [][]string
	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		mu.Lock()
		defer mu.Unlock()
		data, err := os.ReadFile(args[4])
		if err != nil {
			t.Fatalf("read httpx input: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		inputs = append(inputs, lines)
		return nil
	}

	if err := HTTPX(context.Background(), []string{"routes.passive"}, tmp, make(chan string, 10)); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	if len(inputs) != 1 {
		t.Fatalf("expected to capture a single input slice, got %d", len(inputs))
	}

	want := []string{"https://app.example.com/login"}
	if diff := cmp.Diff(want, inputs[0]); diff != "" {
		t.Fatalf("unexpected httpx input (-want +got):\n%s", diff)
	}
}
