package sources

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/core/materializer"
	"passive-rec/internal/core/pipeline"
)

func writeArtifactsFile(t *testing.T, outdir string, artifactsList []artifacts.Artifact) {
	t.Helper()
	path := filepath.Join(outdir, "artifacts.jsonl")
	writer := artifacts.NewWriterV2(path, "test.com")
	if err := writer.WriteArtifacts(artifactsList); err != nil {
		t.Fatalf("write artifacts: %v", err)
	}
}

func TestHTTPXCombinesAllLists(t *testing.T) {
	tmp := t.TempDir()
	writeArtifactsFile(t, tmp, []artifacts.Artifact{
		{Type: "domain", Value: "example.com", Up: true},
		{Type: "domain", Value: "sub.example.com", Up: true},
		{Type: "route", Value: "https://app.example.com/login", Up: true},
	})

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	originalWorkerCount := httpxWorkerCount
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
		httpxWorkerCount = originalWorkerCount
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }
	httpxWorkerCount = 1

	var mu sync.Mutex
	var gotArgs [][]string
	var inputs [][]string
	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		mu.Lock()
		defer mu.Unlock()
		cp := append([]string{}, args...)
		gotArgs = append(gotArgs, cp)

		inputIdx := -1
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "-l" {
				inputIdx = i + 1
				break
			}
		}
		if inputIdx == -1 {
			t.Fatalf("httpx args missing -l input flag: %v", args)
		}

		data, err := os.ReadFile(args[inputIdx])
		if err != nil {
			t.Fatalf("read httpx input: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		inputs = append(inputs, lines)
		return nil
	}

	if err := HTTPX(context.Background(), tmp, make(chan string, 10)); err != nil {
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

func TestCollectHTTPXInputsDedupesAndReportsMissing(t *testing.T) {
	tmp := t.TempDir()
	writeArtifactsFile(t, tmp, []artifacts.Artifact{
		{Type: "domain", Value: "example.com", Up: true},
		{Type: "domain", Value: "# comment", Up: true},
		{Type: "route", Value: "https://assets.example.com/favicon.ico", Up: true},
		{Type: "domain", Value: "example.com", Up: true},
		{Type: "route", Value: "https://valid.example.com/path", Up: true},
		{Type: "route", Value: "", Up: true},
	})

	originalMeta := httpxMetaEmit
	var mu sync.Mutex
	var meta []string
	httpxMetaEmit = func(line string) {
		mu.Lock()
		defer mu.Unlock()
		meta = append(meta, line)
	}
	t.Cleanup(func() {
		httpxMetaEmit = originalMeta
	})

	combined, err := collectHTTPXInputs(tmp)
	if err != nil {
		t.Fatalf("collect inputs: %v", err)
	}

	wantCombined := []string{"example.com", "https://valid.example.com/path"}
	if diff := cmp.Diff(wantCombined, combined); diff != "" {
		t.Fatalf("unexpected combined inputs (-want +got):\n%s", diff)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(meta) != 0 {
		t.Fatalf("expected no meta output when artifacts exist, got %v", meta)
	}
}

func TestCollectHTTPXInputsMissingArtifacts(t *testing.T) {
	tmp := t.TempDir()

	originalMeta := httpxMetaEmit
	var mu sync.Mutex
	var meta []string
	httpxMetaEmit = func(line string) {
		mu.Lock()
		defer mu.Unlock()
		meta = append(meta, line)
	}
	t.Cleanup(func() { httpxMetaEmit = originalMeta })

	combined, err := collectHTTPXInputs(tmp)
	if err != nil {
		t.Fatalf("collect inputs: %v", err)
	}
	if len(combined) != 0 {
		t.Fatalf("expected empty input when artifacts missing, got %v", combined)
	}

	mu.Lock()
	defer mu.Unlock()
	wantMeta := []string{"active: meta: httpx skipped (missing artifacts.jsonl)"}
	if diff := cmp.Diff(wantMeta, meta); diff != "" {
		t.Fatalf("unexpected meta lines (-want +got):\n%s", diff)
	}
}

func TestForwardHTTPXOutputNormalizes(t *testing.T) {
	outCh := make(chan string, 10)
	intermediate, cleanup := forwardHTTPXOutput(outCh)

	intermediate <- "https://app.example.com [200] [Title] [text/html; charset=utf-8]"

	cleanup()

	var forwarded []string
	for len(outCh) > 0 {
		forwarded = append(forwarded, <-outCh)
	}

	want := []string{
		"active: https://app.example.com [200] [Title] [text/html; charset=utf-8]",
		"active: app.example.com [200] [Title] [text/html; charset=utf-8]",
		"active: html: https://app.example.com",
		"active: meta: [200]",
		"active: meta: [Title]",
		"active: meta: [text/html; charset=utf-8]",
	}
	if diff := cmp.Diff(want, forwarded); diff != "" {
		t.Fatalf("unexpected forwarded lines (-want +got):\n%s", diff)
	}
}

func TestForwardHTTPXOutputStripsANSISequences(t *testing.T) {
	outCh := make(chan string, 10)
	intermediate, cleanup := forwardHTTPXOutput(outCh)

	intermediate <- "https://app.example.com [\x1b[32m200\x1b[0m] [\x1b[35mtext/html\x1b[0m]"

	cleanup()

	var forwarded []string
	for len(outCh) > 0 {
		forwarded = append(forwarded, <-outCh)
	}

	want := []string{
		"active: https://app.example.com [200] [text/html]",
		"active: app.example.com [200] [text/html]",
		"active: html: https://app.example.com",
		"active: meta: [200]",
		"active: meta: [text/html]",
	}
	if diff := cmp.Diff(want, forwarded); diff != "" {
		t.Fatalf("unexpected forwarded lines (-want +got):\n%s", diff)
	}
}

func TestRunHTTPXWorkersRespectsBatchSize(t *testing.T) {
	originalBatch := httpxBatchSize
	originalWorkers := httpxWorkerCount
	t.Cleanup(func() {
		httpxBatchSize = originalBatch
		httpxWorkerCount = originalWorkers
	})

	httpxBatchSize = 2
	httpxWorkerCount = 1

	combined := []string{"a", "b", "c", "d", "e"}
	var mu sync.Mutex
	var batches [][]string

	inputWriter := func(lines []string) (string, func(), error) {
		mu.Lock()
		defer mu.Unlock()
		cp := append([]string{}, lines...)
		batches = append(batches, cp)
		return fmt.Sprintf("/tmp/fake-%d", len(batches)), func() {}, nil
	}

	runCmd := func(ctx context.Context, name string, args []string, out chan<- string) error {
		return nil
	}

	err := runHTTPXWorkers(context.Background(), "httpx", combined, make(chan string), runCmd, inputWriter)
	if err != nil {
		t.Fatalf("run workers: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	want := [][]string{{"a", "b"}, {"c", "d"}, {"e"}}
	if diff := cmp.Diff(want, batches); diff != "" {
		t.Fatalf("unexpected batches (-want +got):\n%s", diff)
	}
}

func TestRunHTTPXWorkersCancellation(t *testing.T) {
	originalBatch := httpxBatchSize
	originalWorkers := httpxWorkerCount
	t.Cleanup(func() {
		httpxBatchSize = originalBatch
		httpxWorkerCount = originalWorkers
	})

	httpxBatchSize = 1
	httpxWorkerCount = 1

	combined := []string{"a", "b", "c"}

	var mu sync.Mutex
	var batches [][]string
	inputWriter := func(lines []string) (string, func(), error) {
		mu.Lock()
		defer mu.Unlock()
		cp := append([]string{}, lines...)
		batches = append(batches, cp)
		return fmt.Sprintf("/tmp/fake-%d", len(batches)), func() {}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runCmd := func(cmdCtx context.Context, name string, args []string, out chan<- string) error {
		cancel()
		<-cmdCtx.Done()
		return cmdCtx.Err()
	}

	err := runHTTPXWorkers(ctx, "httpx", combined, make(chan string), runCmd, inputWriter)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(batches) != 1 {
		t.Fatalf("expected only one batch to be processed, got %d", len(batches))
	}
}

func TestHTTPXProcessesRouteArtifactsOnly(t *testing.T) {
	tmp := t.TempDir()
	writeArtifactsFile(t, tmp, []artifacts.Artifact{{Type: "route", Value: "https://app.example.com/login", Up: true}})

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	originalWorkerCount := httpxWorkerCount
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
		httpxWorkerCount = originalWorkerCount
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }
	httpxWorkerCount = 1

	var mu sync.Mutex
	var captured [][]string
	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		mu.Lock()
		defer mu.Unlock()
		inputIdx := -1
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "-l" {
				inputIdx = i + 1
				break
			}
		}
		if inputIdx == -1 {
			t.Fatalf("httpx args missing -l input flag: %v", args)
		}

		data, err := os.ReadFile(args[inputIdx])
		if err != nil {
			t.Fatalf("read httpx input: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		captured = append(captured, lines)
		return nil
	}

	outCh := make(chan string, 5)
	if err := HTTPX(context.Background(), tmp, outCh); err != nil {
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

	if len(meta) != 0 {
		t.Fatalf("expected no meta lines, got %v", meta)
	}
}

func TestHTTPXNormalizesOutput(t *testing.T) {
	inputDir := t.TempDir()
	writeArtifactsFile(t, inputDir, []artifacts.Artifact{{Type: "route", Value: "https://app.example.com", Up: true}})

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	originalWorkerCount := httpxWorkerCount
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
		httpxWorkerCount = originalWorkerCount
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }
	httpxWorkerCount = 1

	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		out <- "https://app.example.com [200] [Title] [text/html; charset=utf-8]"
		return nil
	}

	outCh := make(chan string, 10)
	if err := HTTPX(context.Background(), inputDir, outCh); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	var forwarded []string
	for len(outCh) > 0 {
		forwarded = append(forwarded, <-outCh)
	}

	wantForwarded := []string{
		"active: https://app.example.com [200] [Title] [text/html; charset=utf-8]",
		"active: app.example.com [200] [Title] [text/html; charset=utf-8]",
		"active: html: https://app.example.com",
		"active: meta: [200]",
		"active: meta: [Title]",
		"active: meta: [text/html; charset=utf-8]",
	}
	if diff := cmp.Diff(wantForwarded, forwarded); diff != "" {
		t.Fatalf("unexpected forwarded lines (-want +got):\n%s", diff)
	}

	outputDir := t.TempDir()
	sink, err := pipeline.NewSink(outputDir, false, "example.com", "subdomains", pipeline.LineBufferSize(1))
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
	if err := materializer.Materialize(outputDir); err != nil {
		t.Fatalf("materialize output: %v", err)
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

	routes := readLines(filepath.Join(outputDir, "routes", "routes.active"))
	if diff := cmp.Diff([]string{"https://app.example.com [200] [Title] [text/html; charset=utf-8]"}, routes); diff != "" {
		t.Fatalf("unexpected routes.active contents (-want +got):\n%s", diff)
	}

	passiveRoutes := readLines(filepath.Join(outputDir, "routes", "routes.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com"}, passiveRoutes); diff != "" {
		t.Fatalf("unexpected routes.passive contents (-want +got):\n%s", diff)
	}

	domains := readLines(filepath.Join(outputDir, "domains", "domains.active"))
	if diff := cmp.Diff([]string{"app.example.com [200] [Title] [text/html; charset=utf-8]"}, domains); diff != "" {
		t.Fatalf("unexpected domains.active contents (-want +got):\n%s", diff)
	}

	meta := readLines(filepath.Join(outputDir, "meta.active"))
	sort.Strings(meta) // Meta lines may be reordered during materialization
	wantMeta := []string{"[200]", "[Title]", "[text/html; charset=utf-8]"}
	sort.Strings(wantMeta)
	if diff := cmp.Diff(wantMeta, meta); diff != "" {
		t.Fatalf("unexpected meta.active contents (-want +got):\n%s", diff)
	}

	htmlRoutes := readLines(filepath.Join(outputDir, "routes", "html", "html.active"))
	if diff := cmp.Diff([]string{"https://app.example.com [200] [Title] [text/html; charset=utf-8]"}, htmlRoutes); diff != "" {
		t.Fatalf("unexpected html.active contents (-want +got):\n%s", diff)
	}
}

func TestHTTPXSkipsUnresponsiveResults(t *testing.T) {
	inputDir := t.TempDir()
	writeArtifactsFile(t, inputDir, []artifacts.Artifact{{Type: "route", Value: "https://app.example.com", Up: true}})

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
	if err := HTTPX(context.Background(), inputDir, outCh); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	var forwarded []string
	for len(outCh) > 0 {
		forwarded = append(forwarded, <-outCh)
	}

	want := []string{
		"active: down.example.com [0] [connection refused]",
		"active: meta: [0]",
		"active: meta: [connection refused]",
		"active: https://up.example.com [200] [OK]",
		"active: up.example.com [200] [OK]",
		"active: meta: [200]",
		"active: meta: [OK]",
	}
	if diff := cmp.Diff(want, forwarded); diff != "" {
		t.Fatalf("unexpected forwarded lines (-want +got):\n%s", diff)
	}
}

func TestHTTPXSkipsHTMLForErrorResponses(t *testing.T) {
	inputDir := t.TempDir()
	writeArtifactsFile(t, inputDir, []artifacts.Artifact{{Type: "route", Value: "https://missing.example.com", Up: true}})

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }
	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		out <- "https://missing.example.com [404] [Not Found] [text/html]"
		return nil
	}

	outCh := make(chan string, 10)
	if err := HTTPX(context.Background(), inputDir, outCh); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	var forwarded []string
	for len(outCh) > 0 {
		forwarded = append(forwarded, <-outCh)
	}

	want := []string{
		"active: missing.example.com [404] [Not Found] [text/html]",
		"active: meta: [404]",
		"active: meta: [Not Found]",
		"active: meta: [text/html]",
	}

	if diff := cmp.Diff(want, forwarded); diff != "" {
		t.Fatalf("unexpected forwarded lines (-want +got):\n%s", diff)
	}
}

func TestHTTPXIncludesRedirectDomains(t *testing.T) {
	inputDir := t.TempDir()
	writeArtifactsFile(t, inputDir, []artifacts.Artifact{{Type: "route", Value: "https://redirect.example.com", Up: true}})

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }

	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		out <- "https://redirect.example.com [301] [Moved Permanently]"
		return nil
	}

	outCh := make(chan string, 10)
	if err := HTTPX(context.Background(), inputDir, outCh); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	var forwarded []string
	for len(outCh) > 0 {
		forwarded = append(forwarded, <-outCh)
	}

	if diff := cmp.Diff([]string{
		"active: https://redirect.example.com [301] [Moved Permanently]",
		"active: redirect.example.com [301] [Moved Permanently]",
		"active: meta: [301]",
		"active: meta: [Moved Permanently]",
	}, forwarded); diff != "" {
		t.Fatalf("unexpected forwarded lines (-want +got):\n%s", diff)
	}
}

func TestHTTPXBatchesLargeInputs(t *testing.T) {
	inputDir := t.TempDir()
	var records []artifacts.Artifact
	for i := 0; i < 5; i++ {
		records = append(records, artifacts.Artifact{Type: "route", Value: fmt.Sprintf("https://example.com/path-%d", i), Up: true})
	}
	writeArtifactsFile(t, inputDir, records)

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	originalBatchSize := httpxBatchSize
	originalWorkerCount := httpxWorkerCount
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
		httpxBatchSize = originalBatchSize
		httpxWorkerCount = originalWorkerCount
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }
	httpxBatchSize = 2
	httpxWorkerCount = 2

	var mu sync.Mutex
	var captured [][]string
	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		inputIdx := -1
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "-l" {
				inputIdx = i + 1
				break
			}
		}
		if inputIdx == -1 {
			t.Fatalf("httpx args missing -l input flag: %v", args)
		}

		data, err := os.ReadFile(args[inputIdx])
		if err != nil {
			t.Fatalf("read httpx input: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		mu.Lock()
		captured = append(captured, lines)
		mu.Unlock()
		return nil
	}

	if err := HTTPX(context.Background(), inputDir, make(chan string, 10)); err != nil {
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

func TestProcessHTTPXJSON(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name: "completo con webserver y tecnologías",
			input: `{"timestamp":"2025-10-15T19:13:27.27475621+02:00","port":"443","url":"https://booking.avanzabus.com/comun/css/fonts/opensans-bold-webfont.woff","input":"http://booking.avanzabus.com/comun/css/fonts/opensans-bold-webfont.woff","scheme":"https","webserver":"nginx/1.18.0 (Ubuntu)","content_type":"application/font-woff","method":"HEAD","host":"52.51.81.104","path":"/comun/css/fonts/opensans-bold-webfont.woff","time":"161.824534ms","a":["52.209.141.168","52.51.81.104"],"tech":["Nginx:1.18.0","Ubuntu"],"words":0,"lines":0,"status_code":200,"content_length":25708,"failed":false,"knowledgebase":{"PageType":"other","pHash":0},"resolvers":["8.8.4.4:53"]}`,
			want: []string{
				"active: https://booking.avanzabus.com/comun/css/fonts/opensans-bold-webfont.woff",
				"active: booking.avanzabus.com",
				`active: keyFinding: {"type":"webserver","url":"https://booking.avanzabus.com/comun/css/fonts/opensans-bold-webfont.woff","value":"nginx/1.18.0 (Ubuntu)"}`,
				`active: keyFinding: {"type":"technology","url":"https://booking.avanzabus.com/comun/css/fonts/opensans-bold-webfont.woff","value":"Nginx:1.18.0"}`,
				`active: keyFinding: {"type":"technology","url":"https://booking.avanzabus.com/comun/css/fonts/opensans-bold-webfont.woff","value":"Ubuntu"}`,
				`active: keyFinding: {"type":"content-type","url":"https://booking.avanzabus.com/comun/css/fonts/opensans-bold-webfont.woff","value":"application/font-woff"}`,
			},
		},
		{
			name: "HTML con título",
			input: `{"timestamp":"2025-10-15T19:13:27.27475621+02:00","port":"443","url":"https://example.com/index.html","input":"http://example.com/index.html","scheme":"https","webserver":"Apache/2.4.41","content_type":"text/html; charset=utf-8","method":"GET","host":"93.184.216.34","path":"/index.html","status_code":200,"title":"Example Domain","failed":false}`,
			want: []string{
				"active: https://example.com/index.html",
				"active: example.com",
				"active: html: https://example.com/index.html",
				`active: keyFinding: {"type":"webserver","url":"https://example.com/index.html","value":"Apache/2.4.41"}`,
				`active: keyFinding: {"type":"title","url":"https://example.com/index.html","value":"Example Domain"}`,
			},
		},
		{
			name: "request fallida",
			input: `{"url":"https://down.example.com","status_code":0,"failed":true}`,
			want: nil,
		},
		{
			name: "404 no genera HTML",
			input: `{"url":"https://example.com/missing","status_code":404,"content_type":"text/html","failed":false}`,
			want: []string{
				"active: example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := processHTTPXJSON(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("processHTTPXJSON() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtractKeyFindings(t *testing.T) {
	tests := []struct {
		name  string
		input httpxJSONResponse
		want  []string
	}{
		{
			name: "webserver y tecnologías",
			input: httpxJSONResponse{
				URL:       "https://example.com",
				Webserver: "nginx/1.18.0 (Ubuntu)",
				Tech:      []string{"Nginx:1.18.0", "Ubuntu"},
			},
			want: []string{
				`{"type":"webserver","url":"https://example.com","value":"nginx/1.18.0 (Ubuntu)"}`,
				`{"type":"technology","url":"https://example.com","value":"Nginx:1.18.0"}`,
				`{"type":"technology","url":"https://example.com","value":"Ubuntu"}`,
			},
		},
		{
			name: "título con comillas",
			input: httpxJSONResponse{
				URL:   "https://example.com",
				Title: `Welcome to "Example" Site`,
			},
			want: []string{
				`{"type":"title","url":"https://example.com","value":"Welcome to \"Example\" Site"}`,
			},
		},
		{
			name: "content-type relevante",
			input: httpxJSONResponse{
				URL:         "https://example.com/api/data",
				ContentType: "application/json; charset=utf-8",
			},
			want: []string{
				`{"type":"content-type","url":"https://example.com/api/data","value":"application/json; charset=utf-8"}`,
			},
		},
		{
			name: "sin información relevante",
			input: httpxJSONResponse{
				URL: "https://example.com",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractKeyFindings(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("extractKeyFindings() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHTTPXSkipsLowPriorityRoutes(t *testing.T) {
	tmp := t.TempDir()
	var artifactsList []artifacts.Artifact
	for _, value := range []string{
		"https://app.example.com/login",
		"https://app.example.com/favicon.ico",
		"https://app.example.com/favicon.ico?version=2",
		"https://app.example.com/images/logo_thumb.jpg",
		"https://app.example.com/static/sprite.png",
		"https://app.example.com/static/sprite.svg#section",
		"https://app.example.com/img/banner.GIF",
		"https://app.example.com/files/THUMBS.DB",
		"https://app.example.com/assets/raw.pgm",
	} {
		artifactsList = append(artifactsList, artifacts.Artifact{Type: "route", Value: value, Up: true})
	}
	writeArtifactsFile(t, tmp, artifactsList)

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	originalWorkerCount := httpxWorkerCount
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
		httpxWorkerCount = originalWorkerCount
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }
	httpxWorkerCount = 1

	var mu sync.Mutex
	var inputs [][]string
	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		mu.Lock()
		defer mu.Unlock()
		inputIdx := -1
		for i := 0; i < len(args)-1; i++ {
			if args[i] == "-l" {
				inputIdx = i + 1
				break
			}
		}
		if inputIdx == -1 {
			t.Fatalf("httpx args missing -l input flag: %v", args)
		}

		data, err := os.ReadFile(args[inputIdx])
		if err != nil {
			t.Fatalf("read httpx input: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		inputs = append(inputs, lines)
		return nil
	}

	if err := HTTPX(context.Background(), tmp, make(chan string, 10)); err != nil {
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
