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
	"time"

	"github.com/google/go-cmp/cmp"

	"passive-rec/internal/routes"
)

func sortedCopy(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cp := append([]string(nil), values...)
	sort.Strings(cp)
	return cp
}

func TestClassifyLinkfinderEndpoint(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantJS     bool
		wantHTML   bool
		undetected bool
		wantImage  bool
		wantCats   []routes.Category
	}{
		{name: "javascript absolute", input: "https://example.com/app/main.js", wantJS: true},
		{name: "html absolute", input: "https://example.com/index.html", wantHTML: true},
		{name: "image absolute", input: "https://example.com/static/logo.png", wantImage: true},
		{name: "relative path", input: "api/v1/users", undetected: true},
		{name: "svg relative", input: "logo.svg", undetected: true, wantImage: true, wantCats: []routes.Category{routes.CategorySVG}},
		{name: "wasm", input: "https://example.com/app.wasm", wantCats: []routes.Category{routes.CategoryWASM}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyLinkfinderEndpoint(tt.input)
			if got.isJS != tt.wantJS {
				t.Fatalf("isJS mismatch: got %v want %v", got.isJS, tt.wantJS)
			}
			if got.isHTML != tt.wantHTML {
				t.Fatalf("isHTML mismatch: got %v want %v", got.isHTML, tt.wantHTML)
			}
			if got.undetected != tt.undetected {
				t.Fatalf("undetected mismatch: got %v want %v", got.undetected, tt.undetected)
			}
			if got.isImage != tt.wantImage {
				t.Fatalf("isImage mismatch: got %v want %v", got.isImage, tt.wantImage)
			}
			if diff := cmp.Diff(tt.wantCats, got.categories); diff != "" {
				t.Fatalf("categories mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEmitLinkfinderFindingsFeedsCategories(t *testing.T) {
	reports := []linkfinderReport{{
		Resource: "https://example.com/page.html",
		Endpoints: []linkfinderEndpoint{
			{Link: "logo.svg"},
			{Link: "https://example.com/sitemap.xml"},
			{Link: "https://example.com/config.json"},
			{Link: "https://example.com/openapi.json"},
			{Link: "https://example.com/app.wasm"},
			{Link: "https://example.com/static/app.js"},
		},
	}}

	out := make(chan string, 20)
	result, err := emitLinkfinderFindings(reports, out)
	if err != nil {
		t.Fatalf("emitLinkfinderFindings returned error: %v", err)
	}
	close(out)

	var lines []string
	for line := range out {
		lines = append(lines, line)
	}
	sort.Strings(lines)

	wantLines := []string{
		"active: https://example.com/app.wasm",
		"active: https://example.com/config.json",
		"active: https://example.com/openapi.json",
		"active: https://example.com/sitemap.xml",
		"active: https://example.com/static/app.js",
		"active: api: https://example.com/openapi.json",
		"active: crawl: https://example.com/sitemap.xml",
		"active: html: logo.svg",
		"active: js: https://example.com/static/app.js",
		"active: json: https://example.com/config.json",
		"active: meta-route: https://example.com/config.json",
		"active: logo.svg",
		"active: svg: logo.svg",
		"active: wasm: https://example.com/app.wasm",
	}

	sort.Strings(wantLines)
	if diff := cmp.Diff(wantLines, lines); diff != "" {
		t.Fatalf("unexpected lines (-want +got):\n%s", diff)
	}

	sort.Strings(result.Undetected)
	if diff := cmp.Diff([]string{"logo.svg"}, result.Undetected); diff != "" {
		t.Fatalf("unexpected undetected entries (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff([]string{
		"https://example.com/app.wasm",
		"https://example.com/config.json",
		"https://example.com/openapi.json",
		"https://example.com/sitemap.xml",
		"https://example.com/static/app.js",
		"logo.svg",
	}, sortedCopy(result.Routes)); diff != "" {
		t.Fatalf("unexpected routes list (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff([]string{"https://example.com/static/app.js"}, sortedCopy(result.JS)); diff != "" {
		t.Fatalf("unexpected JS routes (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff([]string{"logo.svg"}, sortedCopy(result.Images)); diff != "" {
		t.Fatalf("unexpected image routes (-want +got):\n%s", diff)
	}

	svgRoutes := sortedCopy(result.Categories[routes.CategorySVG])
	if diff := cmp.Diff([]string{"logo.svg"}, svgRoutes); diff != "" {
		t.Fatalf("unexpected svg routes (-want +got):\n%s", diff)
	}
}

func TestNormalizeScope(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "example.com", want: "example.com"},
		{input: "https://sub.example.com", want: "sub.example.com"},
		{input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := normalizeScope(tt.input); got != tt.want {
				t.Fatalf("normalizeScope(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestWriteLinkfinderOutputsCreatesAllFormats(t *testing.T) {
	agg := newLinkfinderAggregate()
	agg.add("https://example.com/index.html", linkfinderEndpoint{Link: "https://example.com/api", Context: "fetch('/api')", Line: 10})

	tmp := t.TempDir()

	out := make(chan string, 10)
	if err := writeLinkfinderOutputs(tmp, agg, out); err != nil {
		t.Fatalf("writeLinkfinderOutputs returned error: %v", err)
	}

	findingsDir := filepath.Join(tmp, "routes", "linkFindings")
	files := []string{"findings.json", "findings.raw", "findings.html"}
	for _, name := range files {
		path := filepath.Join(findingsDir, name)
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to be created: %v", name, err)
		}
	}
}

func TestBuildLinkfinderArgsIncludesGF(t *testing.T) {
	args := buildLinkfinderArgs("input", "example.com", "raw", "html", "json")
	found := false
	for i := 0; i < len(args); i++ {
		if args[i] == "--gf" && i+1 < len(args) && args[i+1] == "all" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected buildLinkfinderArgs to include --gf all, got %v", args)
	}
}

func TestPersistLinkfinderGFArtifacts(t *testing.T) {
	srcDir := t.TempDir()
	destDir := t.TempDir()

	gfTxt := filepath.Join(srcDir, "gf.txt")
	gfJSON := filepath.Join(srcDir, "gf.json")
	if err := os.WriteFile(gfTxt, []byte("match"), 0o644); err != nil {
		t.Fatalf("failed to write gf.txt: %v", err)
	}
	if err := os.WriteFile(gfJSON, []byte("{}"), 0o644); err != nil {
		t.Fatalf("failed to write gf.json: %v", err)
	}

	if err := persistLinkfinderGFArtifacts(destDir, "html", srcDir); err != nil {
		t.Fatalf("persistLinkfinderGFArtifacts returned error: %v", err)
	}

	wantFiles := []string{
		filepath.Join(destDir, "gf.html.txt"),
		filepath.Join(destDir, "gf.html.json"),
	}
	for _, name := range wantFiles {
		if _, err := os.Stat(name); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}

	if err := os.Remove(gfTxt); err != nil {
		t.Fatalf("failed to remove gf.txt: %v", err)
	}

	if err := persistLinkfinderGFArtifacts(destDir, "html", srcDir); err != nil {
		t.Fatalf("persistLinkfinderGFArtifacts returned error on cleanup: %v", err)
	}

	if _, err := os.Stat(filepath.Join(destDir, "gf.html.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected gf.html.txt to be removed, got err=%v", err)
	}
}

func TestPersistLinkfinderActiveOutputsMergesEntries(t *testing.T) {
	tmp := t.TempDir()

	existingRoutes := filepath.Join(tmp, "routes", "routes.active")
	if err := os.MkdirAll(filepath.Dir(existingRoutes), 0o755); err != nil {
		t.Fatalf("failed to create routes dir: %v", err)
	}
	if err := os.WriteFile(existingRoutes, []byte("https://existing.example\n"), 0o644); err != nil {
		t.Fatalf("failed to seed routes.active: %v", err)
	}

	emission := linkfinderEmissionResult{
		Routes: []string{"https://existing.example", "https://example.com/new"},
		JS:     []string{"https://example.com/app.js"},
		HTML:   []string{"https://example.com/index.html"},
		Images: []string{"https://example.com/logo.png"},
		Categories: map[routes.Category][]string{
			routes.CategoryJSON:  []string{"https://example.com/config.json"},
			routes.CategorySVG:   []string{"https://example.com/icon.svg"},
			routes.CategoryCrawl: []string{"https://example.com/sitemap.xml"},
		},
	}

	if err := persistLinkfinderActiveOutputs(tmp, emission); err != nil {
		t.Fatalf("persistLinkfinderActiveOutputs returned error: %v", err)
	}

	gotRoutes := readLinesFromFile(t, existingRoutes)
	if diff := cmp.Diff([]string{
		"https://example.com/new",
		"https://existing.example",
	}, gotRoutes); diff != "" {
		t.Fatalf("unexpected routes.active contents (-want +got):\n%s", diff)
	}

	jsPath := filepath.Join(tmp, "routes", "js", "js.active")
	gotJS := readLinesFromFile(t, jsPath)
	if diff := cmp.Diff([]string{"https://example.com/app.js"}, gotJS); diff != "" {
		t.Fatalf("unexpected js.active contents (-want +got):\n%s", diff)
	}

	imagesPath := filepath.Join(tmp, "routes", "images", "images.active")
	gotImages := readLinesFromFile(t, imagesPath)
	if diff := cmp.Diff([]string{"https://example.com/logo.png"}, gotImages); diff != "" {
		t.Fatalf("unexpected images.active contents (-want +got):\n%s", diff)
	}

	jsonPath := filepath.Join(tmp, "routes", "json", "json.active")
	gotJSON := readLinesFromFile(t, jsonPath)
	if diff := cmp.Diff([]string{"https://example.com/config.json"}, gotJSON); diff != "" {
		t.Fatalf("unexpected json.active contents (-want +got):\n%s", diff)
	}

	svgPath := filepath.Join(tmp, "routes", "svg", "svg.active")
	gotSVG := readLinesFromFile(t, svgPath)
	if diff := cmp.Diff([]string{"https://example.com/icon.svg"}, gotSVG); diff != "" {
		t.Fatalf("unexpected svg.active contents (-want +got):\n%s", diff)
	}

	crawlPath := filepath.Join(tmp, "routes", "crawl", "crawl.active")
	gotCrawl := readLinesFromFile(t, crawlPath)
	if diff := cmp.Diff([]string{"https://example.com/sitemap.xml"}, gotCrawl); diff != "" {
		t.Fatalf("unexpected crawl.active contents (-want +got):\n%s", diff)
	}
}

func readLinesFromFile(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		t.Fatalf("failed to read %s: %v", path, err)
	}
	lines := strings.Split(string(data), "\n")
	var result []string
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	sort.Strings(result)
	return result
}

func TestCleanLinkfinderEndpointLink(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "already clean", input: "https://example.com/app.js", want: "https://example.com/app.js"},
		{name: "trailing script noise", input: "https://uvesa.es/})}else{visibilityCache=[]", want: "https://uvesa.es/"},
		{name: "wrapped in quotes", input: "\"/static/app.js\"", want: "/static/app.js"},
		{name: "with trailing punctuation", input: "https://example.com/api/v1/users,", want: "https://example.com/api/v1/users"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanLinkfinderEndpointLink(tt.input); got != tt.want {
				t.Fatalf("cleanLinkfinderEndpointLink(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMaybeSampleLinkfinderInputLimitsEntries(t *testing.T) {
	tmp := t.TempDir()

	var builder strings.Builder
	total := linkfinderMaxInputEntries + 50
	for i := 0; i < total; i++ {
		builder.WriteString(fmt.Sprintf("file://example.com/%d\n", i))
	}

	path, totalEntries, sampledEntries, err := maybeSampleLinkfinderInput(tmp, "html", []byte(builder.String()), linkfinderMaxInputEntries)
	if err != nil {
		t.Fatalf("maybeSampleLinkfinderInput returned error: %v", err)
	}
	if path == "" {
		t.Fatalf("expected sampling to occur when total=%d", total)
	}
	if totalEntries != total {
		t.Fatalf("unexpected total entries: got %d want %d", totalEntries, total)
	}
	if sampledEntries != linkfinderMaxInputEntries {
		t.Fatalf("unexpected sampled entries: got %d want %d", sampledEntries, linkfinderMaxInputEntries)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read sample file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != linkfinderMaxInputEntries {
		t.Fatalf("sample file has unexpected number of entries: got %d want %d", len(lines), linkfinderMaxInputEntries)
	}
	for _, line := range lines {
		if strings.TrimSpace(line) != line {
			t.Fatalf("expected sample lines to be trimmed, got %q", line)
		}
	}
}

func TestMaybeSampleLinkfinderInputRespectsCustomLimit(t *testing.T) {
	tmp := t.TempDir()

	var builder strings.Builder
	for i := 0; i < 100; i++ {
		builder.WriteString(fmt.Sprintf("file://example.com/%d\n", i))
	}

	limit := 25
	path, totalEntries, sampledEntries, err := maybeSampleLinkfinderInput(tmp, "html", []byte(builder.String()), limit)
	if err != nil {
		t.Fatalf("maybeSampleLinkfinderInput returned error: %v", err)
	}
	if totalEntries != 100 {
		t.Fatalf("unexpected total entries: got %d want 100", totalEntries)
	}
	if sampledEntries != limit {
		t.Fatalf("unexpected sampled entries: got %d want %d", sampledEntries, limit)
	}
	if path == "" {
		t.Fatalf("expected sampling path when limit=%d", limit)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read sample file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != limit {
		t.Fatalf("sample file has unexpected number of entries: got %d want %d", len(lines), limit)
	}
}

func TestMaybeSampleLinkfinderInputNoopWhenBelowLimit(t *testing.T) {
	tmp := t.TempDir()

	data := []byte("file://example.com/1\nfile://example.com/2\n")
	path, totalEntries, sampledEntries, err := maybeSampleLinkfinderInput(tmp, "html", data, linkfinderMaxInputEntries)
	if err != nil {
		t.Fatalf("maybeSampleLinkfinderInput returned error: %v", err)
	}
	if path != "" {
		t.Fatalf("expected no sampling, but got path %q", path)
	}
	if totalEntries != 2 {
		t.Fatalf("unexpected total entries: got %d want 2", totalEntries)
	}
	if sampledEntries != 2 {
		t.Fatalf("unexpected sampled entries: got %d want 2", sampledEntries)
	}
}

func TestLinkfinderEntryBudget(t *testing.T) {
	ctxNoDeadline := context.Background()
	maxTotal := 3 * linkfinderMaxInputEntries
	if got := linkfinderEntryBudget(ctxNoDeadline, maxTotal); got != maxTotal {
		t.Fatalf("expected full budget without deadline, got %d want %d", got, maxTotal)
	}

	deadline := time.Now().Add(3 * time.Second)
	ctxWithDeadline, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	budget := linkfinderEntryBudget(ctxWithDeadline, maxTotal)
	if budget <= 0 || budget > maxTotal {
		t.Fatalf("unexpected budget with deadline: got %d", budget)
	}

	farFuture := time.Now().Add(10 * time.Minute)
	ctxFuture, cancelFuture := context.WithDeadline(context.Background(), farFuture)
	defer cancelFuture()
	if got := linkfinderEntryBudget(ctxFuture, maxTotal); got != maxTotal {
		t.Fatalf("expected budget to clamp to max for far deadline, got %d want %d", got, maxTotal)
	}
}

func TestLinkFinderEVOIntegrationGeneratesReports(t *testing.T) {
	if _, err := os.Stat("/tmp/golinkfinder"); err != nil {
		t.Skip("GoLinkfinderEVO binary not available for integration test")
	}

	prevFindBin := linkfinderFindBin
	prevRunCmd := linkfinderRunCmd
	t.Cleanup(func() {
		linkfinderFindBin = prevFindBin
		linkfinderRunCmd = prevRunCmd
	})

	linkfinderFindBin = func(names ...string) (string, bool) {
		return "/tmp/golinkfinder", true
	}

	tmp := t.TempDir()
	routesDir := filepath.Join(tmp, "routes")
	if err := os.MkdirAll(filepath.Join(routesDir, "html"), 0o755); err != nil {
		t.Fatalf("failed to create html dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(routesDir, "js"), 0o755); err != nil {
		t.Fatalf("failed to create js dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(routesDir, "crawl"), 0o755); err != nil {
		t.Fatalf("failed to create crawl dir: %v", err)
	}

	sample := filepath.Join(tmp, "sample.html")
	if err := os.WriteFile(sample, []byte(`<html><body><script src="/static/app.js"></script><a href="/foo/bar.html">Link</a></body></html>`), 0o644); err != nil {
		t.Fatalf("failed to write sample html: %v", err)
	}

	htmlList := filepath.Join(routesDir, "html", "html.active")
	if err := os.WriteFile(htmlList, []byte("file://"+sample+"\n"), 0o644); err != nil {
		t.Fatalf("failed to write html list: %v", err)
	}
	if err := os.WriteFile(filepath.Join(routesDir, "js", "js.active"), nil, 0o644); err != nil {
		t.Fatalf("failed to write js list: %v", err)
	}
	if err := os.WriteFile(filepath.Join(routesDir, "crawl", "crawl.active"), nil, 0o644); err != nil {
		t.Fatalf("failed to write crawl list: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan string, 10)
	if err := LinkFinderEVO(ctx, "https://example.com", tmp, out); err != nil {
		t.Fatalf("LinkFinderEVO returned error: %v", err)
	}

	findingsDir := filepath.Join(routesDir, "linkFindings")
	for _, name := range []string{"findings.json", "findings.raw", "findings.html"} {
		if _, err := os.Stat(filepath.Join(findingsDir, name)); err != nil {
			t.Fatalf("expected %s to exist: %v", name, err)
		}
	}

	for _, name := range []string{"findings.html.json", "findings.html.raw", "findings.html.html"} {
		if _, err := os.Stat(filepath.Join(findingsDir, name)); err != nil {
			t.Fatalf("expected intermediate artifact %s: %v", name, err)
		}
	}

	for _, name := range []string{"gf.html.txt", "gf.html.json"} {
		if _, err := os.Stat(filepath.Join(findingsDir, name)); err != nil {
			t.Fatalf("expected gf artifact %s: %v", name, err)
		}
	}

	if _, err := os.Stat(filepath.Join(tmp, "linkfindings")); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected legacy linkfindings directory state: err=%v", err)
	}
}

func TestLinkFinderEVOLimitsWorkloadByDeadline(t *testing.T) {
	prevFindBin := linkfinderFindBin
	prevRunCmd := linkfinderRunCmd
	t.Cleanup(func() {
		linkfinderFindBin = prevFindBin
		linkfinderRunCmd = prevRunCmd
	})

	linkfinderFindBin = func(names ...string) (string, bool) {
		return "golinkfinder", true
	}

	var mu sync.Mutex
	var processed []int
	linkfinderRunCmd = func(ctx context.Context, dir string, name string, args []string, out chan<- string) error {
		for i := 0; i < len(args); i++ {
			if args[i] == "-i" && i+1 < len(args) {
				data, err := os.ReadFile(args[i+1])
				if err != nil {
					return err
				}
				lines := strings.Split(strings.TrimSpace(string(data)), "\n")
				count := 0
				for _, line := range lines {
					if strings.TrimSpace(line) != "" {
						count++
					}
				}
				mu.Lock()
				processed = append(processed, count)
				mu.Unlock()
				break
			}
		}
		return nil
	}

	tmp := t.TempDir()
	routesDir := filepath.Join(tmp, "routes")
	for _, sub := range []string{"html", "js", "crawl"} {
		if err := os.MkdirAll(filepath.Join(routesDir, sub), 0o755); err != nil {
			t.Fatalf("failed to create %s dir: %v", sub, err)
		}
		var builder strings.Builder
		for i := 0; i < 100; i++ {
			builder.WriteString(fmt.Sprintf("file://example.com/%s/%d\n", sub, i))
		}
		if err := os.WriteFile(filepath.Join(routesDir, sub, fmt.Sprintf("%s.active", sub)), []byte(builder.String()), 0o644); err != nil {
			t.Fatalf("failed to write %s list: %v", sub, err)
		}
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(2*time.Second))
	defer cancel()
	expectedBudget := linkfinderEntryBudget(ctx, 3*linkfinderMaxInputEntries)
	if expectedBudget >= 100 {
		t.Fatalf("expected budget to be lower than input size, got %d", expectedBudget)
	}

	out := make(chan string, 20)
	if err := LinkFinderEVO(ctx, "https://example.com", tmp, out); err != nil {
		t.Fatalf("LinkFinderEVO returned error: %v", err)
	}

	mu.Lock()
	calls := append([]int(nil), processed...)
	mu.Unlock()

	if len(calls) == 0 {
		t.Fatalf("expected at least one command invocation")
	}
	if len(calls) > 1 {
		t.Fatalf("expected single invocation due to budget exhaustion, got %d", len(calls))
	}
	if calls[0] <= 0 {
		t.Fatalf("expected positive number of processed entries, got %d", calls[0])
	}
	if calls[0] > expectedBudget {
		t.Fatalf("processed entries exceed budget: got %d want <= %d", calls[0], expectedBudget)
	}
}
