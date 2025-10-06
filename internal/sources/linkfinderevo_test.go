package sources

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"passive-rec/internal/routes"
)

func TestClassifyLinkfinderEndpoint(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantJS     bool
		wantHTML   bool
		undetected bool
		wantCats   []routes.Category
	}{
		{name: "javascript absolute", input: "https://example.com/app/main.js", wantJS: true},
		{name: "html absolute", input: "https://example.com/index.html", wantHTML: true},
		{name: "relative path", input: "api/v1/users", undetected: true},
		{name: "svg relative", input: "logo.svg", undetected: true, wantCats: []routes.Category{routes.CategorySVG}},
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
	undetected, err := emitLinkfinderFindings(reports, out)
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

	sort.Strings(undetected)
	if diff := cmp.Diff([]string{"logo.svg"}, undetected); diff != "" {
		t.Fatalf("unexpected undetected entries (-want +got):\n%s", diff)
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
}
