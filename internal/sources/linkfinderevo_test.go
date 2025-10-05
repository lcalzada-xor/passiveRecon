package sources

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClassifyLinkfinderEndpoint(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantJS     bool
		wantHTML   bool
		undetected bool
	}{
		{name: "javascript absolute", input: "https://example.com/app/main.js", wantJS: true},
		{name: "html absolute", input: "https://example.com/index.html", wantHTML: true},
		{name: "relative path", input: "api/v1/users", undetected: true},
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
		})
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
