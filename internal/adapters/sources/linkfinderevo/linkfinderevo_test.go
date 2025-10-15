package linkfinderevo

import (
	"context"
	"encoding/json"
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

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/adapters/routes"
)

func writeArtifacts(t *testing.T, outdir string, data map[string][]string) {
	t.Helper()
	path := filepath.Join(outdir, "artifacts.jsonl")
	var artifactsList []artifacts.Artifact
	for typ, values := range data {
		for _, value := range values {
			artifactsList = append(artifactsList, artifacts.Artifact{Type: typ, Value: value, Active: true, Up: true})
		}
	}
	writer := artifacts.NewWriterV2(path, "test.com")
	if err := writer.WriteArtifacts(artifactsList); err != nil {
		t.Fatalf("write artifacts: %v", err)
	}
}

func sortedCopy(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	cp := append([]string(nil), values...)
	sort.Strings(cp)
	return cp
}

func TestClassifyEndpoint(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantJS     bool
		wantHTML   bool
		wantCSS    bool
		wantPDF    bool
		wantDoc    bool
		wantFont   bool
		wantVideo  bool
		wantArchive bool
		wantXML    bool
		undetected bool
		wantImage  bool
		wantCats   []routes.Category
	}{
		// JavaScript
		{name: "javascript absolute", input: "https://example.com/app/main.js", wantJS: true, wantCats: []routes.Category{routes.CategoryJS}},
		{name: "typescript", input: "https://example.com/app.ts", wantJS: true, wantCats: []routes.Category{}}, // TS no tiene categoria especial
		{name: "module js", input: "https://example.com/app.mjs", wantJS: true, wantCats: []routes.Category{routes.CategoryJS}},

		// HTML
		{name: "html absolute", input: "https://example.com/index.html", wantHTML: true, wantCats: []routes.Category{routes.CategoryHTML}},
		{name: "php", input: "https://example.com/index.php", wantHTML: true, wantCats: []routes.Category{}}, // PHP no tiene categoría especial
		{name: "jsp", input: "https://example.com/page.jsp", wantHTML: true, wantCats: []routes.Category{}}, // JSP no tiene categoría especial

		// CSS
		{name: "css file", input: "https://example.com/style.css", wantCSS: true, wantCats: []routes.Category{routes.CategoryCSS}},
		{name: "scss file", input: "https://example.com/style.scss", wantCSS: true, wantCats: []routes.Category{}}, // SCSS no tiene categoría especial
		{name: "sass file", input: "https://example.com/style.sass", wantCSS: true, wantCats: []routes.Category{}}, // SASS no tiene categoría especial

		// PDF
		{name: "pdf document", input: "https://example.com/doc.pdf", wantPDF: true, wantCats: []routes.Category{routes.CategoryDocs}},
		{name: "pdf with query", input: "https://example.com/report.pdf?v=1", wantPDF: true, wantCats: []routes.Category{routes.CategoryDocs}},

		// Documentos
		{name: "word doc", input: "https://example.com/file.docx", wantDoc: true, wantCats: []routes.Category{routes.CategoryDocs}},
		{name: "excel", input: "https://example.com/data.xlsx", wantDoc: true, wantCats: []routes.Category{routes.CategoryDocs}},
		{name: "powerpoint", input: "https://example.com/presentation.pptx", wantDoc: true, wantCats: []routes.Category{routes.CategoryDocs}},
		{name: "text file", input: "https://example.com/readme.txt", wantDoc: true, wantCats: []routes.Category{routes.CategoryDocs}},

		// Fuentes
		{name: "woff font", input: "https://example.com/font.woff", wantFont: true, wantCats: []routes.Category{routes.CategoryFonts}},
		{name: "woff2 font", input: "https://example.com/font.woff2", wantFont: true, wantCats: []routes.Category{routes.CategoryFonts}},
		{name: "ttf font", input: "https://example.com/font.ttf", wantFont: true, wantCats: []routes.Category{routes.CategoryFonts}},

		// Video
		{name: "mp4 video", input: "https://example.com/video.mp4", wantVideo: true, wantCats: []routes.Category{routes.CategoryVideo}},
		{name: "webm video", input: "https://example.com/clip.webm", wantVideo: true, wantCats: []routes.Category{routes.CategoryVideo}},

		// Archivos comprimidos
		{name: "zip archive", input: "https://example.com/data.zip", wantArchive: true, wantCats: []routes.Category{routes.CategoryArchives}},
		{name: "tar.gz archive", input: "https://example.com/backup.tar.gz", wantArchive: true, wantCats: []routes.Category{routes.CategoryArchives, routes.CategoryMeta}}, // .gz también es meta
		{name: "rar archive", input: "https://example.com/files.rar", wantArchive: true, wantCats: []routes.Category{routes.CategoryArchives}},

		// XML
		{name: "xml file", input: "https://example.com/sitemap.xml", wantXML: true, wantCats: []routes.Category{routes.CategoryCrawl}},
		{name: "rss feed", input: "https://example.com/feed", wantXML: false, wantCats: []routes.Category{routes.CategoryFeeds}}, // /feed path es detectado como feed

		// Imágenes
		{name: "image absolute", input: "https://example.com/static/logo.png", wantImage: true, wantCats: []routes.Category{routes.CategoryImages}},
		{name: "jpg image", input: "https://example.com/photo.jpg", wantImage: true, wantCats: []routes.Category{routes.CategoryImages}},
		{name: "webp image", input: "https://example.com/modern.webp", wantImage: true, wantCats: []routes.Category{routes.CategoryImages}},
		{name: "svg relative", input: "logo.svg", undetected: true, wantImage: true, wantCats: []routes.Category{routes.CategorySVG}},
		{name: "svg absolute", input: "https://example.com/icon.svg", wantImage: true, wantCats: []routes.Category{routes.CategorySVG}},

		// Casos especiales
		{name: "relative path", input: "api/v1/users", undetected: true, wantCats: []routes.Category{routes.CategoryAPI}},
		{name: "wasm", input: "https://example.com/app.wasm", wantCats: []routes.Category{routes.CategoryWASM}},
		{name: "json config", input: "https://example.com/config.json", wantCats: []routes.Category{routes.CategoryJSON, routes.CategoryMeta}},
		{name: "openapi spec", input: "https://example.com/openapi.json", wantCats: []routes.Category{routes.CategoryAPI}}, // openapi es API, el JSON ya está implícito
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyEndpoint(tt.input)
			if got.isJS != tt.wantJS {
				t.Errorf("isJS mismatch: got %v want %v", got.isJS, tt.wantJS)
			}
			if got.isHTML != tt.wantHTML {
				t.Errorf("isHTML mismatch: got %v want %v", got.isHTML, tt.wantHTML)
			}
			if got.isCSS != tt.wantCSS {
				t.Errorf("isCSS mismatch: got %v want %v", got.isCSS, tt.wantCSS)
			}
			if got.isPDF != tt.wantPDF {
				t.Errorf("isPDF mismatch: got %v want %v", got.isPDF, tt.wantPDF)
			}
			if got.isDoc != tt.wantDoc {
				t.Errorf("isDoc mismatch: got %v want %v", got.isDoc, tt.wantDoc)
			}
			if got.isFont != tt.wantFont {
				t.Errorf("isFont mismatch: got %v want %v", got.isFont, tt.wantFont)
			}
			if got.isVideo != tt.wantVideo {
				t.Errorf("isVideo mismatch: got %v want %v", got.isVideo, tt.wantVideo)
			}
			if got.isArchive != tt.wantArchive {
				t.Errorf("isArchive mismatch: got %v want %v", got.isArchive, tt.wantArchive)
			}
			if got.isXML != tt.wantXML {
				t.Errorf("isXML mismatch: got %v want %v", got.isXML, tt.wantXML)
			}
			if got.undetected != tt.undetected {
				t.Errorf("undetected mismatch: got %v want %v", got.undetected, tt.undetected)
			}
			if got.isImage != tt.wantImage {
				t.Errorf("isImage mismatch: got %v want %v", got.isImage, tt.wantImage)
			}
			if diff := cmp.Diff(tt.wantCats, got.categories); diff != "" {
				t.Errorf("categories mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEmitLinkfinderFindingsFeedsCategories(t *testing.T) {
	reports := []report{{
		Resource: "https://example.com/page.html",
		Endpoints: []endpoint{
			{Link: "logo.svg"},
			{Link: "https://example.com/sitemap.xml"},
			{Link: "https://example.com/config.json"},
			{Link: "https://example.com/openapi.json"},
			{Link: "https://example.com/app.wasm"},
			{Link: "https://example.com/static/app.js"},
		},
	}}

	out := make(chan string, 20)
	result, err := emitFindings(reports, out)
	if err != nil {
		t.Fatalf("emitFindings returned error: %v", err)
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
		// sitemap.xml ya no se emite como "active: " porque tiene tipo específico xml
		// app.js ya no se emite como "active: " porque tiene tipo específico js
		"active: api: https://example.com/openapi.json",
		"active: crawl: https://example.com/sitemap.xml",
		"active: html: logo.svg",
		"active: js: https://example.com/static/app.js",
		"active: json: https://example.com/config.json",
		"active: meta-route: https://example.com/config.json",
		"active: svg: logo.svg",
		"active: wasm: https://example.com/app.wasm",
		"active: xml: https://example.com/sitemap.xml",
	}

	sort.Strings(wantLines)
	if diff := cmp.Diff(wantLines, lines); diff != "" {
		t.Fatalf("unexpected lines (-want +got):\n%s", diff)
	}

	sort.Strings(result.Undetected)
	if diff := cmp.Diff([]string{"logo.svg"}, result.Undetected); diff != "" {
		t.Fatalf("unexpected undetected entries (-want +got):\n%s", diff)
	}

	// Routes ya no incluye archivos con tipos específicos (js, xml, image)
	if diff := cmp.Diff([]string{
		"https://example.com/app.wasm",
		"https://example.com/config.json",
		"https://example.com/openapi.json",
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
	agg := newAggregate()
	agg.add("https://example.com/index.html", endpoint{Link: "https://example.com/api", Context: "fetch('/api')", Line: 10})

	tmp := t.TempDir()

	out := make(chan string, 10)
	if err := writeOutputs(tmp, agg, nil, out); err != nil {
		t.Fatalf("writeOutputs returned error: %v", err)
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

func TestEmitLinkfinderGFFindings(t *testing.T) {
	agg := newGFAggregate()
	agg.add("https://example.com/app.js", 42, "fetch('/api')", "const data = fetch('/api')", []string{"xss"})
	agg.add("https://example.com/app.js", 42, "fetch('/api')", "", []string{"sqli", "xss"})

	out := make(chan string, 1)
	if err := emitGFFindings(agg, out); err != nil {
		t.Fatalf("emitGFFindings returned error: %v", err)
	}
	close(out)

	var lines []string
	for line := range out {
		lines = append(lines, line)
	}
	if len(lines) != 1 {
		t.Fatalf("expected single gf finding line, got %d", len(lines))
	}

	line := lines[0]
	const prefix = "active: gffinding: "
	if !strings.HasPrefix(line, prefix) {
		t.Fatalf("unexpected line prefix: %q", line)
	}

	payload := strings.TrimPrefix(line, prefix)
	var data struct {
		Resource string   `json:"resource"`
		Line     int      `json:"line"`
		Evidence string   `json:"evidence"`
		Context  string   `json:"context"`
		Rules    []string `json:"rules"`
	}
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if data.Resource != "https://example.com/app.js" {
		t.Fatalf("unexpected resource: %q", data.Resource)
	}
	if data.Line != 42 {
		t.Fatalf("unexpected line: %d", data.Line)
	}
	if data.Evidence != "fetch('/api')" {
		t.Fatalf("unexpected evidence: %q", data.Evidence)
	}
	if want := []string{"sqli", "xss"}; !cmp.Equal(want, data.Rules) {
		t.Fatalf("unexpected rules (-want +got):\n%s", cmp.Diff(want, data.Rules))
	}
	if data.Context == "" {
		t.Fatalf("expected context to be preserved")
	}
}

func TestBuildLinkfinderArgsIncludesGF(t *testing.T) {
	args := buildArgs("input", "example.com", "raw", "html", "json", "html")
	found := false
	for i := 0; i < len(args); i++ {
		if args[i] == "--gf" && i+1 < len(args) && args[i+1] == "all" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected buildArgs to include --gf all, got %v", args)
	}
}

func TestBuildArgsUsesCorrectRecursiveDepth(t *testing.T) {
	tests := []struct {
		inputType string
		wantDepth string
	}{
		{inputType: "html", wantDepth: "2"},
		{inputType: "js", wantDepth: "2"},
		{inputType: "crawl", wantDepth: "4"},
	}

	for _, tt := range tests {
		t.Run(tt.inputType, func(t *testing.T) {
			args := buildArgs("input", "example.com", "raw", "html", "json", tt.inputType)
			found := false
			for i := 0; i < len(args); i++ {
				if args[i] == "-recursive" && i+1 < len(args) {
					if args[i+1] != tt.wantDepth {
						t.Fatalf("expected recursive depth %s for %s, got %s", tt.wantDepth, tt.inputType, args[i+1])
					}
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected buildArgs to include -recursive for %s, got %v", tt.inputType, args)
			}
		})
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

	if err := persistGFArtifacts(destDir, "html", srcDir); err != nil {
		t.Fatalf("persistGFArtifacts returned error: %v", err)
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

	if err := persistGFArtifacts(destDir, "html", srcDir); err != nil {
		t.Fatalf("persistGFArtifacts returned error on cleanup: %v", err)
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

	emission := emissionResult{
		Routes: []string{"https://existing.example", "https://example.com/new"},
		JS:     []string{"https://example.com/app.js"},
		HTML:   []string{"https://example.com/index.html"},
		Images: []string{"https://example.com/logo.png"},
		Categories: map[routes.Category][]string{
			routes.CategoryJSON:  {"https://example.com/config.json"},
			routes.CategorySVG:   {"https://example.com/icon.svg"},
			routes.CategoryCrawl: {"https://example.com/sitemap.xml"},
		},
	}

	if err := persistActiveOutputs(tmp, emission); err != nil {
		t.Fatalf("persistActiveOutputs returned error: %v", err)
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
			if got := cleanEndpointLink(tt.input); got != tt.want {
				t.Fatalf("cleanEndpointLink(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestMaybeSampleLinkfinderInputLimitsEntries(t *testing.T) {
	tmp := t.TempDir()

	var builder strings.Builder
	total := maxInputEntries + 50
	for i := 0; i < total; i++ {
		builder.WriteString(fmt.Sprintf("file://example.com/%d\n", i))
	}

	path, totalEntries, sampledEntries, err := maybeSampleInput(tmp, "html", []byte(builder.String()), maxInputEntries)
	if err != nil {
		t.Fatalf("maybeSampleInput returned error: %v", err)
	}
	if path == "" {
		t.Fatalf("expected sampling to occur when total=%d", total)
	}
	if totalEntries != total {
		t.Fatalf("unexpected total entries: got %d want %d", totalEntries, total)
	}
	if sampledEntries != maxInputEntries {
		t.Fatalf("unexpected sampled entries: got %d want %d", sampledEntries, maxInputEntries)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read sample file: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != maxInputEntries {
		t.Fatalf("sample file has unexpected number of entries: got %d want %d", len(lines), maxInputEntries)
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
	path, totalEntries, sampledEntries, err := maybeSampleInput(tmp, "html", []byte(builder.String()), limit)
	if err != nil {
		t.Fatalf("maybeSampleInput returned error: %v", err)
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
	path, totalEntries, sampledEntries, err := maybeSampleInput(tmp, "html", data, maxInputEntries)
	if err != nil {
		t.Fatalf("maybeSampleInput returned error: %v", err)
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
	maxTotal := 3 * maxInputEntries
	if got := entryBudget(ctxNoDeadline, maxTotal); got != maxTotal {
		t.Fatalf("expected full budget without deadline, got %d want %d", got, maxTotal)
	}

	deadline := time.Now().Add(3 * time.Second)
	ctxWithDeadline, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	budget := entryBudget(ctxWithDeadline, maxTotal)
	if budget <= 0 || budget > maxTotal {
		t.Fatalf("unexpected budget with deadline: got %d", budget)
	}

	farFuture := time.Now().Add(10 * time.Minute)
	ctxFuture, cancelFuture := context.WithDeadline(context.Background(), farFuture)
	defer cancelFuture()
	if got := entryBudget(ctxFuture, maxTotal); got != maxTotal {
		t.Fatalf("expected budget to clamp to max for far deadline, got %d want %d", got, maxTotal)
	}
}

func TestLinkFinderEVOIntegrationGeneratesReports(t *testing.T) {
	if _, err := os.Stat("/tmp/golinkfinder"); err != nil {
		t.Skip("GoLinkfinderEVO binary not available for integration test")
	}

	prevFindBin := findBin
	prevRunCmd := runCmd
	t.Cleanup(func() {
		findBin = prevFindBin
		runCmd = prevRunCmd
	})

	findBin = func(names ...string) (string, bool) {
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

	writeArtifacts(t, tmp, map[string][]string{
		"html": {"file://" + sample},
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out := make(chan string, 10)
	if err := Run(ctx, "https://example.com", tmp, out); err != nil {
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
	prevFindBin := findBin
	prevRunCmd := runCmd
	t.Cleanup(func() {
		findBin = prevFindBin
		runCmd = prevRunCmd
	})

	findBin = func(names ...string) (string, bool) {
		return "golinkfinder", true
	}

	var mu sync.Mutex
	var processed []int
	runCmd = func(ctx context.Context, dir string, name string, args []string, out chan<- string) error {
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
	artifactsData := make(map[string][]string)
	for _, sub := range []string{"html", "js", "crawl"} {
		if err := os.MkdirAll(filepath.Join(routesDir, sub), 0o755); err != nil {
			t.Fatalf("failed to create %s dir: %v", sub, err)
		}
		var builder strings.Builder
		var entries []string
		for i := 0; i < 100; i++ {
			value := fmt.Sprintf("file://example.com/%s/%d", sub, i)
			builder.WriteString(value + "\n")
			entries = append(entries, value)
		}
		if err := os.WriteFile(filepath.Join(routesDir, sub, fmt.Sprintf("%s.active", sub)), []byte(builder.String()), 0o644); err != nil {
			t.Fatalf("failed to write %s list: %v", sub, err)
		}
		artifactsData[sub] = entries
	}

	writeArtifacts(t, tmp, artifactsData)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(2*time.Second))
	defer cancel()
	expectedBudget := entryBudget(ctx, 3*maxInputEntries)
	if expectedBudget >= 100 {
		t.Fatalf("expected budget to be lower than input size, got %d", expectedBudget)
	}

	out := make(chan string, 20)
	if err := Run(ctx, "https://example.com", tmp, out); err != nil {
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
