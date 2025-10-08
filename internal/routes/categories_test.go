package routes

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDetectCategories(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []Category
	}{
		{name: "map", input: "https://example.com/static/app.js.map", want: []Category{CategoryMaps}},
		{name: "svg", input: "logo.svg", want: []Category{CategorySVG}},
		{name: "wasm", input: "https://cdn.example.com/app.wasm", want: []Category{CategoryWASM}},
		{name: "json", input: "https://example.com/config.json", want: []Category{CategoryJSON, CategoryMeta}},
		{name: "api json", input: "https://example.com/openapi.json", want: []Category{CategoryAPI}},
		{name: "crawl xml", input: "https://example.com/sitemap.xml", want: []Category{CategoryCrawl}},
		{name: "crawl robots", input: "robots.txt", want: []Category{CategoryCrawl, CategoryDocs}},
		{name: "meta", input: "https://example.com/backup.zip", want: []Category{CategoryArchives, CategoryMeta}},
		{name: "multiple", input: "https://example.com/backup.zip?token=abc", want: []Category{CategoryArchives, CategoryMeta}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectCategories(tt.input)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("DetectCategories(%q) mismatch (-want +got):\n%s", tt.input, diff)
			}
		})
	}
}
