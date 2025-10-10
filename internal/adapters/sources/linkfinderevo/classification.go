package linkfinderevo

import (
	"strings"

	"passive-rec/internal/adapters/routes"
	"passive-rec/internal/platform/urlutil"
)

type classification struct {
	isJS       bool
	isHTML     bool
	isImage    bool
	undetected bool
	categories []routes.Category
}

func classifyEndpoint(link string) classification {
	lower := strings.ToLower(link)
	ext := urlutil.ExtractExtension(link)

	cls := classification{}

	switch ext {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx":
		cls.isJS = true
	case ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".jspx", ".cfm", ".shtml":
		cls.isHTML = true
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tif", ".tiff", ".jfif", ".avif", ".apng", ".heic", ".heif":
		cls.isImage = true
	}

	cls.categories = routes.DetectCategories(link)

	if !hasCompleteURLPrefix(lower) {
		cls.undetected = true
	}

	return cls
}

func hasCompleteURLPrefix(link string) bool {
	prefixes := []string{"http://", "https://", "file://", "ftp://", "ftps://", "//", "/", "./", "../"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(link, prefix) {
			return true
		}
	}
	return false
}

var categoryPrefixes = map[routes.Category]string{
	routes.CategoryMaps:  "maps",
	routes.CategoryJSON:  "json",
	routes.CategoryAPI:   "api",
	routes.CategoryWASM:  "wasm",
	routes.CategorySVG:   "svg",
	routes.CategoryCrawl: "crawl",
	routes.CategoryMeta:  "meta-route",
}
