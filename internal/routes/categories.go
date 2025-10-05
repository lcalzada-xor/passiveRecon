package routes

import (
	"net/url"
	"path/filepath"
	"strings"
)

// Category represents a specialised route grouping derived from an URL or path.
type Category string

const (
	CategoryMaps  Category = "maps"
	CategoryJSON  Category = "json"
	CategoryAPI   Category = "api"
	CategoryWASM  Category = "wasm"
	CategorySVG   Category = "svg"
	CategoryCrawl Category = "crawl"
	CategoryMeta  Category = "meta"
)

// DetectCategories inspects the provided route and returns the inferred
// specialised categories that should receive the entry.
func DetectCategories(route string) []Category {
	trimmed := strings.TrimSpace(route)
	if trimmed == "" {
		return nil
	}

	lowerFull := strings.ToLower(trimmed)
	pathComponent := trimmed
	if u, err := url.Parse(trimmed); err == nil {
		if u.Path != "" {
			pathComponent = u.Path
		}
		lowerFull = strings.ToLower(u.Path)
		if u.RawQuery != "" {
			lowerFull += "?" + strings.ToLower(u.RawQuery)
		}
	}

	if idx := strings.IndexAny(pathComponent, "?#"); idx != -1 {
		pathComponent = pathComponent[:idx]
	}
	pathComponent = strings.TrimSpace(pathComponent)
	lowerPath := strings.ToLower(pathComponent)

	base := strings.ToLower(filepath.Base(pathComponent))
	if base == "." || base == "/" {
		base = ""
	}
	ext := strings.ToLower(filepath.Ext(base))
	nameNoExt := strings.TrimSuffix(base, ext)

	appendCat := func(categories []Category, cat Category) []Category {
		for _, existing := range categories {
			if existing == cat {
				return categories
			}
		}
		return append(categories, cat)
	}

	var categories []Category

	switch ext {
	case ".map":
		categories = appendCat(categories, CategoryMaps)
	case ".wasm":
		categories = appendCat(categories, CategoryWASM)
	case ".svg":
		categories = appendCat(categories, CategorySVG)
	case ".jsonld":
		categories = appendCat(categories, CategoryJSON)
	case ".json":
		if isAPIDocument(lowerPath, base, nameNoExt, lowerFull) {
			categories = appendCat(categories, CategoryAPI)
		} else {
			categories = appendCat(categories, CategoryJSON)
		}
	case ".yaml", ".yml":
		if isAPIDocument(lowerPath, base, nameNoExt, lowerFull) {
			categories = appendCat(categories, CategoryAPI)
		}
	case ".xml":
		if isCrawlFile(base, nameNoExt) {
			categories = appendCat(categories, CategoryCrawl)
		}
	case ".txt":
		if base == "robots.txt" {
			categories = appendCat(categories, CategoryCrawl)
		}
	case ".gz":
		if strings.HasSuffix(base, "sitemap.xml.gz") || strings.HasSuffix(nameNoExt, "sitemap.xml") {
			categories = appendCat(categories, CategoryCrawl)
		}
	}

	if base == "robots.txt" {
		categories = appendCat(categories, CategoryCrawl)
	}
	if ext == "" && isCrawlPathWithoutExt(lowerPath) {
		categories = appendCat(categories, CategoryCrawl)
	}

	if shouldCategorizeMeta(base, nameNoExt, ext, lowerFull) {
		categories = appendCat(categories, CategoryMeta)
	}

	return categories
}

func isAPIDocument(lowerPath, base, nameNoExt, lowerFull string) bool {
	keywords := []string{"swagger", "openapi", "api-doc", "api_docs", "apispec", "api-spec", "api_spec", "api-definition", "api_definition"}
	for _, kw := range keywords {
		if strings.Contains(lowerPath, kw) {
			return true
		}
	}
	for _, kw := range keywords {
		if strings.Contains(base, kw) {
			return true
		}
	}
	if nameNoExt == "api" && (strings.Contains(lowerFull, "openapi") || strings.Contains(lowerFull, "swagger")) {
		return true
	}
	return false
}

func isCrawlFile(base, nameNoExt string) bool {
	if strings.Contains(nameNoExt, "sitemap") {
		return true
	}
	return false
}

func isCrawlPathWithoutExt(lowerPath string) bool {
	if strings.HasSuffix(lowerPath, "/robots") || strings.HasSuffix(lowerPath, "/robots/") {
		return true
	}
	return false
}

func shouldCategorizeMeta(base, nameNoExt, ext, lowerFull string) bool {
	if base == "" {
		return false
	}

	sensitiveExts := map[string]struct{}{
		".bak":    {},
		".old":    {},
		".swp":    {},
		".sql":    {},
		".db":     {},
		".sqlite": {},
		".env":    {},
		".ini":    {},
		".cfg":    {},
		".config": {},
		".conf":   {},
		".log":    {},
	}

	if _, ok := sensitiveExts[ext]; ok {
		return true
	}

	archiveExts := []string{".zip", ".rar", ".7z", ".tar", ".tgz", ".gz"}
	for _, archiveExt := range archiveExts {
		if strings.HasSuffix(base, archiveExt) {
			if strings.Contains(nameNoExt, "backup") || strings.Contains(nameNoExt, "config") || strings.Contains(nameNoExt, "secret") || strings.Contains(nameNoExt, "database") || strings.Contains(nameNoExt, "db") {
				return true
			}
		}
	}

	lowerBase := base
	keywords := []string{"backup", "secret", "token", "password", "passwd", "credential", "creds", "config", "database", "db", "id_rsa", ".env", ".git", ".svn", "ssh", "private"}
	for _, kw := range keywords {
		if strings.Contains(lowerBase, kw) {
			return true
		}
	}

	queryKeywords := []string{"token=", "secret=", "password=", "passwd=", "key=", "apikey=", "api_key=", "access_token=", "auth=", "credential"}
	for _, kw := range queryKeywords {
		if strings.Contains(lowerFull, kw) {
			return true
		}
	}

	return false
}
