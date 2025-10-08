package routes

import (
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Category representa grupos especializados para enrutar artefactos.
type Category string

const (
	CategoryMaps     Category = "maps"
	CategoryJSON     Category = "json"
	CategoryAPI      Category = "api"
	CategoryWASM     Category = "wasm"
	CategorySVG      Category = "svg"
	CategoryCrawl    Category = "crawl"
	CategoryMeta     Category = "meta"
	CategoryJS       Category = "js"
	CategoryCSS      Category = "css"
	CategoryHTML     Category = "html"
	CategoryImages   Category = "images"
	CategoryFonts    Category = "fonts"
	CategoryVideo    Category = "video"
	CategoryDocs     Category = "docs"
	CategoryArchives Category = "archives"
	CategoryFeeds    Category = "feeds"
	CategoryGraphQL  Category = "graphql"
)

// Categorization devuelve categorías y razones (útil para logging / informes)
type Categorization struct {
	Categories []Category
	Reasons    []string
}

// DetectCategories se mantiene para compatibilidad.
func DetectCategories(route string) []Category {
	c := DetectCategoriesEx(route)
	return c.Categories
}

// DetectCategoriesEx realiza la detección ampliada con razones.
func DetectCategoriesEx(route string) Categorization {
	trimmed := strings.TrimSpace(route)
	if trimmed == "" {
		return Categorization{}
	}

	// Ignora esquemas no web típicos
	if strings.HasPrefix(trimmed, "data:") || strings.HasPrefix(trimmed, "mailto:") || strings.HasPrefix(trimmed, "tel:") {
		return Categorization{}
	}

	lowerFull := strings.ToLower(trimmed)
	pathComponent := trimmed
	u, err := url.Parse(trimmed)
	if err == nil {
		if u.Path != "" {
			pathComponent = u.Path
		} else if u.Opaque != "" {
			pathComponent = u.Opaque
		}
		// reconstruye lowerFull con path + query normalizados
		lowerFull = strings.ToLower(u.Path)
		if u.RawQuery != "" {
			lowerFull += "?" + strings.ToLower(u.RawQuery)
		}
	}

	// quita query/fragment del pathComponent
	if idx := strings.IndexAny(pathComponent, "?#"); idx != -1 {
		pathComponent = pathComponent[:idx]
	}
	pathComponent = strings.TrimSpace(pathComponent)
	lowerPath := strings.ToLower(pathComponent)

	// normaliza dobles barras y trailing slash
	lowerPath = path.Clean("/" + lowerPath)

	base := strings.ToLower(filepath.Base(lowerPath))
	if base == "." || base == "/" {
		base = ""
	}
	ext := strings.ToLower(filepath.Ext(base))
	nameNoExt := strings.TrimSuffix(base, ext)

	added := map[Category]bool{}
	reasons := []string{}
	add := func(cat Category, reason string) {
		if !added[cat] {
			added[cat] = true
			reasons = append(reasons, reason)
		}
	}

	// --- Reglas por extensión rápida (tabla) ---
	if ext != "" {
		switch ext {
		case ".map":
			add(CategoryMaps, "ext .map (source map)")
		case ".wasm":
			add(CategoryWASM, "ext .wasm")
		case ".svg":
			add(CategorySVG, "ext .svg")
		case ".jsonld":
			add(CategoryJSON, "ext .jsonld")
		case ".json":
			if isAPIDocument(lowerPath, base, nameNoExt, lowerFull) {
				add(CategoryAPI, "json con indicadores de API")
			} else if looksLikeFeed(lowerPath) {
				add(CategoryFeeds, "json con patrón de feed")
			} else {
				add(CategoryJSON, "ext .json")
			}
		case ".yaml", ".yml":
			if isAPIDocument(lowerPath, base, nameNoExt, lowerFull) {
				add(CategoryAPI, "yaml con indicadores de API")
			}
		case ".xml":
			if isCrawlFile(base, nameNoExt) {
				add(CategoryCrawl, "xml tipo sitemap")
			} else if looksLikeFeed(lowerPath) {
				add(CategoryFeeds, "xml tipo feed (rss/atom)")
			}
		case ".txt":
			if base == "robots.txt" {
				add(CategoryCrawl, "robots.txt")
			}
		}

		// Tipos estáticos comunes
		switch ext {
		case ".js", ".mjs", ".cjs":
			add(CategoryJS, "ext JS")
		case ".css":
			add(CategoryCSS, "ext CSS")
		case ".html", ".htm":
			add(CategoryHTML, "ext HTML")
		case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".ico":
			add(CategoryImages, "ext imagen")
		case ".woff", ".woff2", ".ttf", ".otf", ".eot":
			add(CategoryFonts, "ext fuente")
		case ".mp4", ".webm", ".mkv", ".mov", ".avi":
			add(CategoryVideo, "ext vídeo")
		case ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odp", ".ods", ".odt", ".rtf", ".txt":
			add(CategoryDocs, "ext documento")
		case ".zip", ".rar", ".7z", ".tar", ".tgz", ".gz":
			add(CategoryArchives, "ext archivo comprimido")
		}
	}

	// --- Reglas por nombre/base sin extensión ---
	if base == "robots.txt" {
		add(CategoryCrawl, "robots.txt (nombre)")
	}
	if ext == "" && isCrawlPathWithoutExt(lowerPath) {
		add(CategoryCrawl, "ruta robots sin extensión")
	}

	// GraphQL
	if isGraphQL(lowerPath, base, lowerFull) {
		add(CategoryGraphQL, "ruta GraphQL")
		add(CategoryAPI, "GraphQL es API")
	}

	// Señales de API por path (aunque no sea doc)
	if looksLikeAPIEndpoint(lowerPath) {
		add(CategoryAPI, "segmentos de path sugieren API (/api, /v1, etc.)")
	}

	// Señales de FEEDS por path
	if looksLikeFeed(lowerPath) {
		add(CategoryFeeds, "ruta sugiere feed (rss/atom)")
	}

	// Heurística META (secretos, backups, etc.)
	if shouldCategorizeMeta(base, nameNoExt, ext, lowerFull) {
		add(CategoryMeta, "heurística de meta/secretos")
	}

	// Devuelve categorías en orden estable
	cats := make([]Category, 0, len(orderedCats))
	for _, c := range orderedCats {
		if added[c] {
			cats = append(cats, c)
		}
	}
	return Categorization{Categories: cats, Reasons: reasons}
}

// Orden preferente para salida estable
var orderedCats = []Category{
	CategoryAPI,
	CategoryGraphQL,
	CategoryCrawl,
	CategoryJSON,
	CategoryFeeds,
	CategoryJS,
	CategoryCSS,
	CategoryHTML,
	CategorySVG,
	CategoryWASM,
	CategoryImages,
	CategoryFonts,
	CategoryVideo,
	CategoryDocs,
	CategoryArchives,
	CategoryMaps,
	CategoryMeta,
}

var reAPIDoc = regexp.MustCompile(`(?i)(swagger|openapi|api[-_]?doc|api[-_]?spec|apispec|api[-_]?definition)`)
var reAPISegment = regexp.MustCompile(`(?i)(^|/)(api|v\d+|beta|graphql)(/|$)`)
var reGraphQL = regexp.MustCompile(`(?i)(^|/)(graphql|graphi?ql|playground)(/|$)`)
var reFeeds = regexp.MustCompile(`(?i)(^|/)(feed|rss|atom)(/|$)`)

func isAPIDocument(lowerPath, base, nameNoExt, lowerFull string) bool {
	if reAPIDoc.MatchString(lowerPath) || reAPIDoc.MatchString(base) {
		return true
	}
	if nameNoExt == "api" && (strings.Contains(lowerFull, "openapi") || strings.Contains(lowerFull, "swagger")) {
		return true
	}
	// query hints (e.g., ?format=openapi)
	if strings.Contains(lowerFull, "format=openapi") || strings.Contains(lowerFull, "format=swagger") {
		return true
	}
	return false
}

func looksLikeAPIEndpoint(lowerPath string) bool {
	// Señales suaves de endpoint de API
	if reAPISegment.MatchString(lowerPath) {
		return true
	}
	// /rest/ o /services/
	if strings.Contains(lowerPath, "/rest/") || strings.Contains(lowerPath, "/services/") {
		return true
	}
	return false
}

func isGraphQL(lowerPath, base, lowerFull string) bool {
	if reGraphQL.MatchString(lowerPath) || reGraphQL.MatchString(base) {
		return true
	}
	// query hints: ?query=... o operationName
	if (strings.Contains(lowerFull, "operationname=") || strings.Contains(lowerFull, "query=")) &&
		reGraphQL.MatchString(lowerFull) {
		return true
	}
	return false
}

func looksLikeFeed(lowerPath string) bool {
	if reFeeds.MatchString(lowerPath) {
		return true
	}
	// patrones comunes
	if strings.HasSuffix(lowerPath, "/feed") || strings.HasSuffix(lowerPath, "/rss") || strings.HasSuffix(lowerPath, "/atom") {
		return true
	}
	return false
}

func isCrawlFile(base, nameNoExt string) bool {
	return strings.Contains(nameNoExt, "sitemap") || base == "sitemap.xml" || base == "sitemap_index.xml"
}

func isCrawlPathWithoutExt(lowerPath string) bool {
	return strings.HasSuffix(lowerPath, "/robots") || strings.HasSuffix(lowerPath, "/robots/")
}

func shouldCategorizeMeta(base, nameNoExt, ext, lowerFull string) bool {
	if base == "" {
		return false
	}

	sensitiveExts := map[string]struct{}{
		".bak": {}, ".old": {}, ".swp": {}, ".sql": {}, ".db": {}, ".sqlite": {},
		".env": {}, ".ini": {}, ".cfg": {}, ".config": {}, ".conf": {}, ".log": {},
		".pem": {}, ".key": {}, ".p12": {}, ".pfx": {}, ".crt": {},
	}
	if _, ok := sensitiveExts[ext]; ok {
		return true
	}

	archiveExts := []string{".zip", ".rar", ".7z", ".tar", ".tgz", ".gz"}
	for _, archiveExt := range archiveExts {
		if strings.HasSuffix(base, archiveExt) {
			if strings.Contains(nameNoExt, "backup") ||
				strings.Contains(nameNoExt, "config") ||
				strings.Contains(nameNoExt, "secret") ||
				strings.Contains(nameNoExt, "database") ||
				strings.Contains(nameNoExt, "db") {
				return true
			}
		}
	}

	lowerBase := base
	keywords := []string{
		"backup", "secret", "secrets", "token", "password", "passwd", "credential", "creds",
		"config", "database", "db", "id_rsa", ".env", ".git", ".svn", "ssh", "private", "keystore", "keystore",
	}
	for _, kw := range keywords {
		if strings.Contains(lowerBase, kw) {
			return true
		}
	}

	queryKeywords := []string{
		"token=", "secret=", "password=", "passwd=", "key=", "apikey=", "api_key=",
		"access_token=", "auth=", "credential", "private_key=", "signature=",
	}
	for _, kw := range queryKeywords {
		if strings.Contains(lowerFull, kw) {
			return true
		}
	}

	return false
}
