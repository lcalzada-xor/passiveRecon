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
	isCSS      bool
	isPDF      bool
	isDoc      bool
	isFont     bool
	isVideo    bool
	isArchive  bool
	isXML      bool
	undetected bool
	categories []routes.Category
}

func classifyEndpoint(link string) classification {
	lower := strings.ToLower(link)
	ext := urlutil.ExtractExtension(link)

	cls := classification{}

	// Clasificación por extensión (más exhaustiva)
	switch ext {
	// JavaScript
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx":
		cls.isJS = true

	// HTML y plantillas server-side
	case ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".jspx", ".cfm", ".shtml", ".ejs", ".hbs", ".handlebars", ".mustache", ".twig", ".blade.php":
		cls.isHTML = true

	// Imágenes (raster)
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".ico", ".tif", ".tiff", ".jfif", ".avif", ".apng", ".heic", ".heif":
		cls.isImage = true

	// CSS
	case ".css", ".scss", ".sass", ".less":
		cls.isCSS = true

	// PDFs
	case ".pdf":
		cls.isPDF = true

	// Documentos
	case ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".txt":
		cls.isDoc = true

	// Fuentes
	case ".woff", ".woff2", ".ttf", ".otf", ".eot":
		cls.isFont = true

	// Video
	case ".mp4", ".webm", ".mkv", ".mov", ".avi", ".flv", ".wmv", ".m4v":
		cls.isVideo = true

	// Archivos comprimidos
	case ".zip", ".rar", ".7z", ".tar", ".tgz", ".gz", ".bz2", ".xz":
		cls.isArchive = true

	// XML (incluye SVG que también se detecta como categoría especial)
	case ".xml", ".xsl", ".xslt", ".rdf":
		cls.isXML = true

	// SVG se marca como imagen también (aunque es vector)
	case ".svg":
		cls.isImage = true
	}

	// Detectar categorías especializadas (API, WASM, Maps, etc.)
	cls.categories = routes.DetectCategories(link)

	// Marcar como no detectado si no tiene prefijo URL completo
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
