package types

import (
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// DetectionResult representa el resultado de detectar el tipo de un artifact.
type DetectionResult struct {
	Type    string   // Tipo principal
	Subtype string   // Subtipo específico
	Tags    []string // Tags adicionales (opcional)
	Reason  string   // Razón de la detección (útil para debugging)
}

// DetectArtifactType es la función unificada para detectar el tipo de un artifact.
// Funciona tanto para URLs, dominios, certificados, y otros tipos de artifacts.
func DetectArtifactType(value string) DetectionResult {
	value = strings.TrimSpace(value)
	if value == "" {
		return DetectionResult{Type: "route", Subtype: "", Reason: "empty value"}
	}

	// Detectar tipos no-URL primero (certificados, dns, etc.)
	if strings.HasPrefix(value, "{") || strings.HasPrefix(value, "[") {
		// JSON - podría ser certificado u otro tipo estructurado
		if strings.Contains(value, "\"common_name\"") || strings.Contains(value, "\"issuer\"") {
			return DetectionResult{Type: "certificate", Subtype: "", Reason: "JSON structure with certificate fields"}
		}
		return DetectionResult{Type: "route", Subtype: "", Reason: "JSON structure"}
	}

	// Intentar parsear como URL
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" {
		// No es una URL válida - podría ser un dominio
		if isDomain(value) {
			return DetectionResult{Type: "domain", Subtype: "", Reason: "hostname without scheme"}
		}
		return DetectionResult{Type: "route", Subtype: "", Reason: "unparseable or plain text"}
	}

	// Ignorar esquemas especiales
	if u.Scheme == "data" || u.Scheme == "mailto" || u.Scheme == "tel" {
		return DetectionResult{Type: "route", Subtype: "", Reason: "special scheme: " + u.Scheme}
	}

	// Obtener componentes de la URL
	pathComponent := u.Path
	if pathComponent == "" && u.Opaque != "" {
		pathComponent = u.Opaque
	}

	// Quitar query/fragment del path
	if idx := strings.IndexAny(pathComponent, "?#"); idx != -1 {
		pathComponent = pathComponent[:idx]
	}

	// Normalizar path
	lowerPath := strings.ToLower(pathComponent)
	lowerPath = path.Clean("/" + lowerPath)
	lowerFull := strings.ToLower(u.Path)
	if u.RawQuery != "" {
		lowerFull += "?" + strings.ToLower(u.RawQuery)
	}

	base := strings.ToLower(filepath.Base(lowerPath))
	if base == "." || base == "/" {
		base = ""
	}
	ext := strings.ToLower(filepath.Ext(base))
	nameNoExt := strings.TrimSuffix(base, ext)

	// Detección por extensión (prioridad alta)
	if ext != "" {
		if result, ok := detectByExtension(ext, lowerPath, base, nameNoExt, lowerFull); ok {
			return result
		}
	}

	// Detección por contenido/path (prioridad media)
	if result, ok := detectByPath(lowerPath, lowerFull, base, nameNoExt); ok {
		return result
	}

	// Default: route genérica
	return DetectionResult{Type: "route", Subtype: "", Reason: "no specific type detected"}
}

// detectByExtension detecta el tipo basándose en la extensión del archivo.
func detectByExtension(ext, lowerPath, base, nameNoExt, lowerFull string) (DetectionResult, bool) {
	switch ext {
	// JavaScript
	case ".js", ".mjs", ".cjs":
		return DetectionResult{Type: "resource", Subtype: "javascript", Reason: "extension: " + ext}, true

	// HTML
	case ".html", ".htm":
		return DetectionResult{Type: "resource", Subtype: "html", Reason: "extension: " + ext}, true

	// CSS
	case ".css":
		return DetectionResult{Type: "resource", Subtype: "css", Reason: "extension: " + ext}, true

	// Images
	case ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".bmp", ".ico":
		return DetectionResult{Type: "resource", Subtype: "image", Reason: "extension: " + ext}, true

	// Fonts
	case ".woff", ".woff2", ".ttf", ".otf", ".eot":
		return DetectionResult{Type: "resource", Subtype: "font", Reason: "extension: " + ext}, true

	// Video
	case ".mp4", ".webm", ".mkv", ".mov", ".avi":
		return DetectionResult{Type: "resource", Subtype: "video", Reason: "extension: " + ext}, true

	// Documents
	case ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odp", ".ods", ".odt", ".rtf":
		return DetectionResult{Type: "resource", Subtype: "document", Reason: "extension: " + ext}, true

	// Archives
	case ".zip", ".rar", ".7z", ".tar", ".tgz", ".gz":
		return DetectionResult{Type: "resource", Subtype: "archive", Reason: "extension: " + ext}, true

	// Source maps
	case ".map":
		return DetectionResult{Type: "meta", Subtype: "sourcemap", Reason: "extension: .map"}, true

	// WASM
	case ".wasm":
		return DetectionResult{Type: "meta", Subtype: "wasm", Reason: "extension: .wasm"}, true

	// SVG (es especial - puede ser imagen o meta)
	case ".svg":
		return DetectionResult{Type: "meta", Subtype: "svg", Reason: "extension: .svg"}, true

	// JSON (necesita análisis adicional)
	case ".json", ".jsonld":
		if isAPIDocument(lowerPath, base, nameNoExt, lowerFull) {
			return DetectionResult{Type: "endpoint", Subtype: "rest", Tags: []string{"openapi"}, Reason: "JSON API document"}, true
		}
		return DetectionResult{Type: "data", Subtype: "json", Reason: "extension: " + ext}, true

	// YAML (necesita análisis adicional)
	case ".yaml", ".yml":
		if isAPIDocument(lowerPath, base, nameNoExt, lowerFull) {
			return DetectionResult{Type: "endpoint", Subtype: "rest", Tags: []string{"openapi"}, Reason: "YAML API document"}, true
		}
		return DetectionResult{Type: "data", Subtype: "xml", Reason: "extension: " + ext}, true

	// XML (necesita análisis adicional)
	case ".xml":
		if isCrawlFile(base, nameNoExt) {
			return DetectionResult{Type: "meta", Subtype: "crawl", Tags: []string{"sitemap"}, Reason: "XML sitemap"}, true
		}
		return DetectionResult{Type: "data", Subtype: "xml", Reason: "extension: .xml"}, true

	// TXT especial (robots.txt)
	case ".txt":
		if base == "robots.txt" {
			return DetectionResult{Type: "meta", Subtype: "crawl", Tags: []string{"robots"}, Reason: "robots.txt"}, true
		}
		return DetectionResult{Type: "resource", Subtype: "document", Reason: "extension: .txt"}, true

	default:
		return DetectionResult{}, false
	}
}

// detectByPath detecta el tipo basándose en patrones en el path.
func detectByPath(lowerPath, lowerFull, base, nameNoExt string) (DetectionResult, bool) {
	// GraphQL
	if isGraphQL(lowerPath, base, lowerFull) {
		return DetectionResult{Type: "endpoint", Subtype: "graphql", Reason: "GraphQL path pattern"}, true
	}

	// API endpoints
	if looksLikeAPIEndpoint(lowerPath) {
		return DetectionResult{Type: "endpoint", Subtype: "rest", Reason: "API path pattern (/api, /v1, etc.)"}, true
	}

	// robots.txt sin extensión
	if base == "robots.txt" || strings.HasSuffix(lowerPath, "/robots") {
		return DetectionResult{Type: "meta", Subtype: "crawl", Tags: []string{"robots"}, Reason: "robots path"}, true
	}

	// Sitemap sin extensión
	if strings.Contains(nameNoExt, "sitemap") {
		return DetectionResult{Type: "meta", Subtype: "crawl", Tags: []string{"sitemap"}, Reason: "sitemap path"}, true
	}

	// Meta/secretos basándose en nombres sensibles
	if shouldCategorizeMeta(base, nameNoExt, lowerFull) {
		return DetectionResult{Type: "meta", Subtype: "route", Tags: []string{"sensitive"}, Reason: "sensitive keywords in path"}, true
	}

	return DetectionResult{}, false
}

// isDomain verifica si un string es un dominio válido (sin scheme).
func isDomain(value string) bool {
	// Verificar que no tenga caracteres de URL
	if strings.Contains(value, "/") || strings.Contains(value, "?") {
		return false
	}
	// Verificar que tenga al menos un punto
	if !strings.Contains(value, ".") {
		return false
	}
	// Verificar formato básico de dominio
	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
	}
	return true
}

// Regexes compiladas para mejor rendimiento
var (
	reAPIDoc     = regexp.MustCompile(`(?i)(swagger|openapi|api[-_]?doc|api[-_]?spec|apispec|api[-_]?definition)`)
	reAPISegment = regexp.MustCompile(`(?i)(^|/)(api|v\d+|beta|rest|services)(/|$)`)
	reGraphQL    = regexp.MustCompile(`(?i)(^|/)(graphql|graphi?ql|playground)(/|$)`)
)

func isAPIDocument(lowerPath, base, nameNoExt, lowerFull string) bool {
	if reAPIDoc.MatchString(lowerPath) || reAPIDoc.MatchString(base) {
		return true
	}
	if nameNoExt == "api" && (strings.Contains(lowerFull, "openapi") || strings.Contains(lowerFull, "swagger")) {
		return true
	}
	if strings.Contains(lowerFull, "format=openapi") || strings.Contains(lowerFull, "format=swagger") {
		return true
	}
	return false
}

func looksLikeAPIEndpoint(lowerPath string) bool {
	if reAPISegment.MatchString(lowerPath) {
		return true
	}
	if strings.Contains(lowerPath, "/rest/") || strings.Contains(lowerPath, "/services/") {
		return true
	}
	return false
}

func isGraphQL(lowerPath, base, lowerFull string) bool {
	if reGraphQL.MatchString(lowerPath) || reGraphQL.MatchString(base) {
		return true
	}
	if (strings.Contains(lowerFull, "operationname=") || strings.Contains(lowerFull, "query=")) &&
		reGraphQL.MatchString(lowerFull) {
		return true
	}
	return false
}

func isCrawlFile(base, nameNoExt string) bool {
	return strings.Contains(nameNoExt, "sitemap") || base == "sitemap.xml" || base == "sitemap_index.xml"
}

func shouldCategorizeMeta(base, nameNoExt, lowerFull string) bool {
	if base == "" {
		return false
	}

	// Keywords sensibles en el nombre del archivo
	keywords := []string{
		"backup", "secret", "secrets", "token", "password", "passwd", "credential", "creds",
		"config", "database", "db", "id_rsa", ".env", ".git", ".svn", "ssh", "private", "keystore",
		".bak", ".old", ".swp", ".sql", ".sqlite", ".pem", ".key", ".p12", ".pfx",
	}
	lowerBase := strings.ToLower(base)
	for _, kw := range keywords {
		if strings.Contains(lowerBase, kw) {
			return true
		}
	}

	// Keywords sensibles en query params
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
