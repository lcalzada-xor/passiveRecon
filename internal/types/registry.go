package types

// Category representa una agrupación lógica de tipos de artifacts
type Category int

const (
	CategoryUnknown Category = iota
	CategoryDomain
	CategoryRoute
	CategoryWebResource
	CategoryEndpoint
	CategoryData
	CategoryMeta
	CategorySecurity
	CategoryInfrastructure
)

// TypeDef define la configuración completa de un tipo de artifact
type TypeDef struct {
	Type           string   // Tipo principal (ej: "resource")
	Subtype        string   // Subtipo específico (ej: "javascript")
	KeyspacePrefix string   // Prefijo para keyspace de deduplicación
	OutputDir      string   // Directorio de salida para materialización
	OutputFile     string   // Nombre base del archivo de salida
	Category       Category // Categoría lógica
	CheckScope     bool     // Si debe verificar scope
	UseRawMetadata bool     // Si debe usar raw metadata en output
}

// Registry es el single source of truth para todas las definiciones de tipos
var Registry = map[string]TypeDef{
	// ========================================================================
	// DOMAIN
	// ========================================================================
	"domain": {
		Type:           "domain",
		Subtype:        "",
		KeyspacePrefix: "domain",
		OutputDir:      "domains",
		OutputFile:     "domains",
		Category:       CategoryDomain,
		CheckScope:     true,
		UseRawMetadata: true,
	},

	// ========================================================================
	// ROUTE (Generic)
	// ========================================================================
	"route": {
		Type:           "route",
		Subtype:        "",
		KeyspacePrefix: "route",
		OutputDir:      "routes",
		OutputFile:     "routes",
		Category:       CategoryRoute,
		CheckScope:     true,
		UseRawMetadata: false,
	},

	// ========================================================================
	// RESOURCES (Static web resources)
	// ========================================================================
	"resource.javascript": {
		Type:           "resource",
		Subtype:        "javascript",
		KeyspacePrefix: "resource:js",
		OutputDir:      "routes/js",
		OutputFile:     "js",
		Category:       CategoryWebResource,
		CheckScope:     true,
		UseRawMetadata: true,
	},
	"resource.html": {
		Type:           "resource",
		Subtype:        "html",
		KeyspacePrefix: "resource:html",
		OutputDir:      "routes/html",
		OutputFile:     "html",
		Category:       CategoryWebResource,
		CheckScope:     true,
		UseRawMetadata: true,
	},
	"resource.css": {
		Type:           "resource",
		Subtype:        "css",
		KeyspacePrefix: "resource:css",
		OutputDir:      "routes/css",
		OutputFile:     "css",
		Category:       CategoryWebResource,
		CheckScope:     true,
		UseRawMetadata: false,
	},
	"resource.image": {
		Type:           "resource",
		Subtype:        "image",
		KeyspacePrefix: "resource:image",
		OutputDir:      "routes/images",
		OutputFile:     "images",
		Category:       CategoryWebResource,
		CheckScope:     true,
		UseRawMetadata: true,
	},
	"resource.font": {
		Type:           "resource",
		Subtype:        "font",
		KeyspacePrefix: "resource:font",
		OutputDir:      "routes/fonts",
		OutputFile:     "fonts",
		Category:       CategoryWebResource,
		CheckScope:     true,
		UseRawMetadata: false,
	},
	"resource.video": {
		Type:           "resource",
		Subtype:        "video",
		KeyspacePrefix: "resource:video",
		OutputDir:      "routes/video",
		OutputFile:     "video",
		Category:       CategoryWebResource,
		CheckScope:     true,
		UseRawMetadata: false,
	},
	"resource.document": {
		Type:           "resource",
		Subtype:        "document",
		KeyspacePrefix: "resource:doc",
		OutputDir:      "routes/docs",
		OutputFile:     "docs",
		Category:       CategoryWebResource,
		CheckScope:     true,
		UseRawMetadata: false,
	},
	"resource.archive": {
		Type:           "resource",
		Subtype:        "archive",
		KeyspacePrefix: "resource:archive",
		OutputDir:      "routes/archives",
		OutputFile:     "archives",
		Category:       CategoryWebResource,
		CheckScope:     true,
		UseRawMetadata: false,
	},

	// ========================================================================
	// ENDPOINTS (API endpoints)
	// ========================================================================
	"endpoint.rest": {
		Type:           "endpoint",
		Subtype:        "rest",
		KeyspacePrefix: "endpoint:api",
		OutputDir:      "routes/api",
		OutputFile:     "api",
		Category:       CategoryEndpoint,
		CheckScope:     true,
		UseRawMetadata: false,
	},
	"endpoint.graphql": {
		Type:           "endpoint",
		Subtype:        "graphql",
		KeyspacePrefix: "endpoint:graphql",
		OutputDir:      "routes/graphql",
		OutputFile:     "graphql",
		Category:       CategoryEndpoint,
		CheckScope:     true,
		UseRawMetadata: false,
	},

	// ========================================================================
	// DATA (Structured data files)
	// ========================================================================
	"data.json": {
		Type:           "data",
		Subtype:        "json",
		KeyspacePrefix: "data:json",
		OutputDir:      "routes/json",
		OutputFile:     "json",
		Category:       CategoryData,
		CheckScope:     true,
		UseRawMetadata: false,
	},
	"data.xml": {
		Type:           "data",
		Subtype:        "xml",
		KeyspacePrefix: "data:xml",
		OutputDir:      "routes/xml",
		OutputFile:     "xml",
		Category:       CategoryData,
		CheckScope:     true,
		UseRawMetadata: false,
	},

	// ========================================================================
	// META (Configuration and mapping files)
	// ========================================================================
	"meta.sourcemap": {
		Type:           "meta",
		Subtype:        "sourcemap",
		KeyspacePrefix: "meta:maps",
		OutputDir:      "routes/maps",
		OutputFile:     "maps",
		Category:       CategoryMeta,
		CheckScope:     true,
		UseRawMetadata: false,
	},
	"meta.wasm": {
		Type:           "meta",
		Subtype:        "wasm",
		KeyspacePrefix: "meta:wasm",
		OutputDir:      "routes/wasm",
		OutputFile:     "wasm",
		Category:       CategoryMeta,
		CheckScope:     true,
		UseRawMetadata: false,
	},
	"meta.svg": {
		Type:           "meta",
		Subtype:        "svg",
		KeyspacePrefix: "meta:svg",
		OutputDir:      "routes/svg",
		OutputFile:     "svg",
		Category:       CategoryMeta,
		CheckScope:     true,
		UseRawMetadata: false,
	},
	"meta.crawl": {
		Type:           "meta",
		Subtype:        "crawl",
		KeyspacePrefix: "meta:crawl",
		OutputDir:      "routes/crawl",
		OutputFile:     "crawl",
		Category:       CategoryMeta,
		CheckScope:     true,
		UseRawMetadata: false,
	},
	"meta.route": {
		Type:           "meta",
		Subtype:        "route",
		KeyspacePrefix: "meta:route",
		OutputDir:      "routes/meta",
		OutputFile:     "meta",
		Category:       CategoryMeta,
		CheckScope:     true,
		UseRawMetadata: false,
	},

	// ========================================================================
	// INFRASTRUCTURE
	// ========================================================================
	"certificate": {
		Type:           "certificate",
		Subtype:        "",
		KeyspacePrefix: "cert",
		OutputDir:      "certs",
		OutputFile:     "certs",
		Category:       CategoryInfrastructure,
		CheckScope:     false,
		UseRawMetadata: true,
	},
	"dns": {
		Type:           "dns",
		Subtype:        "",
		KeyspacePrefix: "dns",
		OutputDir:      "dns",
		OutputFile:     "dns",
		Category:       CategoryInfrastructure,
		CheckScope:     false,
		UseRawMetadata: true,
	},

	// ========================================================================
	// SECURITY FINDINGS
	// ========================================================================
	"finding.gf": {
		Type:           "finding",
		Subtype:        "gf",
		KeyspacePrefix: "finding:gf",
		OutputDir:      "findings",
		OutputFile:     "gf",
		Category:       CategorySecurity,
		CheckScope:     false,
		UseRawMetadata: false,
	},
	"finding.secret": {
		Type:           "finding",
		Subtype:        "secret",
		KeyspacePrefix: "finding:secret",
		OutputDir:      "findings",
		OutputFile:     "secrets",
		Category:       CategorySecurity,
		CheckScope:     false,
		UseRawMetadata: false,
	},

	// ========================================================================
	// SPECIAL
	// ========================================================================
	"meta": {
		Type:           "meta",
		Subtype:        "",
		KeyspacePrefix: "meta",
		OutputDir:      "",
		OutputFile:     "meta",
		Category:       CategoryMeta,
		CheckScope:     false,
		UseRawMetadata: true,
	},
	"rdap": {
		Type:           "rdap",
		Subtype:        "",
		KeyspacePrefix: "rdap",
		OutputDir:      "rdap",
		OutputFile:     "rdap",
		Category:       CategoryInfrastructure,
		CheckScope:     false,
		UseRawMetadata: true,
	},
}

// Get devuelve la definición de tipo para un Type+Subtype dado
func Get(typ, subtype string) (TypeDef, bool) {
	key := typ
	if subtype != "" {
		key = typ + "." + subtype
	}
	def, ok := Registry[key]
	return def, ok
}

// GetKeyspace devuelve el keyspace para deduplicación
func GetKeyspace(typ, subtype string, active bool) string {
	def, ok := Get(typ, subtype)
	if !ok {
		// Fallback para tipos desconocidos
		return typ + ":unknown"
	}

	suffix := ":passive"
	if active {
		suffix = ":active"
	}

	return def.KeyspacePrefix + suffix
}

// LegacyTypeToNew convierte tipos del sistema legacy a Type+Subtype
func LegacyTypeToNew(legacyType string) (typ, subtype string) {
	switch legacyType {
	case "domain":
		return "domain", ""
	case "route":
		return "route", ""
	case "js":
		return "resource", "javascript"
	case "html":
		return "resource", "html"
	case "css":
		return "resource", "css"
	case "image":
		return "resource", "image"
	case "font":
		return "resource", "font"
	case "video":
		return "resource", "video"
	case "doc":
		return "resource", "document"
	case "archive":
		return "resource", "archive"
	case "json":
		return "data", "json"
	case "xml":
		return "data", "xml"
	case "api":
		return "endpoint", "rest"
	case "graphql":
		return "endpoint", "graphql"
	case "maps":
		return "meta", "sourcemap"
	case "wasm":
		return "meta", "wasm"
	case "svg":
		return "meta", "svg"
	case "crawl":
		return "meta", "crawl"
	case "meta-route":
		return "meta", "route"
	case "certificate":
		return "certificate", ""
	case "dns":
		return "dns", ""
	case "gfFinding":
		return "finding", "gf"
	case "keyFinding":
		return "finding", "secret"
	case "meta":
		return "meta", ""
	case "rdap":
		return "rdap", ""
	default:
		// Tipo desconocido, mantener como route genérico
		return "route", ""
	}
}

// NewToLegacyType convierte Type+Subtype al tipo legacy (para compatibilidad)
func NewToLegacyType(typ, subtype string) string {
	if subtype == "" {
		switch typ {
		case "domain", "route", "certificate", "dns", "meta", "rdap":
			return typ
		default:
			return "route"
		}
	}

	key := typ + "." + subtype
	switch key {
	case "resource.javascript":
		return "js"
	case "resource.html":
		return "html"
	case "resource.css":
		return "css"
	case "resource.image":
		return "image"
	case "resource.font":
		return "font"
	case "resource.video":
		return "video"
	case "resource.document":
		return "doc"
	case "resource.archive":
		return "archive"
	case "data.json":
		return "json"
	case "data.xml":
		return "xml"
	case "endpoint.rest":
		return "api"
	case "endpoint.graphql":
		return "graphql"
	case "meta.sourcemap":
		return "maps"
	case "meta.wasm":
		return "wasm"
	case "meta.svg":
		return "svg"
	case "meta.crawl":
		return "crawl"
	case "meta.route":
		return "meta-route"
	case "finding.gf":
		return "gfFinding"
	case "finding.secret":
		return "keyFinding"
	default:
		return "route"
	}
}
