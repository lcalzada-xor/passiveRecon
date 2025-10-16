package analysis

import (
	"time"

	"passive-rec/internal/adapters/artifacts"
)

// Report representa un reporte completo de análisis de reconocimiento pasivo.
type Report struct {
	// Metadata del scan
	Target       string    `json:"target"`
	ScanDate     time.Time `json:"scan_date"`
	Duration     string    `json:"duration,omitempty"`
	ReportDate   time.Time `json:"report_date"`

	// Estadísticas generales
	Summary      Summary           `json:"summary"`

	// Análisis detallados
	TechStack    *TechStack        `json:"tech_stack,omitempty"`
	AttackSurface *AttackSurface   `json:"attack_surface,omitempty"`
	Infrastructure *Infrastructure `json:"infrastructure,omitempty"`
	Assets       *AssetInventory   `json:"assets,omitempty"`
	Security     *SecurityFindings `json:"security,omitempty"`

	// Insights y recomendaciones
	Insights     []Insight         `json:"insights,omitempty"`
	Timeline     []TimelineEvent   `json:"timeline,omitempty"`
}

// Summary contiene estadísticas generales del scan.
type Summary struct {
	TotalArtifacts    int            `json:"total_artifacts"`
	ActiveArtifacts   int            `json:"active_artifacts"`
	PassiveArtifacts  int            `json:"passive_artifacts"`
	ArtifactsByType   map[string]int `json:"artifacts_by_type"`
	ArtifactsByStatus map[string]int `json:"artifacts_by_status"`
	ToolsUsed         []string       `json:"tools_used"`
	TopTools          []ToolStat     `json:"top_tools,omitempty"`
}

// ToolStat representa estadísticas de una herramienta.
type ToolStat struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// TechStack representa el stack tecnológico detectado.
type TechStack struct {
	// Frontend
	JavaScript  []Technology `json:"javascript,omitempty"`
	CSS         []Technology `json:"css,omitempty"`
	Frameworks  []Technology `json:"frameworks,omitempty"`
	Libraries   []Technology `json:"libraries,omitempty"`

	// Backend (inferido)
	Languages   []Technology `json:"languages,omitempty"`
	Servers     []Technology `json:"servers,omitempty"`
	CMS         []Technology `json:"cms,omitempty"`

	// Infraestructura
	CDN         []Technology `json:"cdn,omitempty"`
	Analytics   []Technology `json:"analytics,omitempty"`

	// Tecnologías obsoletas (riesgo)
	Deprecated  []Technology `json:"deprecated,omitempty"`

	// Confianza del análisis
	Confidence  string       `json:"confidence"` // high, medium, low
}

// Technology representa una tecnología detectada.
type Technology struct {
	Name       string   `json:"name"`
	Version    string   `json:"version,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
	Confidence string   `json:"confidence"` // high, medium, low
	Deprecated bool     `json:"deprecated,omitempty"`
	Risk       string   `json:"risk,omitempty"` // critical, high, medium, low, none
}

// AttackSurface representa el análisis de superficie de ataque.
type AttackSurface struct {
	Score          float64           `json:"score"`           // 0-100
	Level          string            `json:"level"`           // minimal, low, medium, high, critical
	TotalEndpoints int               `json:"total_endpoints"`
	ActiveEndpoints int              `json:"active_endpoints"`

	// Categorización de endpoints
	SensitiveEndpoints []SensitiveEndpoint `json:"sensitive_endpoints,omitempty"`
	APIEndpoints       []string            `json:"api_endpoints,omitempty"`
	AdminEndpoints     []string            `json:"admin_endpoints,omitempty"`
	AuthEndpoints      []string            `json:"auth_endpoints,omitempty"`

	// Exposiciones
	ExposedFiles       []ExposedFile       `json:"exposed_files,omitempty"`
	ExposedTech        []string            `json:"exposed_tech,omitempty"`

	// Factores de riesgo
	RiskFactors        []RiskFactor        `json:"risk_factors,omitempty"`
}

// SensitiveEndpoint representa un endpoint potencialmente sensible.
type SensitiveEndpoint struct {
	URL        string   `json:"url"`
	Category   string   `json:"category"` // admin, auth, api, config, backup, etc.
	Risk       string   `json:"risk"`     // critical, high, medium, low
	Reason     string   `json:"reason"`
	Active     bool     `json:"active"`
	StatusCode int      `json:"status_code,omitempty"`
}

// ExposedFile representa un archivo expuesto que podría ser sensible.
type ExposedFile struct {
	Path       string `json:"path"`
	Type       string `json:"type"` // robots.txt, .git, .env, backup, etc.
	Risk       string `json:"risk"` // critical, high, medium, low
	Active     bool   `json:"active"`
	StatusCode int    `json:"status_code,omitempty"`
}

// RiskFactor representa un factor de riesgo detectado.
type RiskFactor struct {
	Category    string   `json:"category"`    // tech, exposure, config, etc.
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"` // critical, high, medium, low
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// Infrastructure representa información de infraestructura.
type Infrastructure struct {
	// DNS
	Nameservers  []string          `json:"nameservers,omitempty"`
	DNSRecords   map[string][]string `json:"dns_records,omitempty"` // A, AAAA, MX, NS, TXT, etc.

	// IPs
	IPs          []IPInfo          `json:"ips,omitempty"`

	// RDAP
	Registrar    string            `json:"registrar,omitempty"`
	Registered   *time.Time        `json:"registered,omitempty"`
	Expires      *time.Time        `json:"expires,omitempty"`
	LastChanged  *time.Time        `json:"last_changed,omitempty"`
	Status       []string          `json:"status,omitempty"`

	// Hosting
	HostingProvider string         `json:"hosting_provider,omitempty"`
	EmailProvider   string         `json:"email_provider,omitempty"`
}

// IPInfo representa información de una IP.
type IPInfo struct {
	Address  string `json:"address"`
	Type     string `json:"type"` // IPv4, IPv6
	Resolved bool   `json:"resolved"`
}

// AssetInventory representa el inventario de assets descubiertos.
type AssetInventory struct {
	// Dominios
	TotalDomains  int      `json:"total_domains"`
	ActiveDomains int      `json:"active_domains"`
	Domains       []Domain `json:"domains,omitempty"`

	// Subdominios
	TotalSubdomains  int      `json:"total_subdomains"`
	ActiveSubdomains int      `json:"active_subdomains"`

	// Recursos web
	HTMLPages     int      `json:"html_pages"`
	JavaScripts   int      `json:"javascripts"`
	Stylesheets   int      `json:"stylesheets"`
	Images        int      `json:"images"`
	Documents     int      `json:"documents"`
	OtherResources int     `json:"other_resources"`

	// APIs
	RestAPIs      []string `json:"rest_apis,omitempty"`
	GraphQLAPIs   []string `json:"graphql_apis,omitempty"`

	// Certificados
	Certificates  int      `json:"certificates"`
}

// Domain representa un dominio descubierto.
type Domain struct {
	Name      string `json:"name"`
	Active    bool   `json:"active"`
	Verified  bool   `json:"verified"`
	Source    string `json:"source,omitempty"`
}

// SecurityFindings representa hallazgos de seguridad.
type SecurityFindings struct {
	TotalFindings    int               `json:"total_findings"`
	Critical         int               `json:"critical"`
	High             int               `json:"high"`
	Medium           int               `json:"medium"`
	Low              int               `json:"low"`

	// Hallazgos por categoría
	Findings         []Finding         `json:"findings,omitempty"`

	// Patrones detectados por GoLinkFinder
	GFFindings       []GFFinding       `json:"gf_findings,omitempty"`
}

// Finding representa un hallazgo de seguridad.
type Finding struct {
	ID          string   `json:"id"`
	Category    string   `json:"category"` // exposure, vulnerability, misconfiguration, etc.
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"` // critical, high, medium, low
	Evidence    []string `json:"evidence,omitempty"`
	Location    string   `json:"location,omitempty"`
	CWE         string   `json:"cwe,omitempty"`
	CVSS        float64  `json:"cvss,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// GFFinding representa un hallazgo de GoLinkFinder.
type GFFinding struct {
	Resource string   `json:"resource"`
	Evidence string   `json:"evidence"`
	Line     int      `json:"line,omitempty"`
	Context  string   `json:"context,omitempty"`
	Rules    []string `json:"rules,omitempty"`
	Category string   `json:"category"` // secret, api-key, token, path, etc.
	Severity string   `json:"severity"` // critical, high, medium, low
}

// Insight representa un insight o recomendación.
type Insight struct {
	Type        string   `json:"type"`        // info, warning, critical, recommendation
	Category    string   `json:"category"`    // technology, security, infrastructure, business
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Priority    int      `json:"priority"`    // 1-5 (1=highest)
	Evidence    []string `json:"evidence,omitempty"`
	Action      string   `json:"action,omitempty"` // Acción recomendada
}

// TimelineEvent representa un evento en la línea de tiempo.
type TimelineEvent struct {
	Timestamp   time.Time `json:"timestamp"`
	Type        string    `json:"type"` // discovery, change, exposure, etc.
	Description string    `json:"description"`
	Source      string    `json:"source,omitempty"`
	Severity    string    `json:"severity,omitempty"`
}

// AnalysisOptions configura las opciones del análisis.
type AnalysisOptions struct {
	// Qué análisis ejecutar
	EnableTechDetection      bool
	EnableAttackSurface      bool
	EnableInfrastructure     bool
	EnableAssetInventory     bool
	EnableSecurityFindings   bool
	EnableInsights           bool
	EnableTimeline           bool

	// Configuraciones
	MinConfidence            string // low, medium, high
	IncludePassiveOnly       bool
	IncludeActiveOnly        bool
	MaxDepth                 int
}

// DefaultAnalysisOptions retorna las opciones por defecto.
func DefaultAnalysisOptions() AnalysisOptions {
	return AnalysisOptions{
		EnableTechDetection:    true,
		EnableAttackSurface:    true,
		EnableInfrastructure:   true,
		EnableAssetInventory:   true,
		EnableSecurityFindings: true,
		EnableInsights:         true,
		EnableTimeline:         false, // Costoso computacionalmente
		MinConfidence:          "low",
		IncludePassiveOnly:     false,
		IncludeActiveOnly:      false,
		MaxDepth:               -1, // Sin límite
	}
}

// ArtifactStats representa estadísticas básicas de artefactos.
type ArtifactStats struct {
	Total        int
	Active       int
	Passive      int
	ByType       map[string]int
	BySubtype    map[string]int
	ByStatus     map[string]int
	ByTool       map[string]int
	UniqueTools  []string
}

// ComputeStats calcula estadísticas de un conjunto de artefactos.
func ComputeStats(artifacts []artifacts.Artifact) ArtifactStats {
	stats := ArtifactStats{
		ByType:    make(map[string]int),
		BySubtype: make(map[string]int),
		ByStatus:  make(map[string]int),
		ByTool:    make(map[string]int),
	}

	toolSet := make(map[string]struct{})

	for _, art := range artifacts {
		stats.Total++

		if art.Active {
			stats.Active++
		} else {
			stats.Passive++
		}

		stats.ByType[art.Type]++

		if art.Subtype != "" {
			stats.BySubtype[art.Subtype]++
		}

		// Determinar estado
		status := "up"
		if art.Active && art.Up {
			status = "active_up"
		} else if art.Active && !art.Up {
			status = "active_down"
		} else if !art.Active && !art.Up {
			status = "down"
		}
		stats.ByStatus[status]++

		// Contar herramientas
		if art.Tool != "" {
			stats.ByTool[art.Tool]++
			toolSet[art.Tool] = struct{}{}
		}
		for _, tool := range art.Tools {
			if tool != "" {
				stats.ByTool[tool]++
				toolSet[tool] = struct{}{}
			}
		}
	}

	// Construir lista de herramientas únicas
	for tool := range toolSet {
		stats.UniqueTools = append(stats.UniqueTools, tool)
	}

	return stats
}
