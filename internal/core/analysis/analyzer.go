package analysis

import (
	"fmt"
	"time"

	"passive-rec/internal/adapters/artifacts"
)

// Analyzer es el motor de análisis principal que coordina todos los análisis.
type Analyzer struct {
	artifacts []artifacts.Artifact
	header    artifacts.HeaderV2
	options   AnalysisOptions
	stats     ArtifactStats
}

// NewAnalyzer crea una nueva instancia del analizador.
func NewAnalyzer(arts []artifacts.Artifact, header artifacts.HeaderV2, opts AnalysisOptions) *Analyzer {
	return &Analyzer{
		artifacts: arts,
		header:    header,
		options:   opts,
		stats:     ComputeStats(arts),
	}
}

// NewAnalyzerFromArtifacts crea un analizador con opciones por defecto.
func NewAnalyzerFromArtifacts(arts []artifacts.Artifact) *Analyzer {
	return NewAnalyzer(arts, artifacts.HeaderV2{}, DefaultAnalysisOptions())
}

// Analyze ejecuta todos los análisis configurados y genera el reporte completo.
func (a *Analyzer) Analyze() (*Report, error) {
	report := &Report{
		Target:     a.header.Target,
		ScanDate:   time.Unix(a.header.Created, 0),
		ReportDate: time.Now().UTC(),
		Summary:    a.buildSummary(),
	}

	// Análisis de tecnología
	if a.options.EnableTechDetection {
		report.TechStack = a.detectTechnology()
	}

	// Análisis de superficie de ataque
	if a.options.EnableAttackSurface {
		report.AttackSurface = a.analyzeAttackSurface()
	}

	// Análisis de infraestructura
	if a.options.EnableInfrastructure {
		report.Infrastructure = a.analyzeInfrastructure()
	}

	// Inventario de assets
	if a.options.EnableAssetInventory {
		report.Assets = a.buildAssetInventory()
	}

	// Hallazgos de seguridad
	if a.options.EnableSecurityFindings {
		report.Security = a.analyzeSecurityFindings()
	}

	// Generar insights
	if a.options.EnableInsights {
		report.Insights = a.generateInsights(report)
	}

	// Timeline
	if a.options.EnableTimeline {
		report.Timeline = a.buildTimeline()
	}

	return report, nil
}

// buildSummary construye el resumen ejecutivo.
func (a *Analyzer) buildSummary() Summary {
	summary := Summary{
		TotalArtifacts:    a.stats.Total,
		ActiveArtifacts:   a.stats.Active,
		PassiveArtifacts:  a.stats.Passive,
		ArtifactsByType:   a.stats.ByType,
		ArtifactsByStatus: a.stats.ByStatus,
		ToolsUsed:         a.stats.UniqueTools,
	}

	// Top tools
	type toolCount struct {
		name  string
		count int
	}
	var toolCounts []toolCount
	for tool, count := range a.stats.ByTool {
		toolCounts = append(toolCounts, toolCount{name: tool, count: count})
	}

	// Ordenar por count descendente (bubble sort simple)
	for i := 0; i < len(toolCounts); i++ {
		for j := i + 1; j < len(toolCounts); j++ {
			if toolCounts[j].count > toolCounts[i].count {
				toolCounts[i], toolCounts[j] = toolCounts[j], toolCounts[i]
			}
		}
	}

	// Top 5
	limit := 5
	if len(toolCounts) < limit {
		limit = len(toolCounts)
	}
	for i := 0; i < limit; i++ {
		summary.TopTools = append(summary.TopTools, ToolStat{
			Name:  toolCounts[i].name,
			Count: toolCounts[i].count,
		})
	}

	return summary
}

// GetStats retorna las estadísticas computadas.
func (a *Analyzer) GetStats() ArtifactStats {
	return a.stats
}

// FilterArtifacts filtra artefactos por tipo.
func (a *Analyzer) FilterArtifacts(typ string) []artifacts.Artifact {
	var filtered []artifacts.Artifact
	for _, art := range a.artifacts {
		if art.Type == typ {
			filtered = append(filtered, art)
		}
	}
	return filtered
}

// FilterBySubtype filtra artefactos por subtipo.
func (a *Analyzer) FilterBySubtype(typ, subtype string) []artifacts.Artifact {
	var filtered []artifacts.Artifact
	for _, art := range a.artifacts {
		if art.Type == typ && art.Subtype == subtype {
			filtered = append(filtered, art)
		}
	}
	return filtered
}

// FilterActive retorna solo artefactos activos.
func (a *Analyzer) FilterActive() []artifacts.Artifact {
	var filtered []artifacts.Artifact
	for _, art := range a.artifacts {
		if art.Active {
			filtered = append(filtered, art)
		}
	}
	return filtered
}

// FilterPassive retorna solo artefactos pasivos.
func (a *Analyzer) FilterPassive() []artifacts.Artifact {
	var filtered []artifacts.Artifact
	for _, art := range a.artifacts {
		if !art.Active {
			filtered = append(filtered, art)
		}
	}
	return filtered
}

// GetArtifactValue retorna el valor de un artefacto como string.
func GetArtifactValue(art artifacts.Artifact) string {
	return art.Value
}

// GetArtifactMetadata obtiene un valor de metadata.
func GetArtifactMetadata(art artifacts.Artifact, key string) (interface{}, bool) {
	if art.Metadata == nil {
		return nil, false
	}
	val, ok := art.Metadata[key]
	return val, ok
}

// GetArtifactMetadataString obtiene un valor string de metadata.
func GetArtifactMetadataString(art artifacts.Artifact, key string) string {
	val, ok := GetArtifactMetadata(art, key)
	if !ok {
		return ""
	}
	if str, ok := val.(string); ok {
		return str
	}
	return fmt.Sprintf("%v", val)
}
