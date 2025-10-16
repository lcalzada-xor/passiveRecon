package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/core/analysis"
	"passive-rec/internal/platform/config"
	"passive-rec/internal/platform/logx"
)

// GenerateV2 genera reportes completos (Markdown, HTML, PDF) usando el nuevo motor de análisis.
func GenerateV2(ctx context.Context, cfg *config.Config) error {
	if cfg == nil {
		return errors.New("report: missing config")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Verificar que exista artifacts.jsonl
	exists, err := artifacts.Exists(cfg.OutDir)
	if err != nil {
		return fmt.Errorf("report: artifacts manifest: %w", err)
	}
	if !exists {
		return errors.New("report: artifacts.jsonl not found")
	}

	// Leer artifacts
	logx.Debug("Leyendo artifacts", logx.Fields{"directory": cfg.OutDir})
	manifestPath := filepath.Join(cfg.OutDir, "artifacts.jsonl")
	file, err := os.Open(manifestPath)
	if err != nil {
		return fmt.Errorf("report: open artifacts: %w", err)
	}
	defer file.Close()

	reader, err := artifacts.NewReaderV2(file)
	if err != nil {
		return fmt.Errorf("report: create reader: %w", err)
	}

	var arts []artifacts.Artifact
	var header artifacts.HeaderV2
	for {
		art, err := reader.ReadArtifact()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return fmt.Errorf("report: read artifact: %w", err)
		}
		arts = append(arts, art)
	}

	logx.Debug("Artifacts cargados", logx.Fields{"count": len(arts)})

	// Inferir header si no está disponible
	if header.Target == "" {
		header.Target = cfg.Target
	}
	if header.Created == 0 {
		header.Created = time.Now().Unix()
	}

	// Crear analizador con opciones por defecto
	opts := analysis.DefaultAnalysisOptions()
	opts.EnableTimeline = true // Habilitar timeline para reportes completos

	analyzer := analysis.NewAnalyzer(arts, header, opts)

	// Ejecutar análisis
	logx.Debug("Ejecutando análisis", logx.Fields{"type": "inteligente"})
	report, err := analyzer.Analyze()
	if err != nil {
		return fmt.Errorf("report: analyze: %w", err)
	}

	// Crear carpeta /reports
	reportsDir := filepath.Join(cfg.OutDir, "reports")
	if err := os.MkdirAll(reportsDir, 0755); err != nil {
		return fmt.Errorf("report: create reports dir: %w", err)
	}

	// Generar Markdown
	logx.Debug("Generando reporte", logx.Fields{"format": "markdown"})
	mdReport := analysis.GenerateMarkdownReport(report)
	mdPath := filepath.Join(reportsDir, "REPORT.md")
	if err := os.WriteFile(mdPath, []byte(mdReport), 0644); err != nil {
		return fmt.Errorf("report: write markdown: %w", err)
	}
	logx.Debug("Reporte guardado", logx.Fields{"format": "markdown", "path": mdPath})

	// Generar JSON
	logx.Debug("Generando reporte", logx.Fields{"format": "json"})
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("report: marshal json: %w", err)
	}
	jsonPath := filepath.Join(reportsDir, "report.json")
	if err := os.WriteFile(jsonPath, jsonData, 0644); err != nil {
		return fmt.Errorf("report: write json: %w", err)
	}
	logx.Debug("Reporte guardado", logx.Fields{"format": "json", "path": jsonPath})

	// Generar HTML
	logx.Debug("Generando reporte", logx.Fields{"format": "html"})
	if err := GenerateHTML(report, reportsDir); err != nil {
		logx.Warn("Fallo generar HTML", logx.Fields{"error": err.Error()})
	} else {
		logx.Debug("Reporte guardado", logx.Fields{"format": "html", "path": reportsDir + "/report.html"})
	}

	// Generar PDF
	logx.Debug("Generando reporte", logx.Fields{"format": "pdf"})
	if err := GeneratePDF(report, reportsDir); err != nil {
		logx.Warn("Fallo generar PDF", logx.Fields{"error": err.Error()})
	} else {
		logx.Debug("Reporte guardado", logx.Fields{"format": "pdf", "path": reportsDir + "/report.pdf"})
	}

	return nil
}
