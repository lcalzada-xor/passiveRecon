package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/core/analysis"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <directory>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s rezasa_com/\n", os.Args[0])
		os.Exit(1)
	}

	dir := os.Args[1]
	artifactsPath := filepath.Join(dir, "artifacts.jsonl")

	// Leer artifacts
	fmt.Printf("Reading artifacts from: %s\n", artifactsPath)

	file, err := os.Open(artifactsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	reader, err := artifacts.NewReaderV2(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating reader: %v\n", err)
		os.Exit(1)
	}

	// Obtener header (si está disponible)
	var header artifacts.HeaderV2

	// Leer todos los artifacts
	var arts []artifacts.Artifact
	for {
		art, err := reader.ReadArtifact()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			fmt.Fprintf(os.Stderr, "Error reading artifact: %v\n", err)
			break
		}
		arts = append(arts, art)
	}

	// Intentar obtener información básica del primer artifact
	if len(arts) > 0 {
		// Podemos inferir el target del nombre del directorio
		header.Target = filepath.Base(dir)
	}

	fmt.Printf("Loaded %d artifacts\n\n", len(arts))

	// Crear analizador con opciones por defecto
	opts := analysis.DefaultAnalysisOptions()
	analyzer := analysis.NewAnalyzer(arts, header, opts)

	// Ejecutar análisis
	fmt.Println("Running analysis...")
	report, err := analyzer.Analyze()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error analyzing: %v\n", err)
		os.Exit(1)
	}

	// Generar reporte Markdown
	fmt.Println("Generating Markdown report...")
	markdownReport := analysis.GenerateMarkdownReport(report)

	// Guardar reporte
	reportPath := filepath.Join(dir, "REPORT.md")
	if err := os.WriteFile(reportPath, []byte(markdownReport), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing report: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("✓ Markdown report saved to: %s\n", reportPath)

	// También guardar como JSON
	jsonReportPath := filepath.Join(dir, "report.json")
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
	} else {
		if err := os.WriteFile(jsonReportPath, jsonData, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON report: %v\n", err)
		} else {
			fmt.Printf("✓ JSON report saved to: %s\n", jsonReportPath)
		}
	}

	// Imprimir resumen
	fmt.Println("\n=== SUMMARY ===")
	fmt.Printf("Total Artifacts: %d\n", report.Summary.TotalArtifacts)
	fmt.Printf("Active: %d, Passive: %d\n", report.Summary.ActiveArtifacts, report.Summary.PassiveArtifacts)

	if report.AttackSurface != nil {
		fmt.Printf("\nAttack Surface Score: %.1f/100 (%s)\n", report.AttackSurface.Score, report.AttackSurface.Level)
		fmt.Printf("Active Endpoints: %d\n", report.AttackSurface.ActiveEndpoints)
		fmt.Printf("Sensitive Endpoints: %d\n", len(report.AttackSurface.SensitiveEndpoints))
	}

	if report.TechStack != nil {
		fmt.Printf("\nTechnology Stack:\n")
		fmt.Printf("- JavaScript Libraries: %d\n", len(report.TechStack.JavaScript))
		fmt.Printf("- Frameworks: %d\n", len(report.TechStack.Frameworks))
		fmt.Printf("- CSS Frameworks: %d\n", len(report.TechStack.CSS))
		fmt.Printf("- Deprecated Technologies: %d\n", len(report.TechStack.Deprecated))
	}

	if report.Security != nil {
		fmt.Printf("\nSecurity Findings: %d total\n", report.Security.TotalFindings)
		fmt.Printf("- Critical: %d\n", report.Security.Critical)
		fmt.Printf("- High: %d\n", report.Security.High)
		fmt.Printf("- Medium: %d\n", report.Security.Medium)
		fmt.Printf("- Low: %d\n", report.Security.Low)
	}

	fmt.Printf("\nInsights: %d\n", len(report.Insights))

	// Mostrar insights críticos
	criticalInsights := 0
	for _, insight := range report.Insights {
		if insight.Type == "critical" {
			criticalInsights++
			fmt.Printf("\n🚨 CRITICAL: %s\n", insight.Title)
			fmt.Printf("   %s\n", insight.Description)
		}
	}

	if criticalInsights == 0 {
		fmt.Println("\n✓ No critical issues detected")
	}

	fmt.Println("\nDone!")
}
