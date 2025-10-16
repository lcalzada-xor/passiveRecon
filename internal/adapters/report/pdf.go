package report

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"passive-rec/internal/core/analysis"
	"passive-rec/internal/platform/logx"
)

// GeneratePDF genera un reporte PDF a partir del HTML.
// Intenta usar herramientas del sistema (wkhtmltopdf, chromium headless).
// Si no están disponibles, retorna error informativo sin fallar.
func GeneratePDF(report *analysis.Report, reportsDir string) error {
	htmlPath := filepath.Join(reportsDir, "report.html")
	pdfPath := filepath.Join(reportsDir, "report.pdf")

	// Verificar que existe el HTML
	if _, err := os.Stat(htmlPath); err != nil {
		return fmt.Errorf("html report not found: %w", err)
	}

	// Intentar usar wkhtmltopdf primero (más común en servidores Linux)
	if err := tryWkhtmltopdf(htmlPath, pdfPath); err == nil {
		return nil
	}

	// Intentar chromium/chrome headless
	if err := tryChromium(htmlPath, pdfPath); err == nil {
		return nil
	}

	// Si ninguna herramienta está disponible, retornar error amigable
	return fmt.Errorf("PDF generation requires wkhtmltopdf or chromium/chrome. Install one of:\n" +
		"  - wkhtmltopdf: apt install wkhtmltopdf (Debian/Ubuntu) or yum install wkhtmltopdf (RHEL/CentOS)\n" +
		"  - chromium: apt install chromium-browser (Debian/Ubuntu) or yum install chromium (RHEL/CentOS)")
}

// tryWkhtmltopdf intenta generar PDF usando wkhtmltopdf.
func tryWkhtmltopdf(htmlPath, pdfPath string) error {
	// Verificar si wkhtmltopdf está disponible
	if _, err := exec.LookPath("wkhtmltopdf"); err != nil {
		return fmt.Errorf("wkhtmltopdf not found")
	}

	logx.Debugf("Generating PDF using wkhtmltopdf...")

	cmd := exec.Command("wkhtmltopdf",
		"--enable-local-file-access",
		"--no-stop-slow-scripts",
		"--javascript-delay", "1000",
		"--margin-top", "10mm",
		"--margin-bottom", "10mm",
		"--margin-left", "10mm",
		"--margin-right", "10mm",
		htmlPath,
		pdfPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("wkhtmltopdf failed: %w\nOutput: %s", err, string(output))
	}

	logx.Debugf("PDF generated successfully with wkhtmltopdf")
	return nil
}

// tryChromium intenta generar PDF usando Chromium o Chrome headless.
func tryChromium(htmlPath, pdfPath string) error {
	// Buscar chromium o chrome
	var binary string
	for _, bin := range []string{"chromium", "chromium-browser", "google-chrome", "chrome"} {
		if path, err := exec.LookPath(bin); err == nil {
			binary = path
			break
		}
	}

	if binary == "" {
		return fmt.Errorf("chromium/chrome not found")
	}

	logx.Debugf("Generating PDF using %s...", binary)

	// Convertir a file:// URL absoluta
	absPath, err := filepath.Abs(htmlPath)
	if err != nil {
		return fmt.Errorf("abs path: %w", err)
	}
	fileURL := "file://" + absPath

	cmd := exec.Command(binary,
		"--headless",
		"--disable-gpu",
		"--no-sandbox",
		"--disable-dev-shm-usage",
		"--print-to-pdf="+pdfPath,
		fileURL,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("chromium/chrome failed: %w\nOutput: %s", err, string(output))
	}

	logx.Debugf("PDF generated successfully with %s", binary)
	return nil
}
