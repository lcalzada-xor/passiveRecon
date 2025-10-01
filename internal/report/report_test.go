package report

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"passive-rec/internal/config"
)

func TestGenerateCreatesHTMLReport(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "domains.passive"), strings.Join([]string{
		"app.example.com",
		"api.example.com",
		"static.test.com",
		"deep.a.b.example.com",
	}, "\n"))
	writeFixture(t, filepath.Join(dir, "routes.passive"), strings.Join([]string{
		"http://app.example.com/login",
		"https://app.example.com/dashboard",
		"https://static.example.com/assets/img/logo.png",
	}, "\n"))
	writeFixture(t, filepath.Join(dir, "certs.passive"), strings.Join([]string{
		"alt1.example.com",
		"alt2.example.com",
		"service.test.com",
	}, "\n"))
	writeFixture(t, filepath.Join(dir, "meta.passive"), strings.Join([]string{
		"subfinder: ok",
		"httpx: skipped",
	}, "\n"))

	cfg := &config.Config{Target: "example.com", OutDir: dir}
	if err := Generate(context.Background(), cfg, DefaultSinkFiles(dir)); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	contents := readFile(t, filepath.Join(dir, "report.html"))
	checks := []string{
		"Total de artefactos procesados",
		"Dominios únicos:</strong> 4 (registrables: 2)",
		"Niveles promedio por dominio:</strong> 3.50",
		"Top dominios registrables",
		"example.com</td><td>3",
		"test.com</td><td>1",
		"Hosts únicos observados:</strong> 2",
		"Profundidad promedio de ruta:</strong> 1.67",
		"Uso de HTTPS:</strong> 66.7% de las rutas.",
		"Esquemas por volumen",
		"http</td><td>1",
		"https</td><td>2",
		"Certificados únicos:</strong> 3",
		"Dominios registrables únicos:</strong> 2",
		"Meta",
		"subfinder: ok",
	}
	for _, want := range checks {
		if !strings.Contains(contents, want) {
			t.Fatalf("expected report.html to contain %q\nreport contents:\n%s", want, contents)
		}
	}
}

func TestGenerateHandlesMissingFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	cfg := &config.Config{Target: "example.com", OutDir: dir}
	files := SinkFiles{Meta: filepath.Join(dir, "meta.passive")}
	if err := Generate(context.Background(), cfg, files); err != nil {
		t.Fatalf("Generate with missing files: %v", err)
	}

	contents := readFile(t, filepath.Join(dir, "report.html"))
	if !strings.Contains(contents, "Sin entradas meta.") {
		t.Fatalf("expected empty meta message, got:\n%s", contents)
	}
}

func writeFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	return string(data)
}
