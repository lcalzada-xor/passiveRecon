package report

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"passive-rec/internal/certs"
	"passive-rec/internal/config"
)

func TestGenerateCreatesHTMLReport(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFixture(t, filepath.Join(dir, "domains", "domains.passive"), strings.Join([]string{
		"app.example.com",
		"api.example.com",
		"static.test.com",
		"deep.a.b.example.com",
	}, "\n"))
	writeFixture(t, filepath.Join(dir, "routes", "routes.passive"), strings.Join([]string{
		"http://app.example.com/login",
		"https://app.example.com/dashboard",
		"https://static.example.com/assets/img/logo.png",
	}, "\n"))
	certOne, err := (certs.Record{
		Source:     "crt.sh",
		CommonName: "alt1.example.com",
		DNSNames:   []string{"alt1.example.com", "alt2.example.com"},
		Issuer:     "Example CA",
		NotAfter:   "2032-01-01T00:00:00Z",
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal certOne: %v", err)
	}
	certTwo, err := (certs.Record{
		Source:     "censys",
		CommonName: "service.test.com",
		DNSNames:   []string{"service.test.com"},
		Issuer:     "Example CA",
		NotAfter:   "2029-06-15T00:00:00Z",
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal certTwo: %v", err)
	}
	certThree, err := (certs.Record{
		Source:     "crt.sh",
		CommonName: "portal.example.com",
		Issuer:     "Example CA",
		NotAfter:   "2001-01-01T00:00:00Z",
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal certThree: %v", err)
	}
	writeFixture(t, filepath.Join(dir, "certs", "certs.passive"), strings.Join([]string{certOne, certTwo, certThree}, "\n"))
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
		"Emisores únicos:</strong> 1",
		"Certificados vencidos:</strong> 1",
		"Dominios registrables únicos:</strong> 2",
		"Certificados por expirar (30 días):</strong> 0",
		"Próximo vencimiento:</strong> 2029-06-15",
		"Último vencimiento observado:</strong> 2032-01-01",
		"Meta",
		"subfinder: ok",
		"Top emisores",
		"Example CA</td><td>3",
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

func TestBuildDomainStatsSkipsEmpty(t *testing.T) {
	t.Parallel()

	stats := buildDomainStats([]string{"example.com", " ", "", "sub.example.com"})
	if stats.Total != 2 {
		t.Fatalf("Total = %d, want 2", stats.Total)
	}
	if stats.Unique != 2 {
		t.Fatalf("Unique = %d, want 2", stats.Unique)
	}
}

func TestBuildCertStatsSkipsEmpty(t *testing.T) {
	t.Parallel()

	valid, err := (certs.Record{CommonName: "alt.example.com", DNSNames: []string{"sub.example.com"}}).Marshal()
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	stats := buildCertStats([]string{valid, "   ", ""})
	if stats.Total != 1 {
		t.Fatalf("Total = %d, want 1", stats.Total)
	}
	if stats.Unique != 1 {
		t.Fatalf("Unique = %d, want 1", stats.Unique)
	}
	if stats.UniqueRegistrable != 1 {
		t.Fatalf("UniqueRegistrable = %d, want 1", stats.UniqueRegistrable)
	}
	if stats.SoonThresholdDays != 30 {
		t.Fatalf("SoonThresholdDays = %d, want 30", stats.SoonThresholdDays)
	}
}

func TestBuildCertStatsExpiryCounters(t *testing.T) {
	t.Parallel()

	expired, err := (certs.Record{Issuer: "Example CA", NotAfter: "2020-01-01T00:00:00Z"}).Marshal()
	if err != nil {
		t.Fatalf("marshal expired: %v", err)
	}
	soon, err := (certs.Record{Issuer: "Example CA", NotAfter: "2024-01-15T00:00:00Z"}).Marshal()
	if err != nil {
		t.Fatalf("marshal soon: %v", err)
	}
	future, err := (certs.Record{Issuer: "Other CA", NotAfter: "2024-03-01T00:00:00Z"}).Marshal()
	if err != nil {
		t.Fatalf("marshal future: %v", err)
	}
	now := time.Date(2024, time.January, 1, 0, 0, 0, 0, time.UTC)
	stats := buildCertStatsAt([]string{expired, soon, future}, now)
	if stats.Expired != 1 {
		t.Fatalf("Expired = %d, want 1", stats.Expired)
	}
	if stats.ExpiringSoon != 1 {
		t.Fatalf("ExpiringSoon = %d, want 1", stats.ExpiringSoon)
	}
	if stats.NextExpiration != "2024-01-15" {
		t.Fatalf("NextExpiration = %q, want 2024-01-15", stats.NextExpiration)
	}
	if stats.LatestExpiration != "2024-03-01" {
		t.Fatalf("LatestExpiration = %q, want 2024-03-01", stats.LatestExpiration)
	}
	if stats.UniqueIssuers != 2 {
		t.Fatalf("UniqueIssuers = %d, want 2", stats.UniqueIssuers)
	}
	if len(stats.TopIssuers) == 0 {
		t.Fatalf("expected TopIssuers to be populated")
	}
}

func TestBuildRouteStatsIgnoresInvalidLines(t *testing.T) {
	t.Parallel()

	routes := []string{
		"http://app.example.com/login",
		"   ",
		"http://[::1", // invalid URL, should be skipped
		"https://secure.example.com/dashboard 200 OK",
	}
	stats := buildRouteStats(routes)
	if stats.Total != 2 {
		t.Fatalf("Total = %d, want 2", stats.Total)
	}
	if got := int(stats.SecurePercentage + 0.5); got != 50 {
		t.Fatalf("SecurePercentage ≈ %.2f, want 50", stats.SecurePercentage)
	}
	if stats.UniqueHosts != 2 {
		t.Fatalf("UniqueHosts = %d, want 2", stats.UniqueHosts)
	}
}

func writeFixture(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("MkdirAll(%q): %v", filepath.Dir(path), err)
	}
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
