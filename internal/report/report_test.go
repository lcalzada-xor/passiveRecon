package report

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"passive-rec/internal/certs"
	"passive-rec/internal/config"
	"passive-rec/internal/pipeline"
)

func TestGenerateCreatesHTMLReport(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
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

	writeArtifacts(t, dir, []pipeline.Artifact{
		{Type: "domain", Value: "app.example.com", Active: false, Up: true},
		{Type: "domain", Value: "api.example.com", Active: false, Up: true},
		{Type: "domain", Value: "static.test.com", Active: false, Up: true},
		{Type: "domain", Value: "deep.a.b.example.com", Active: false, Up: true},
		{Type: "route", Value: "http://app.example.com/login", Active: false, Up: true},
		{Type: "route", Value: "https://app.example.com/dashboard", Active: false, Up: true},
		{Type: "route", Value: "https://static.example.com/assets/img/logo.png", Active: false, Up: true},
		{Type: "certificate", Value: certOne, Active: false, Up: true, Tool: "crt.sh"},
		{Type: "certificate", Value: certTwo, Active: false, Up: true, Tool: "censys"},
		{Type: "certificate", Value: certThree, Active: false, Up: true, Tool: "crt.sh"},
		{Type: "meta", Value: "subfinder: ok", Active: false, Up: true},
		{Type: "meta", Value: "httpx: skipped", Active: false, Up: true},
	})

	cfg := &config.Config{Target: "example.com", OutDir: dir}
	if err := Generate(context.Background(), cfg); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	contents := readFile(t, filepath.Join(dir, "report.html"))
	checks := []string{
		"Total de artefactos procesados",
		"Dominios únicos:</strong> 4 (registrables: 2)",
		"Niveles promedio por dominio:</strong> 3.50",
		"Dominios comodín detectados:</strong> 0",
		"Top dominios registrables",
		"example.com</td><td>3",
		"test.com</td><td>1",
		"Top TLDs observados",
		"com</td><td>4",
		"Dominios potencialmente sensibles",
		"api.example.com",
		"Hosts únicos observados:</strong> 2",
		"Profundidad promedio de ruta:</strong> 1.67",
		"Uso de HTTPS:</strong> 66.7% de las rutas.",
		"Hosts con protocolos inseguros:</strong> 1",
		"Esquemas por volumen",
		"http</td><td>1",
		"https</td><td>2",
		"Hosts con tráfico no cifrado",
		"app.example.com</td><td>1",
		"Puertos observados",
		"80</td><td>1",
		"443</td><td>2",
		"Endpoints con palabras clave sensibles",
		"http://app.example.com/login",
		"Certificados únicos:</strong> 3",
		"Emisores únicos:</strong> 1",
		"Certificados vencidos:</strong> 1",
		"Dominios registrables únicos:</strong> 2",
		"Certificados por expirar (30 días):</strong> 0",
		"Próximo vencimiento:</strong> 2029-06-15",
		"Último vencimiento observado:</strong> 2032-01-01",
		"Certificados vencidos destacados",
		"portal.example.com (venció 2001-01-01)",
		"Meta",
		"subfinder: ok",
		"Top emisores",
		"Example CA</td><td>3",
		"Hallazgos clave",
		"1 host expone servicios sin HTTPS (por ejemplo app.example.com)",
		"Endpoints potencialmente sensibles encontrados (ej. http://app.example.com/login)",
		"Dominios que sugieren entornos sensibles: api.example.com, static.test.com",
		"1 certificados vencidos, incluyendo portal.example.com (venció 2001-01-01)",
	}
	for _, want := range checks {
		if !strings.Contains(contents, want) {
			t.Fatalf("expected report.html to contain %q\nreport contents:\n%s", want, contents)
		}
	}
}

func TestGenerateIncludesActiveData(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	activeDomain := "vpn-admin.example.com"
	activeRoute := "http://vpn-admin.example.com/login [200]"
	dnsJSON, err := json.Marshal(dnsRecord{
		Host:  "vpn-admin.example.com",
		Type:  "A",
		Value: "203.0.113.10",
		Raw:   "vpn-admin.example.com [A] 203.0.113.10",
		PTR:   []string{"edge.provider.example"},
	})
	if err != nil {
		t.Fatalf("marshal dns record: %v", err)
	}

	writeArtifacts(t, dir, []pipeline.Artifact{
		{Type: "domain", Value: "example.com", Active: false, Up: true},
		{Type: "route", Value: "https://example.com", Active: false, Up: true},
		{Type: "meta", Value: "passive: ok", Active: false, Up: true},
		{Type: "domain", Value: activeDomain, Active: true, Up: true},
		{Type: "route", Value: "http://vpn-admin.example.com/login", Active: true, Up: true, Metadata: map[string]any{
			"raw":    activeRoute,
			"status": 200,
		}},
		{Type: "dns", Value: string(dnsJSON), Active: true, Up: true},
		{Type: "meta", Value: "httpx(active): 1/1 ok", Active: true, Up: true},
	})

	cfg := &config.Config{Target: "example.com", OutDir: dir, Active: true}
	if err := Generate(context.Background(), cfg); err != nil {
		t.Fatalf("Generate: %v", err)
	}

	contents := readFile(t, filepath.Join(dir, "report.html"))
	checks := []string{
		"Resultados de recolección activa",
		activeDomain,
		activeRoute,
		"Registros DNS",
		"vpn-admin.example.com [A] 203.0.113.10 (PTR: edge.provider.example)",
		"httpx(active): 1/1 ok",
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
	if err := Generate(context.Background(), cfg); err != nil {
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

func TestBuildDNSStats(t *testing.T) {
	t.Parallel()

	stats := buildDNSStats([]dnsRecord{
		{Host: "api.example.com", Type: "A", Value: "1.1.1.1", Raw: "api.example.com [A] 1.1.1.1"},
		{Host: "api.example.com", Type: "AAAA", Value: "::1", Raw: "api.example.com [AAAA] ::1"},
		{Host: "cdn.example.com", Type: "CNAME", Value: "edge.example.net", Raw: "cdn.example.com [CNAME] edge.example.net"},
		{Raw: " "},
	})
	if stats.Total != 3 {
		t.Fatalf("Total = %d, want 3", stats.Total)
	}
	if stats.UniqueHosts != 2 {
		t.Fatalf("UniqueHosts = %d, want 2", stats.UniqueHosts)
	}
	if len(stats.RecordTypes) == 0 || stats.RecordTypes[0].Name != "A" {
		t.Fatalf("expected record types to include A, got %v", stats.RecordTypes)
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

func TestBuildDomainStatsGroupsMultiLevelTLDs(t *testing.T) {
	t.Parallel()

	stats := buildDomainStats([]string{
		"api.example.co.uk",
		"portal.example.co.uk",
		"example.co.uk",
		"app.example.com",
	})

	if stats.UniqueRegistrable != 2 {
		t.Fatalf("UniqueRegistrable = %d, want 2", stats.UniqueRegistrable)
	}

	counts := make(map[string]int)
	for _, item := range stats.TopRegistrable {
		counts[item.Name] = item.Count
	}

	if counts["example.co.uk"] != 3 {
		t.Fatalf("example.co.uk count = %d, want 3", counts["example.co.uk"])
	}
	if counts["example.com"] != 1 {
		t.Fatalf("example.com count = %d, want 1", counts["example.com"])
	}
}

func TestBuildCertStatsGroupsMultiLevelTLDs(t *testing.T) {
	t.Parallel()

	record, err := (certs.Record{
		CommonName: "*.portal.example.co.uk",
		DNSNames: []string{
			"portal.example.co.uk",
			"login.example.co.uk",
			"example.com",
		},
		Issuer:   "Example CA",
		NotAfter: "2030-01-01T00:00:00Z",
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}

	stats := buildCertStats([]string{record})

	if stats.UniqueRegistrable != 2 {
		t.Fatalf("UniqueRegistrable = %d, want 2", stats.UniqueRegistrable)
	}

	counts := make(map[string]int)
	for _, item := range stats.TopRegistrable {
		counts[item.Name] = item.Count
	}

	if counts["example.co.uk"] != 3 {
		t.Fatalf("example.co.uk count = %d, want 3", counts["example.co.uk"])
	}
	if counts["example.com"] != 1 {
		t.Fatalf("example.com count = %d, want 1", counts["example.com"])
	}
}

func writeArtifacts(t *testing.T, dir string, artifacts []pipeline.Artifact) {
	t.Helper()
	var builder strings.Builder
	for _, artifact := range artifacts {
		data, err := json.Marshal(artifact)
		if err != nil {
			t.Fatalf("marshal artifact: %v", err)
		}
		builder.Write(data)
		builder.WriteByte('\n')
	}
	writeFixture(t, filepath.Join(dir, "artifacts.jsonl"), builder.String())
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
