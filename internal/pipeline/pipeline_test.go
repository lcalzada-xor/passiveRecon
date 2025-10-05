package pipeline

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"passive-rec/internal/certs"
	"passive-rec/internal/netutil"
)

func newTestSink(t *testing.T, active bool) (*Sink, string) {
	t.Helper()
	dir := t.TempDir()
	sink, err := NewSink(dir, active, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	return sink, dir
}

func TestSinkClassification(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)

	certOne, err := (certs.Record{
		Source:       "test",
		CommonName:   "direct-cert.example.com",
		DNSNames:     []string{"alt1.example.com", "alt2.example.com"},
		Issuer:       "Example CA",
		NotBefore:    "2024-01-01T00:00:00Z",
		NotAfter:     "2025-01-01T00:00:00Z",
		SerialNumber: "01",
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal certOne: %v", err)
	}
	certTwo, err := (certs.Record{
		Source:       "test",
		CommonName:   "alt3.example.com",
		DNSNames:     []string{"alt3.example.com"},
		Issuer:       "Example CA",
		NotBefore:    "2023-06-01T00:00:00Z",
		NotAfter:     "2024-06-01T00:00:00Z",
		SerialNumber: "02",
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal certTwo: %v", err)
	}

	inputs := []string{
		"  example.com  ",
		"https://app.example.com/login",
		"http://example.com/about",
		"meta: run started",
		"sub.example.com/path",
		"www.example.com",
		"[2001:db8::1]:8443",
		"2001:db8::1",
		"meta: run started",
		"cert: " + certOne,
		"cert: " + certTwo,
		"   ",
	}

	for _, line := range inputs {
		sink.In() <- line
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	domains := readLines(t, filepath.Join(dir, "domains", "domains.passive"))
	wantDomains := []string{
		"example.com",
		"alt1.example.com",
		"alt2.example.com",
		"direct-cert.example.com",
		"alt3.example.com",
	}
	if diff := cmp.Diff(wantDomains, domains); diff != "" {
		t.Fatalf("unexpected domains (-want +got):\n%s", diff)
	}

	if activeDomains := readLines(t, filepath.Join(dir, "domains", "domains.active")); activeDomains != nil {
		t.Fatalf("expected empty domains.active, got %v", activeDomains)
	}

	routes := readLines(t, filepath.Join(dir, "routes", "routes.passive"))
	wantRoutes := []string{
		"https://app.example.com/login",
		"http://example.com/about",
		"http://sub.example.com/path",
	}
	if diff := cmp.Diff(wantRoutes, routes); diff != "" {
		t.Fatalf("unexpected routes (-want +got):\n%s", diff)
	}

	if activeRoutes := readLines(t, filepath.Join(dir, "routes", "routes.active")); activeRoutes != nil {
		t.Fatalf("expected empty routes.active, got %v", activeRoutes)
	}

	certLines := readLines(t, filepath.Join(dir, "certs", "certs.passive"))
	if len(certLines) != 2 {
		t.Fatalf("expected two certificate records, got %d", len(certLines))
	}
	var gotCerts []certs.Record
	for _, line := range certLines {
		record, err := certs.Parse(line)
		if err != nil {
			t.Fatalf("parse certificate line: %v", err)
		}
		gotCerts = append(gotCerts, record)
	}

	wantRecords := []certs.Record{{
		Source:       "test",
		CommonName:   "alt3.example.com",
		DNSNames:     []string{"alt3.example.com"},
		Issuer:       "Example CA",
		NotBefore:    "2023-06-01T00:00:00Z",
		NotAfter:     "2024-06-01T00:00:00Z",
		SerialNumber: "02",
	}, {
		Source:       "test",
		CommonName:   "direct-cert.example.com",
		DNSNames:     []string{"alt1.example.com", "alt2.example.com"},
		Issuer:       "Example CA",
		NotBefore:    "2024-01-01T00:00:00Z",
		NotAfter:     "2025-01-01T00:00:00Z",
		SerialNumber: "01",
	}}

	sort.Slice(gotCerts, func(i, j int) bool { return gotCerts[i].CommonName < gotCerts[j].CommonName })
	sort.Slice(wantRecords, func(i, j int) bool { return wantRecords[i].CommonName < wantRecords[j].CommonName })
	if diff := cmp.Diff(wantRecords, gotCerts); diff != "" {
		t.Fatalf("unexpected certificate records (-want +got):\n%s", diff)
	}

	if activeCerts := readLines(t, filepath.Join(dir, "certs", "certs.active")); activeCerts != nil {
		t.Fatalf("expected empty certs.active, got %v", activeCerts)
	}

	meta := readLines(t, filepath.Join(dir, "meta.passive"))
	wantMeta := []string{"run started"}
	if diff := cmp.Diff(wantMeta, meta); diff != "" {
		t.Fatalf("unexpected meta (-want +got):\n%s", diff)
	}

	if activeMeta := readLines(t, filepath.Join(dir, "meta.active")); activeMeta != nil {
		t.Fatalf("expected empty meta.active, got %v", activeMeta)
	}
}

func TestSinkFiltersOutOfScope(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	sink.Start(2)

	allowedCert, err := (certs.Record{CommonName: "app.example.com", DNSNames: []string{"app.example.com", "evil.com"}}).Marshal()
	if err != nil {
		t.Fatalf("marshal allowed cert: %v", err)
	}
	deniedCert, err := (certs.Record{CommonName: "evil.com", DNSNames: []string{"evil.com"}}).Marshal()
	if err != nil {
		t.Fatalf("marshal denied cert: %v", err)
	}

	inputs := []string{
		"example.com",
		"evil.com",
		"https://app.example.com/login",
		"https://evil.com/hack",
		"js: https://app.example.com/app.js",
		"js: https://evil.com/app.js",
		"html: https://app.example.com/index.html",
		"html: //cdn.evil.com/lib.js",
		"cert: " + allowedCert,
		"cert: " + deniedCert,
	}

	for _, line := range inputs {
		sink.In() <- line
	}

	sink.Flush()
	if err := sink.Close(); err != nil {
		t.Fatalf("sink close: %v", err)
	}

	read := func(path string) []string {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		trimmed := strings.TrimSpace(string(data))
		if trimmed == "" {
			return nil
		}
		return strings.Split(trimmed, "\n")
	}

	domains := read(filepath.Join(dir, "domains", "domains.passive"))
	sort.Strings(domains)
	wantDomains := []string{"app.example.com", "example.com"}
	if diff := cmp.Diff(wantDomains, domains); diff != "" {
		t.Fatalf("unexpected domains.passive contents (-want +got):\n%s", diff)
	}

	routes := read(filepath.Join(dir, "routes", "routes.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/login"}, routes); diff != "" {
		t.Fatalf("unexpected routes.passive contents (-want +got):\n%s", diff)
	}

	jsRoutes := read(filepath.Join(dir, "routes", "js", "js.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/app.js"}, jsRoutes); diff != "" {
		t.Fatalf("unexpected js.passive contents (-want +got):\n%s", diff)
	}

	certsPassive := read(filepath.Join(dir, "certs", "certs.passive"))
	if len(certsPassive) != 1 {
		t.Fatalf("expected 1 certificate, got %v", certsPassive)
	}
	if !strings.Contains(certsPassive[0], "app.example.com") || strings.Contains(certsPassive[0], "evil.com") {
		t.Fatalf("unexpected cert contents: %s", certsPassive[0])
	}
}

func TestActiveCertLines(t *testing.T) {
	t.Parallel()

	sink, dir := newTestSink(t, true)
	sink.Start(1)

	passiveRecord, err := (certs.Record{
		Source:       "passive",
		CommonName:   "passive-cert.example.com",
		DNSNames:     []string{"passive-san.example.com"},
		Issuer:       "Example CA",
		NotBefore:    "2023-01-01T00:00:00Z",
		NotAfter:     "2024-01-01T00:00:00Z",
		SerialNumber: "p-01",
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal passive record: %v", err)
	}

	activeRecord, err := (certs.Record{
		Source:       "active",
		CommonName:   "active-cert.example.com",
		DNSNames:     []string{"active-san-one.example.com", "active-san-two.example.com"},
		Issuer:       "Example Active CA",
		NotBefore:    "2024-02-02T00:00:00Z",
		NotAfter:     "2025-02-02T00:00:00Z",
		SerialNumber: "a-01",
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal active record: %v", err)
	}

	sink.In() <- "cert: " + passiveRecord
	sink.In() <- "active: cert: " + activeRecord
	sink.In() <- "active: cert: " + activeRecord

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	passiveLines := readLines(t, filepath.Join(dir, "certs", "certs.passive"))
	if diff := cmp.Diff([]string{passiveRecord}, passiveLines); diff != "" {
		t.Fatalf("unexpected certs.passive contents (-want +got):\n%s", diff)
	}

	activeLines := readLines(t, filepath.Join(dir, "certs", "certs.active"))
	if diff := cmp.Diff([]string{activeRecord}, activeLines); diff != "" {
		t.Fatalf("unexpected certs.active contents (-want +got):\n%s", diff)
	}

	passiveDomains := readLines(t, filepath.Join(dir, "domains", "domains.passive"))
	sort.Strings(passiveDomains)
	wantPassiveDomains := []string{
		"active-cert.example.com",
		"active-san-one.example.com",
		"active-san-two.example.com",
		"passive-cert.example.com",
		"passive-san.example.com",
	}
	if diff := cmp.Diff(wantPassiveDomains, passiveDomains); diff != "" {
		t.Fatalf("unexpected domains.passive contents (-want +got):\n%s", diff)
	}

	activeDomains := readLines(t, filepath.Join(dir, "domains", "domains.active"))
	sort.Strings(activeDomains)
	if diff := cmp.Diff(wantPassiveDomains, activeDomains); diff != "" {
		t.Fatalf("unexpected domains.active contents (-want +got):\n%s", diff)
	}
}

func TestSinkFlush(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(2)

	sink.In() <- "one.example.com"
	sink.In() <- "two.example.com"

	sink.Flush()

	domains := readLines(t, filepath.Join(dir, "domains", "domains.passive"))
	wantDomains := []string{"one.example.com", "two.example.com"}
	sort.Strings(domains)
	if diff := cmp.Diff(wantDomains, domains); diff != "" {
		t.Fatalf("unexpected domains after flush (-want +got):\n%s", diff)
	}

	sink.In() <- "meta: later"

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestNormalizeDomainIPv6(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"[2001:db8::1]:8443":                "2001:db8::1",
		"2001:db8::1":                       "2001:db8::1",
		"HTTPS://[2001:db8::1]:8443/path":   "2001:db8::1",
		"http://[2001:db8::1]/":             "2001:db8::1",
		"[2001:db8::1]:8443 extra metadata": "2001:db8::1",
	}

	for input, want := range cases {
		input, want := input, want
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if got := netutil.NormalizeDomain(input); got != want {
				t.Fatalf("NormalizeDomain(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestNewSinkClosesWritersOnError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Force the second writer creation to fail by pre-creating a directory with
	// the same name. os.OpenFile will return an error because the path points to
	// a directory instead of a regular file.
	routesDir := filepath.Join(dir, "routes")
	if err := os.MkdirAll(routesDir, 0o755); err != nil {
		t.Fatalf("MkdirAll routes dir: %v", err)
	}
	if err := os.Mkdir(filepath.Join(routesDir, "routes.passive"), 0o755); err != nil {
		t.Fatalf("Mkdir routes.passive: %v", err)
	}

	domainPath := filepath.Join(dir, "domains", "domains.passive")
	if got := countOpenFDs(t, domainPath); got != 0 {
		t.Fatalf("unexpected open descriptors before NewSink: %d", got)
	}

	sink, err := NewSink(dir, false, "example.com")
	if err == nil {
		// Close to ensure no resources leak in this unexpected success case.
		_ = sink.Close()
		t.Fatalf("expected NewSink to fail")
	}

	if _, err := os.Stat(domainPath); err != nil {
		t.Fatalf("expected %q to exist: %v", domainPath, err)
	}

	if got := countOpenFDs(t, domainPath); got != 0 {
		t.Fatalf("domains writer file descriptor leaked: %d", got)
	}
}

func TestCertLinesPopulateDomainsPassiveSink(t *testing.T) {
	t.Parallel()

	sink, dir := newTestSink(t, false)
	sink.Start(1)

	raw, err := (certs.Record{
		CommonName: "cn.example.com",
		DNSNames:   []string{"alt1.example.com"},
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}

	sink.In() <- "cert: " + raw

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	domains := readLines(t, filepath.Join(dir, "domains", "domains.passive"))
	want := []string{"alt1.example.com", "cn.example.com"}
	if diff := cmp.Diff(want, domains); diff != "" {
		t.Fatalf("unexpected domains.passive contents (-want +got):\n%s", diff)
	}

	if active := readLines(t, filepath.Join(dir, "domains", "domains.active")); active != nil {
		t.Fatalf("expected empty domains.active, got %v", active)
	}
}

func TestCertLinesPopulateDomainsActiveSink(t *testing.T) {
	t.Parallel()

	sink, dir := newTestSink(t, true)
	sink.Start(1)

	raw, err := (certs.Record{
		CommonName: "api.example.com",
		DNSNames:   []string{"service.example.com"},
	}).Marshal()
	if err != nil {
		t.Fatalf("marshal certificate: %v", err)
	}

	sink.In() <- "cert: " + raw

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	want := []string{"api.example.com", "service.example.com"}

	passive := readLines(t, filepath.Join(dir, "domains", "domains.passive"))
	if diff := cmp.Diff(want, passive); diff != "" {
		t.Fatalf("unexpected domains.passive contents (-want +got):\n%s", diff)
	}

	active := readLines(t, filepath.Join(dir, "domains", "domains.active"))
	if diff := cmp.Diff(want, active); diff != "" {
		t.Fatalf("unexpected domains.active contents (-want +got):\n%s", diff)
	}
}

func TestActiveRoutesPopulatePassive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)
	sink.In() <- "active: https://app.example.com/login [200] [Title]"

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	passive := readLines(t, filepath.Join(dir, "routes", "routes.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/login"}, passive); diff != "" {
		t.Fatalf("unexpected routes.passive contents (-want +got):\n%s", diff)
	}

	active := readLines(t, filepath.Join(dir, "routes", "routes.active"))
	if diff := cmp.Diff([]string{"https://app.example.com/login [200] [Title]"}, active); diff != "" {
		t.Fatalf("unexpected routes.active contents (-want +got):\n%s", diff)
	}
}

func TestActiveRoutesSkip404(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)
	sink.In() <- "active: https://app.example.com/login [404]"
	sink.In() <- "active: https://app.example.com/dashboard [200]"

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	passive := readLines(t, filepath.Join(dir, "routes", "routes.passive"))
	wantPassive := []string{
		"https://app.example.com/login",
		"https://app.example.com/dashboard",
	}
	if diff := cmp.Diff(wantPassive, passive); diff != "" {
		t.Fatalf("unexpected routes.passive contents (-want +got):\n%s", diff)
	}

	active := readLines(t, filepath.Join(dir, "routes", "routes.active"))
	if diff := cmp.Diff([]string{"https://app.example.com/dashboard [200]"}, active); diff != "" {
		t.Fatalf("unexpected routes.active contents (-want +got):\n%s", diff)
	}
}

func TestJSLinesAreWrittenToFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)
	sink.In() <- "js: https://static.example.com/app.js"
	sink.In() <- "active: js: https://static.example.com/app.js"

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	passivePath := filepath.Join(dir, "routes", "js", "js.passive")
	passiveLines := readLines(t, passivePath)
	if diff := cmp.Diff([]string{"https://static.example.com/app.js"}, passiveLines); diff != "" {
		t.Fatalf("unexpected js.passive contents (-want +got):\n%s", diff)
	}

	activePath := filepath.Join(dir, "routes", "js", "js.active")
	activeLines := readLines(t, activePath)
	if diff := cmp.Diff([]string{"https://static.example.com/app.js"}, activeLines); diff != "" {
		t.Fatalf("unexpected js.active contents (-want +got):\n%s", diff)
	}
}

func TestActiveJSExcludes404(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)
	sink.In() <- "active: js: https://static.example.com/app.js [200]"
	sink.In() <- "active: js: https://static.example.com/missing.js [404]"

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	activePath := filepath.Join(dir, "routes", "js", "js.active")
	activeLines := readLines(t, activePath)
	if diff := cmp.Diff([]string{"https://static.example.com/app.js [200]"}, activeLines); diff != "" {
		t.Fatalf("unexpected js.active contents (-want +got):\n%s", diff)
	}
}

func TestHTMLLinesAreWrittenToActiveFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)
	sink.In() <- "active: html: https://app.example.com"

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	htmlPath := filepath.Join(dir, "routes", "html", "html.active")
	htmlLines := readLines(t, htmlPath)
	if diff := cmp.Diff([]string{"https://app.example.com"}, htmlLines); diff != "" {
		t.Fatalf("unexpected html.active contents (-want +got):\n%s", diff)
	}
}

func TestHTMLActiveSkipsErrorResponses(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)
	sink.In() <- "active: html: https://app.example.com [404] [Not Found]"

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	htmlPath := filepath.Join(dir, "routes", "html", "html.active")
	if lines := readLines(t, htmlPath); len(lines) != 0 {
		t.Fatalf("expected html.active to be empty, got %v", lines)
	}
}

func TestHTMLImageLinesAreRedirectedToImagesFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)
	sink.In() <- "active: html: https://app.example.com/assets/logo.png"
	sink.In() <- "active: html: https://app.example.com/assets/logo.svg"

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	htmlPath := filepath.Join(dir, "routes", "html", "html.active")
	if lines := readLines(t, htmlPath); len(lines) != 0 {
		t.Fatalf("expected html.active to be empty, got %v", lines)
	}

	imagesPath := filepath.Join(dir, "routes", "images", "images.active")
	imagesLines := readLines(t, imagesPath)
	wantImages := []string{
		"https://app.example.com/assets/logo.png",
		"https://app.example.com/assets/logo.svg",
	}
	if diff := cmp.Diff(wantImages, imagesLines); diff != "" {
		t.Fatalf("unexpected images.active contents (-want +got):\n%s", diff)
	}
}

func TestRouteCategorizationPassive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)
	inputs := []string{
		"https://app.example.com/static/app.js.map",
		"https://app.example.com/static/app.jsonld",
		"https://app.example.com/static/manifest.json",
		"https://app.example.com/static/swagger.yaml",
		"https://app.example.com/static/swagger.json",
		"https://app.example.com/static/module.wasm",
		"https://app.example.com/static/vector.svg",
		"https://app.example.com/robots.txt",
		"https://app.example.com/sitemap.xml",
		"https://app.example.com/backup.tar.gz?download=1",
		"https://app.example.com/debug?token=secret",
	}
	for _, line := range inputs {
		sink.In() <- line
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mapsLines := readLines(t, filepath.Join(dir, "routes", "maps", "maps.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/app.js.map"}, mapsLines); diff != "" {
		t.Fatalf("unexpected maps.passive contents (-want +got):\n%s", diff)
	}

	jsonLines := readLines(t, filepath.Join(dir, "routes", "json", "json.passive"))
	wantJSON := []string{
		"https://app.example.com/static/app.jsonld",
		"https://app.example.com/static/manifest.json",
	}
	if diff := cmp.Diff(wantJSON, jsonLines); diff != "" {
		t.Fatalf("unexpected json.passive contents (-want +got):\n%s", diff)
	}

	apiLines := readLines(t, filepath.Join(dir, "routes", "api", "api.passive"))
	wantAPI := []string{
		"https://app.example.com/static/swagger.yaml",
		"https://app.example.com/static/swagger.json",
	}
	if diff := cmp.Diff(wantAPI, apiLines); diff != "" {
		t.Fatalf("unexpected api.passive contents (-want +got):\n%s", diff)
	}

	wasmLines := readLines(t, filepath.Join(dir, "routes", "wasm", "wasm.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/module.wasm"}, wasmLines); diff != "" {
		t.Fatalf("unexpected wasm.passive contents (-want +got):\n%s", diff)
	}

	svgLines := readLines(t, filepath.Join(dir, "routes", "svg", "svg.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/vector.svg"}, svgLines); diff != "" {
		t.Fatalf("unexpected svg.passive contents (-want +got):\n%s", diff)
	}

	crawlLines := readLines(t, filepath.Join(dir, "routes", "crawl", "crawl.passive"))
	wantCrawl := []string{
		"https://app.example.com/robots.txt",
		"https://app.example.com/sitemap.xml",
	}
	if diff := cmp.Diff(wantCrawl, crawlLines); diff != "" {
		t.Fatalf("unexpected crawl.passive contents (-want +got):\n%s", diff)
	}

	metaLines := readLines(t, filepath.Join(dir, "routes", "meta", "meta.passive"))
	wantMeta := []string{
		"https://app.example.com/backup.tar.gz?download=1",
		"https://app.example.com/debug?token=secret",
	}
	if diff := cmp.Diff(wantMeta, metaLines); diff != "" {
		t.Fatalf("unexpected meta.passive contents (-want +got):\n%s", diff)
	}
}

func TestRouteCategorizationActiveMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, true, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)
	sink.In() <- "https://app.example.com/static/app.js.map"
	sink.In() <- "active: https://app.example.com/static/app.js.map [200]"
	sink.In() <- "active: https://app.example.com/static/manifest.json [200]"
	sink.In() <- "https://app.example.com/static/swagger.json"
	sink.In() <- "active: https://app.example.com/static/swagger.json [200]"

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mapsPassive := readLines(t, filepath.Join(dir, "routes", "maps", "maps.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/app.js.map"}, mapsPassive); diff != "" {
		t.Fatalf("unexpected maps.passive contents (-want +got):\n%s", diff)
	}

	mapsPath := filepath.Join(dir, "routes", "maps", "maps.active")
	mapsLines := readLines(t, mapsPath)
	if diff := cmp.Diff([]string{"https://app.example.com/static/app.js.map"}, mapsLines); diff != "" {
		t.Fatalf("unexpected maps.active contents (-want +got):\n%s", diff)
	}

	jsonLines := readLines(t, filepath.Join(dir, "routes", "json", "json.active"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/manifest.json"}, jsonLines); diff != "" {
		t.Fatalf("unexpected json.active contents (-want +got):\n%s", diff)
	}

	apiPassive := readLines(t, filepath.Join(dir, "routes", "api", "api.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/swagger.json"}, apiPassive); diff != "" {
		t.Fatalf("unexpected api.passive contents (-want +got):\n%s", diff)
	}

	apiLines := readLines(t, filepath.Join(dir, "routes", "api", "api.active"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/swagger.json"}, apiLines); diff != "" {
		t.Fatalf("unexpected api.active contents (-want +got):\n%s", diff)
	}

	if _, err := os.Stat(filepath.Join(dir, "routes", "meta")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected routes/meta to be absent, got err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "routes", "wasm")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected routes/wasm to be absent, got err=%v", err)
	}
}

func TestRouteCategorizationActiveModeSkipsErrorStatus(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, true, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)
	sink.In() <- "active: https://app.example.com/static/config.json [404] [Not Found]"

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	jsonPath := filepath.Join(dir, "routes", "json", "json.active")
	if _, err := os.Stat(jsonPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected no json.active file, got err=%v", err)
	}
}

func TestRouteCategorizationPassiveModeEmitsActiveFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)
	sink.In() <- "active: https://app.example.com/static/app.js.map [200]"

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	activeLines := readLines(t, filepath.Join(dir, "routes", "maps", "maps.active"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/app.js.map"}, activeLines); diff != "" {
		t.Fatalf("unexpected maps.active contents (-want +got):\n%s", diff)
	}

	if _, err := os.Stat(filepath.Join(dir, "routes", "maps", "maps.passive")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected maps.passive to be absent, got err=%v", err)
	}
}

func TestRouteCategorizationDeduplicatesCategoryOutputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false, "example.com")
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(2)
	inputs := []string{
		"https://app.example.com/static/app.js.map",
		"https://app.example.com/static/app.js.map",
		"https://app.example.com/static/manifest.json",
		"https://app.example.com/static/manifest.json",
		"https://app.example.com/static/swagger.json",
		"https://app.example.com/static/swagger.json",
		"https://app.example.com/static/module.wasm",
		"https://app.example.com/static/module.wasm",
		"https://app.example.com/static/vector.svg",
		"https://app.example.com/static/vector.svg",
		"https://app.example.com/robots.txt",
		"https://app.example.com/robots.txt",
		"https://app.example.com/sitemap.xml",
		"https://app.example.com/sitemap.xml",
		"https://app.example.com/backup.tar.gz?download=1",
		"https://app.example.com/backup.tar.gz?download=1",
	}
	for _, line := range inputs {
		sink.In() <- line
	}

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	mapsLines := readLines(t, filepath.Join(dir, "routes", "maps", "maps.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/app.js.map"}, mapsLines); diff != "" {
		t.Fatalf("unexpected maps.passive contents (-want +got):\n%s", diff)
	}

	jsonLines := readLines(t, filepath.Join(dir, "routes", "json", "json.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/manifest.json"}, jsonLines); diff != "" {
		t.Fatalf("unexpected json.passive contents (-want +got):\n%s", diff)
	}

	apiLines := readLines(t, filepath.Join(dir, "routes", "api", "api.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/swagger.json"}, apiLines); diff != "" {
		t.Fatalf("unexpected api.passive contents (-want +got):\n%s", diff)
	}

	wasmLines := readLines(t, filepath.Join(dir, "routes", "wasm", "wasm.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/module.wasm"}, wasmLines); diff != "" {
		t.Fatalf("unexpected wasm.passive contents (-want +got):\n%s", diff)
	}

	svgLines := readLines(t, filepath.Join(dir, "routes", "svg", "svg.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/vector.svg"}, svgLines); diff != "" {
		t.Fatalf("unexpected svg.passive contents (-want +got):\n%s", diff)
	}

	crawlLines := readLines(t, filepath.Join(dir, "routes", "crawl", "crawl.passive"))
	wantCrawl := []string{
		"https://app.example.com/robots.txt",
		"https://app.example.com/sitemap.xml",
	}
	if diff := cmp.Diff(wantCrawl, crawlLines); diff != "" {
		t.Fatalf("unexpected crawl.passive contents (-want +got):\n%s", diff)
	}

	metaLines := readLines(t, filepath.Join(dir, "routes", "meta", "meta.passive"))
	if diff := cmp.Diff([]string{"https://app.example.com/backup.tar.gz?download=1"}, metaLines); diff != "" {
		t.Fatalf("unexpected meta.passive contents (-want +got):\n%s", diff)
	}
}

func readLines(t *testing.T, path string) []string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%q): %v", path, err)
	}
	contents := strings.TrimSpace(string(data))
	if contents == "" {
		return nil
	}
	return strings.Split(contents, "\n")
}

func countOpenFDs(t *testing.T, path string) int {
	t.Helper()

	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatalf("ReadDir(/proc/self/fd): %v", err)
	}

	count := 0
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err != nil {
			continue
		}
		if strings.HasPrefix(target, path) {
			count++
		}
	}
	return count
}
