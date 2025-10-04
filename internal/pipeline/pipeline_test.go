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
)

func newTestSink(t *testing.T, active bool) (*Sink, string) {
	t.Helper()
	dir := t.TempDir()
	sink, err := NewSink(dir, active)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}
	return sink, dir
}

func TestSinkClassification(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false)
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
	wantDomains := []string{"example.com", "2001:db8::1"}
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

	if _, err := os.Stat(filepath.Join(dir, "certs", "certs.active")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected certs.active to be absent, got err=%v", err)
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

func TestSinkFlush(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false)
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

func TestHandleMeta(t *testing.T) {
	t.Parallel()

	t.Run("passive", func(t *testing.T) {
		t.Parallel()
		sink, dir := newTestSink(t, false)
		if !handleMeta(sink, "meta: passive entry", false) {
			t.Fatalf("expected meta prefix to be handled")
		}
		if !handleMeta(sink, "note --> details", false) {
			t.Fatalf("expected comment line to be handled")
		}
		if handleMeta(sink, "plain text", false) {
			t.Fatalf("expected non-meta line to be ignored")
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		got := readLines(t, filepath.Join(dir, "meta.passive"))
		want := []string{"passive entry", "note --> details"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("unexpected meta.passive contents (-want +got):\n%s", diff)
		}
	})

	t.Run("active", func(t *testing.T) {
		t.Parallel()
		sink, dir := newTestSink(t, true)
		if !handleMeta(sink, "meta: active entry", true) {
			t.Fatalf("expected active meta prefix to be handled")
		}
		if !handleMeta(sink, "active --> details", true) {
			t.Fatalf("expected active comment to be handled")
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		got := readLines(t, filepath.Join(dir, "meta.active"))
		want := []string{"active entry", "active --> details"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("unexpected meta.active contents (-want +got):\n%s", diff)
		}
	})
}

func TestHandleJS(t *testing.T) {
	t.Parallel()

	t.Run("passive", func(t *testing.T) {
		t.Parallel()
		sink, dir := newTestSink(t, false)
		if !handleJS(sink, "js: https://example.com/static.js", false) {
			t.Fatalf("expected passive js line to be handled")
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		got := readLines(t, filepath.Join(dir, "routes", "js", "js.passive"))
		want := []string{"https://example.com/static.js"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("unexpected js.passive contents (-want +got):\n%s", diff)
		}
	})

	t.Run("active", func(t *testing.T) {
		t.Parallel()
		sink, dir := newTestSink(t, false)
		if !handleJS(sink, "js: https://example.com/active.js", true) {
			t.Fatalf("expected active js line to be handled")
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		passive := readLines(t, filepath.Join(dir, "routes", "js", "js.passive"))
		if diff := cmp.Diff([]string{"https://example.com/active.js"}, passive); diff != "" {
			t.Fatalf("unexpected js.passive contents for active line (-want +got):\n%s", diff)
		}
		active := readLines(t, filepath.Join(dir, "routes", "js", "js.active"))
		if diff := cmp.Diff([]string{"https://example.com/active.js"}, active); diff != "" {
			t.Fatalf("unexpected js.active contents (-want +got):\n%s", diff)
		}
	})
}

func TestHandleHTML(t *testing.T) {
	t.Parallel()

	t.Run("passive", func(t *testing.T) {
		t.Parallel()
		sink, dir := newTestSink(t, false)
		if !handleHTML(sink, "html: https://example.com/page", false) {
			t.Fatalf("expected passive html line to be handled")
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "routes", "html", "html.passive")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected passive HTML artifact to be absent, got err=%v", err)
		}
	})

	t.Run("active", func(t *testing.T) {
		t.Parallel()
		sink, dir := newTestSink(t, false)
		line := "html: <div>active</div>"
		if !handleHTML(sink, line, true) {
			t.Fatalf("expected active html line to be handled")
		}
		if !handleHTML(sink, line, true) {
			t.Fatalf("expected duplicate active html line to be handled")
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		got := readLines(t, filepath.Join(dir, "routes", "html", "html.active"))
		want := []string{"<div>active</div>"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("unexpected html.active contents (-want +got):\n%s", diff)
		}
	})
}

func TestHandleRoute(t *testing.T) {
	t.Parallel()

	t.Run("passive", func(t *testing.T) {
		t.Parallel()
		sink, dir := newTestSink(t, false)
		line := "https://example.com/data.json"
		if !handleRoute(sink, line, false) {
			t.Fatalf("expected passive route to be handled")
		}
		if !handleRoute(sink, line, false) {
			t.Fatalf("expected duplicate passive route to be handled")
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		routes := readLines(t, filepath.Join(dir, "routes", "routes.passive"))
		if diff := cmp.Diff([]string{line}, routes); diff != "" {
			t.Fatalf("unexpected routes.passive contents (-want +got):\n%s", diff)
		}
		jsonRoutes := readLines(t, filepath.Join(dir, "routes", "json", "json.passive"))
		if diff := cmp.Diff([]string{line}, jsonRoutes); diff != "" {
			t.Fatalf("unexpected json.passive contents (-want +got):\n%s", diff)
		}
	})

	t.Run("active", func(t *testing.T) {
		t.Parallel()
		sink, dir := newTestSink(t, true)
		line := "https://active.example.com/api.json"
		if !handleRoute(sink, line, true) {
			t.Fatalf("expected active route to be handled")
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		active := readLines(t, filepath.Join(dir, "routes", "routes.active"))
		if diff := cmp.Diff([]string{line}, active); diff != "" {
			t.Fatalf("unexpected routes.active contents (-want +got):\n%s", diff)
		}
		passive := readLines(t, filepath.Join(dir, "routes", "routes.passive"))
		if diff := cmp.Diff([]string{line}, passive); diff != "" {
			t.Fatalf("unexpected passive copy of active route (-want +got):\n%s", diff)
		}
		jsonRoutes := readLines(t, filepath.Join(dir, "routes", "json", "json.active"))
		if diff := cmp.Diff([]string{line}, jsonRoutes); diff != "" {
			t.Fatalf("unexpected json.active contents (-want +got):\n%s", diff)
		}
	})
}

func TestHandleCert(t *testing.T) {
	t.Parallel()

	t.Run("passive", func(t *testing.T) {
		t.Parallel()
		sink, dir := newTestSink(t, false)
		recordOne, err := (certs.Record{CommonName: "one.example.com"}).Marshal()
		if err != nil {
			t.Fatalf("marshal recordOne: %v", err)
		}
		recordTwo, err := (certs.Record{CommonName: "two.example.com", DNSNames: []string{"two.example.com"}}).Marshal()
		if err != nil {
			t.Fatalf("marshal recordTwo: %v", err)
		}
		if !handleCert(sink, "cert: "+recordOne, false) {
			t.Fatalf("expected prefixed cert line to be handled")
		}
		if !handleCert(sink, recordTwo, false) {
			t.Fatalf("expected raw cert line to be handled")
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		got := readLines(t, filepath.Join(dir, "certs", "certs.passive"))
		if len(got) != 2 {
			t.Fatalf("expected two certificate records, got %d", len(got))
		}
	})

	t.Run("active", func(t *testing.T) {
		t.Parallel()
		sink, dir := newTestSink(t, true)
		record, err := (certs.Record{CommonName: "active.example.com"}).Marshal()
		if err != nil {
			t.Fatalf("marshal record: %v", err)
		}
		if !handleCert(sink, "cert: "+record, true) {
			t.Fatalf("expected active cert line to be handled")
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		got := readLines(t, filepath.Join(dir, "certs", "certs.passive"))
		if diff := cmp.Diff([]string{record}, got); diff != "" {
			t.Fatalf("unexpected cert output (-want +got):\n%s", diff)
		}
	})
}

func TestHandleDomain(t *testing.T) {
	t.Parallel()

	t.Run("passive", func(t *testing.T) {
		t.Parallel()
		sink, dir := newTestSink(t, false)
		if !handleDomain(sink, "example.com", false) {
			t.Fatalf("expected passive domain to be handled")
		}
		if !handleDomain(sink, "www.example.com", false) {
			t.Fatalf("expected duplicate passive domain to be handled")
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		got := readLines(t, filepath.Join(dir, "domains", "domains.passive"))
		if diff := cmp.Diff([]string{"example.com"}, got); diff != "" {
			t.Fatalf("unexpected domains.passive contents (-want +got):\n%s", diff)
		}
	})

	t.Run("active", func(t *testing.T) {
		t.Parallel()
		sink, dir := newTestSink(t, true)
		if !handleDomain(sink, "active.example.com", true) {
			t.Fatalf("expected active domain to be handled")
		}
		if err := sink.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		got := readLines(t, filepath.Join(dir, "domains", "domains.active"))
		if diff := cmp.Diff([]string{"active.example.com"}, got); diff != "" {
			t.Fatalf("unexpected domains.active contents (-want +got):\n%s", diff)
		}
	})
}

func TestNormalizeDomainKeyIPv6(t *testing.T) {
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
			if got := normalizeDomainKey(input); got != want {
				t.Fatalf("normalizeDomainKey(%q) = %q, want %q", input, got, want)
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

	sink, err := NewSink(dir, false)
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

func TestActiveRoutesPopulatePassive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false)
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

func TestJSLinesAreWrittenToFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false)
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

func TestHTMLLinesAreWrittenToActiveFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false)
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

func TestRouteCategorizationPassive(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false)
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
	sink, err := NewSink(dir, true)
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

	mapsPath := filepath.Join(dir, "routes", "maps", "maps.active")
	mapsLines := readLines(t, mapsPath)
	if diff := cmp.Diff([]string{"https://app.example.com/static/app.js.map"}, mapsLines); diff != "" {
		t.Fatalf("unexpected maps.active contents (-want +got):\n%s", diff)
	}

	jsonLines := readLines(t, filepath.Join(dir, "routes", "json", "json.active"))
	if diff := cmp.Diff([]string{"https://app.example.com/static/manifest.json"}, jsonLines); diff != "" {
		t.Fatalf("unexpected json.active contents (-want +got):\n%s", diff)
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
	sink, err := NewSink(dir, true)
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

func TestRouteCategorizationDeduplicatesCategoryOutputs(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir, false)
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
