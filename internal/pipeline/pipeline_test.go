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

func TestSinkClassification(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir)
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
	wantDomains := []string{"example.com"}
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
	sink, err := NewSink(dir)
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

	sink, err := NewSink(dir)
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
	sink, err := NewSink(dir)
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
