package pipeline

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestSinkClassification(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	sink, err := NewSink(dir)
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)

	inputs := []string{
		"  example.com  ",
		"https://app.example.com/login",
		"http://example.com/about",
		"meta: run started",
		"sub.example.com/path",
		"www.example.com",
		"meta: run started",
		"alt1.example.com,alt2.example.com",
		"alt2.example.com\nalt3.example.com",
		"cert: direct-cert.example.com",
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

	certs := readLines(t, filepath.Join(dir, "certs", "certs.passive"))
	wantCerts := []string{"alt1.example.com", "alt2.example.com", "alt3.example.com", "direct-cert.example.com"}
	if diff := cmp.Diff(wantCerts, certs); diff != "" {
		t.Fatalf("unexpected certs (-want +got):\n%s", diff)
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
