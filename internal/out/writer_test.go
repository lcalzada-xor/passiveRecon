package out

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestNormalizeDomain(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"example.com":                        "example.com",
		" https://www.Example.com/path ":     "example.com",
		"WWW.example.com":                    "example.com",
		"WwW.foo.com":                        "foo.com",
		"sub.example.com:8080/other":         "sub.example.com",
		"http://www.example.com:443/foo/bar": "example.com",
		"[2001:db8::1]:8443":                 "2001:db8::1",
		" 2001:db8::1 ":                      "2001:db8::1",
		"[2001:db8::1]:8443 status: up":      "2001:db8::1 status: up",
		"example.com\tstatus:200":            "example.com status:200",
		"example.com   status ok":            "example.com status ok",
		"*.example.com":                      "",
		"":                                   "",
		"No assets were discovered":          "",
	}
	for input, expected := range cases {
		input, expected := input, expected
		name := strings.ReplaceAll(input, "\t", "\\t")
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := normalizeDomain(input); got != expected {
				t.Fatalf("normalizeDomain(%q) = %q, want %q", input, got, expected)
			}
		})
	}
}

func TestNormalizeURL(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"example.com":             "http://example.com",
		"https://secure.example":  "https://secure.example",
		" http://foo.bar/baz ":    "http://foo.bar/baz",
		"":                        "",
		"//relative/path":         "http:////relative/path",
		"HTTPS://Example.com":     "https://example.com",
		"http://Example.com:8080": "http://example.com:8080",
	}
	for input, expected := range cases {
		input, expected := input, expected
		t.Run(input, func(t *testing.T) {
			t.Parallel()
			if got := normalizeURL(input); got != expected {
				t.Fatalf("normalizeURL(%q) = %q, want %q", input, got, expected)
			}
		})
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

func TestWriteDomain(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := New(dir, "domains.passive")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	inputs := []string{
		"https://example.com",           // base
		"example.com",                   // duplicate after normalization
		"www.example.com",               // trimmed prefix
		"sub.example.com",               // unique
		"sub.example.com/",              // same as previous
		"[2001:db8::1]:8443",            // IPv6 with port and brackets
		"2001:db8::1",                   // duplicate of previous
		"[2001:db8::1]:8443 status: up", // IPv6 with metadata
		"2001:db8::1 status: up",        // duplicate preserving metadata
		"",                              // ignored
		"No assets were discovered",     // noise from assetfinder output
	}
	for _, in := range inputs {
		if err := w.WriteDomain(in); err != nil {
			t.Fatalf("WriteDomain(%q): %v", in, err)
		}
	}

	got := readLines(t, filepath.Join(dir, "domains.passive"))
	want := []string{"example.com", "sub.example.com", "2001:db8::1", "2001:db8::1 status: up"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected domains (-want +got):\n%s", diff)
	}
}

func TestWriteURL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := New(dir, "routes.passive")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	inputs := []string{
		"example.com/path",
		"http://example.com/path",
		"https://secure.example.com",
		"https://secure.example.com", // duplicate
		"",                           // ignored
	}
	for _, in := range inputs {
		if err := w.WriteURL(in); err != nil {
			t.Fatalf("WriteURL(%q): %v", in, err)
		}
	}

	got := readLines(t, filepath.Join(dir, "routes.passive"))
	want := []string{
		"http://example.com/path",
		"https://secure.example.com",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected urls (-want +got):\n%s", diff)
	}
}

func TestWriteRaw(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	w, err := New(dir, "meta.passive")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	inputs := []string{"line1", " line1 ", "line2"}
	for _, in := range inputs {
		if err := w.WriteRaw(in); err != nil {
			t.Fatalf("WriteRaw(%q): %v", in, err)
		}
	}

	got := readLines(t, filepath.Join(dir, "meta.passive"))
	want := []string{"line1", "line2"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("unexpected raw lines (-want +got):\n%s", diff)
	}
}
