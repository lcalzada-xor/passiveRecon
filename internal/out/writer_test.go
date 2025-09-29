package out

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"example.com":                        "example.com",
		"https://www.Example.com/path":       "example.com",
		"sub.example.com:8080/other":         "sub.example.com",
		"http://www.example.com:443/foo/bar": "example.com",
		"":                                   "",
	}
	for input, expected := range cases {
		if got := normalizeDomain(input); got != expected {
			t.Fatalf("normalizeDomain(%q) = %q, want %q", input, got, expected)
		}
	}
}

func TestWriteDomain(t *testing.T) {
	dir := t.TempDir()
	w, err := New(dir, "domains.passive")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer w.Close()

	inputs := []string{
		"https://example.com", // base
		"example.com",         // duplicate after normalization
		"www.example.com",     // trimmed prefix
		"sub.example.com",     // unique
		"sub.example.com/",    // same as previous
		"",                    // ignored
	}
	for _, in := range inputs {
		if err := w.WriteDomain(in); err != nil {
			t.Fatalf("WriteDomain(%q): %v", in, err)
		}
	}

	data, err := os.ReadFile(filepath.Join(dir, "domains.passive"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	got := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := []string{"example.com", "sub.example.com"}
	if len(got) != len(want) {
		t.Fatalf("WriteDomain produced %d lines, want %d: %q", len(got), len(want), got)
	}
	for i, line := range want {
		if got[i] != line {
			t.Fatalf("line %d = %q, want %q", i, got[i], line)
		}
	}
}

func TestWriteURL(t *testing.T) {
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

	data, err := os.ReadFile(filepath.Join(dir, "routes.passive"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")

	want := []string{
		"http://example.com/path",
		"https://secure.example.com",
	}
	if len(lines) != len(want) {
		t.Fatalf("WriteURL produced %d lines, want %d: %q", len(lines), len(want), lines)
	}
	for i, line := range want {
		if lines[i] != line {
			t.Fatalf("line %d = %q, want %q", i, lines[i], line)
		}
	}
}

func TestWriteRaw(t *testing.T) {
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

	data, err := os.ReadFile(filepath.Join(dir, "meta.passive"))
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := []string{"line1", "line2"}
	if len(lines) != len(want) {
		t.Fatalf("WriteRaw produced %d lines, want %d: %q", len(lines), len(want), lines)
	}
	for i, line := range want {
		if lines[i] != line {
			t.Fatalf("line %d = %q, want %q", i, lines[i], line)
		}
	}
}
