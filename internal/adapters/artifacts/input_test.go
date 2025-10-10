package artifacts

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteTempInputCreatesFile(t *testing.T) {
	path, cleanup, err := WriteTempInput("HTTPX", []string{"one", "two"})
	if err != nil {
		t.Fatalf("WriteTempInput returned error: %v", err)
	}
	if cleanup == nil {
		t.Fatalf("expected cleanup callback")
	}
	defer cleanup()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected readable temp file: %v", err)
	}
	if string(data) != "one\ntwo\n" {
		t.Fatalf("unexpected file contents: %q", string(data))
	}

	if !strings.Contains(filepath.Base(path), "passive-rec-httpx-") {
		t.Fatalf("unexpected temp file name: %s", path)
	}

	cleanup()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected cleanup to remove file, stat err=%v", err)
	}
}

func TestSanitizePrefixFallback(t *testing.T) {
	name := sanitizePrefix("  @@@  ")
	if name != "input" {
		t.Fatalf("unexpected sanitize result: %q", name)
	}

	name = sanitizePrefix("Go-Linkfinder!")
	if name != "go-linkfinder" {
		t.Fatalf("unexpected sanitize result: %q", name)
	}
}
