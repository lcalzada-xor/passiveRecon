package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDebugGFFinding(t *testing.T) {
	dir := t.TempDir()

	sink, err := NewSink(dir, true, "example.com", "subdomains", LineBufferSize(1))
	if err != nil {
		t.Fatalf("NewSink: %v", err)
	}

	sink.Start(1)
	payload := map[string]any{
		"resource": "https://example.com/app.js",
		"line":     99,
		"evidence": "fetch('/api')",
		"context":  "const data = fetch('/api')",
		"rules":    []string{"xss", "sqli", "xss"},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}

	sink.In() <- "active: gffinding: " + string(data)

	if err := sink.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Read raw file
	raw, _ := os.ReadFile(filepath.Join(dir, "artifacts.jsonl"))
	fmt.Println("=== Raw JSONL file contents ===")
	fmt.Println(string(raw))
	fmt.Println()

	// Read artifacts using reader
	artifacts := readArtifactsFile(t, filepath.Join(dir, "artifacts.jsonl"))
	fmt.Printf("=== Found %d artifacts ===\n", len(artifacts))
	for i, art := range artifacts {
		j, _ := json.MarshalIndent(art, "", "  ")
		fmt.Printf("Artifact %d:\n%s\n\n", i, string(j))
	}

	expectedValue := buildGFFindingValue("https://example.com/app.js", 99, "fetch('/api')")
	fmt.Printf("Expected value: %q\n", expectedValue)
	fmt.Printf("Actual value:   %q\n", artifacts[0].Value)
}
