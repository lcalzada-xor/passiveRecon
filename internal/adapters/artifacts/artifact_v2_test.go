package artifacts

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestToV2_BasicArtifact(t *testing.T) {
	baseTime := time.Date(2025, 10, 13, 19, 29, 44, 0, time.UTC)

	v1 := Artifact{
		Type:        "domain",
		Value:       "example.com",
		Active:      false,
		Up:          true,
		Tool:        "crtsh",
		Occurrences: 5,
		FirstSeen:   "2025-10-13T19:29:44Z",
		LastSeen:    "2025-10-13T19:30:44Z",
		Version:     "1.0",
	}

	v2 := ToV2(v1, baseTime)

	if v2.T != "domain" {
		t.Errorf("Expected type 'domain', got '%s'", v2.T)
	}

	if v2.V != "example.com" {
		t.Errorf("Expected value 'example.com', got '%v'", v2.V)
	}

	if v2.St != StateInactiveUp {
		t.Errorf("Expected state '%s', got '%s'", StateInactiveUp, v2.St)
	}

	if v2.Tl != "crtsh" {
		t.Errorf("Expected tool 'crtsh', got '%s'", v2.Tl)
	}

	if v2.N != 5 {
		t.Errorf("Expected occurrences 5, got %d", v2.N)
	}

	// Timestamps: first=0ms, last=60000ms (60 seconds)
	if len(v2.Ts) != 2 {
		t.Errorf("Expected 2 timestamps, got %d", len(v2.Ts))
	}
	if v2.Ts[0] != 0 {
		t.Errorf("Expected first timestamp 0, got %d", v2.Ts[0])
	}
	if v2.Ts[1] != 60000 {
		t.Errorf("Expected last timestamp 60000, got %d", v2.Ts[1])
	}
}

func TestToV1_RoundTrip(t *testing.T) {
	baseTime := time.Date(2025, 10, 13, 19, 29, 44, 0, time.UTC)

	original := Artifact{
		Type:        "route",
		Value:       "/api/users",
		Active:      true,
		Up:          true,
		Tool:        "linkfinderevo",
		Occurrences: 3,
		FirstSeen:   "2025-10-13T19:29:44Z",
		LastSeen:    "2025-10-13T19:29:44Z", // Same as first
		Version:     "1.0",
	}

	v2 := ToV2(original, baseTime)
	restored := ToV1(v2, baseTime)

	if restored.Type != original.Type {
		t.Errorf("Type mismatch: expected '%s', got '%s'", original.Type, restored.Type)
	}

	if restored.Value != original.Value {
		t.Errorf("Value mismatch: expected '%s', got '%s'", original.Value, restored.Value)
	}

	if restored.Active != original.Active {
		t.Errorf("Active mismatch: expected %v, got %v", original.Active, restored.Active)
	}

	if restored.Up != original.Up {
		t.Errorf("Up mismatch: expected %v, got %v", original.Up, restored.Up)
	}

	if restored.Tool != original.Tool {
		t.Errorf("Tool mismatch: expected '%s', got '%s'", original.Tool, restored.Tool)
	}
}

func TestStateConversion(t *testing.T) {
	tests := []struct {
		active   bool
		up       bool
		expected string
	}{
		{true, true, StateActiveUp},
		{true, false, StateActiveDown},
		{false, true, StateInactiveUp},
		{false, false, StateInactiveDown},
	}

	for _, tt := range tests {
		result := stateToV2(tt.active, tt.up)
		if result != tt.expected {
			t.Errorf("stateToV2(%v, %v) = '%s', expected '%s'",
				tt.active, tt.up, result, tt.expected)
		}

		// Test reverse
		active, up := stateFromV2(result)
		if active != tt.active || up != tt.up {
			t.Errorf("stateFromV2('%s') = (%v, %v), expected (%v, %v)",
				result, active, up, tt.active, tt.up)
		}
	}
}

func TestCertificateCompaction(t *testing.T) {
	cert := map[string]any{
		"common_name":   "example.com",
		"dns_names":     []interface{}{"example.com", "www.example.com"},
		"issuer":        "C=US, O=Google Trust Services, CN=WR3",
		"not_before":    "2025-09-14T16:05:09Z",
		"not_after":     "2025-12-13T16:54:40Z",
		"serial_number": "18b68e9a192e38741260c04470b05367",
	}

	compact := certificateToCompact(cert)

	if compact.CN != "example.com" {
		t.Errorf("Expected CN 'example.com', got '%s'", compact.CN)
	}

	if len(compact.DNS) != 2 {
		t.Errorf("Expected 2 DNS names, got %d", len(compact.DNS))
	}

	if compact.Iss != "GTS_WR3" {
		t.Errorf("Expected issuer alias 'GTS_WR3', got '%s'", compact.Iss)
	}

	if compact.NB != "2025-09-14" {
		t.Errorf("Expected not_before '2025-09-14', got '%s'", compact.NB)
	}

	if compact.NA != "2025-12-13" {
		t.Errorf("Expected not_after '2025-12-13', got '%s'", compact.NA)
	}

	if compact.SN != "18b68e9a192e3874" {
		t.Errorf("Expected truncated serial '18b68e9a192e3874', got '%s'", compact.SN)
	}
}

func TestIssuerAliasing(t *testing.T) {
	tests := []struct {
		full  string
		alias string
	}{
		{"C=US, O=Google Trust Services, CN=WR3", "GTS_WR3"},
		{"C=US, O=Google Trust Services LLC, CN=GTS CA 1D4", "GTS_1D4"},
		{"C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3", "LE_X3"},
		{"C=US, O=Unknown CA, CN=Test", "C=US, O=Unknown CA, CN=Test"}, // No alias
	}

	for _, tt := range tests {
		alias := compactIssuer(tt.full)
		if alias != tt.alias {
			t.Errorf("compactIssuer('%s') = '%s', expected '%s'", tt.full, alias, tt.alias)
		}

		// Test expansion
		if tt.alias != tt.full { // Only if there's a real alias
			expanded := expandIssuer(alias)
			if expanded != tt.full {
				t.Errorf("expandIssuer('%s') = '%s', expected '%s'", alias, expanded, tt.full)
			}
		}
	}
}

func TestWriterV2_WriteArtifacts(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.v2.jsonl")

	writer := NewWriterV2(path, "example.com")
	writer.SetBaseTime(time.Date(2025, 10, 13, 19, 29, 44, 0, time.UTC))

	artifacts := []Artifact{
		{
			Type:      "domain",
			Value:     "example.com",
			Active:    false,
			Up:        true,
			Tool:      "crtsh",
			FirstSeen: "2025-10-13T19:29:44Z",
			LastSeen:  "2025-10-13T19:29:44Z",
		},
		{
			Type:      "route",
			Value:     "/api/v1/users",
			Active:    true,
			Up:        true,
			Tool:      "linkfinderevo",
			FirstSeen: "2025-10-13T19:30:00Z",
			LastSeen:  "2025-10-13T19:30:10Z",
		},
	}

	err := writer.WriteArtifacts(artifacts)
	if err != nil {
		t.Fatalf("WriteArtifacts failed: %v", err)
	}

	// Verificar que el archivo existe
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Fatalf("Output file was not created")
	}

	// Leer y verificar contenido
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("Failed to open output file: %v", err)
	}
	defer file.Close()

	reader, err := NewReaderV2(file)
	if err != nil {
		t.Fatalf("NewReaderV2 failed: %v", err)
	}

	header := reader.GetHeader()
	if header == nil {
		t.Fatal("Expected header")
	}

	if header.Schema != SchemaV2 {
		t.Errorf("Expected schema '%s', got '%s'", SchemaV2, header.Schema)
	}

	if header.Target != "example.com" {
		t.Errorf("Expected target 'example.com', got '%s'", header.Target)
	}

	// Leer artifacts
	readArtifacts, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}

	if len(readArtifacts) != len(artifacts) {
		t.Errorf("Expected %d artifacts, got %d", len(artifacts), len(readArtifacts))
	}
}

func TestTimestampCompaction(t *testing.T) {
	baseTime := time.Date(2025, 10, 13, 19, 29, 44, 0, time.UTC)

	// Test with same timestamps (should produce array of length 1)
	v1Same := Artifact{
		Type:      "domain",
		Value:     "example.com",
		FirstSeen: "2025-10-13T19:29:44Z",
		LastSeen:  "2025-10-13T19:29:44Z",
	}

	v2Same := ToV2(v1Same, baseTime)
	if len(v2Same.Ts) != 1 {
		t.Errorf("Expected 1 timestamp for same first/last, got %d", len(v2Same.Ts))
	}

	// Test with different timestamps (should produce array of length 2)
	v1Diff := Artifact{
		Type:      "domain",
		Value:     "example.com",
		FirstSeen: "2025-10-13T19:29:44Z",
		LastSeen:  "2025-10-13T19:30:44Z",
	}

	v2Diff := ToV2(v1Diff, baseTime)
	if len(v2Diff.Ts) != 2 {
		t.Errorf("Expected 2 timestamps for different first/last, got %d", len(v2Diff.Ts))
	}
	if v2Diff.Ts[0] != 0 {
		t.Errorf("Expected first timestamp 0, got %d", v2Diff.Ts[0])
	}
	if v2Diff.Ts[1] != 60000 {
		t.Errorf("Expected last timestamp 60000ms, got %d", v2Diff.Ts[1])
	}
}
