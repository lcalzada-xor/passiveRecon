package artifacts

import (
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCollectArtifactsByTypeMultiTypeRecords(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	artifact := Artifact{
		Type:   "route",
		Types:  []string{"html"},
		Value:  "https://app.example.com/login",
		Active: false,
		Up:     true,
	}

	path := filepath.Join(dir, "artifacts.jsonl")
	writeArtifactsFile(t, path, []Artifact{artifact})

	selectors := map[string]ActiveState{
		"route": PassiveOnly,
		"html":  PassiveOnly,
	}
	byType, err := CollectArtifactsByType(dir, selectors)
	if err != nil {
		t.Fatalf("CollectArtifactsByType: %v", err)
	}

	routeArtifacts := byType["route"]
	if len(routeArtifacts) != 1 {
		t.Fatalf("expected 1 route artifact, got %d", len(routeArtifacts))
	}
	htmlArtifacts := byType["html"]
	if len(htmlArtifacts) != 1 {
		t.Fatalf("expected 1 html artifact, got %d", len(htmlArtifacts))
	}

	if routeArtifacts[0].Type != "route" {
		t.Fatalf("expected route artifact type 'route', got %q", routeArtifacts[0].Type)
	}
	if htmlArtifacts[0].Type != "html" {
		t.Fatalf("expected html artifact type 'html', got %q", htmlArtifacts[0].Type)
	}

	routeTypes := routeArtifacts[0].Types
	if len(routeTypes) != 1 || routeTypes[0] != "html" {
		t.Fatalf("expected route artifact types to equal [html], got %v", routeTypes)
	}
	htmlTypes := htmlArtifacts[0].Types
	if len(htmlTypes) != 1 || htmlTypes[0] != "route" {
		t.Fatalf("expected html artifact types to equal [route], got %v", htmlTypes)
	}

	values, err := CollectValuesByType(dir, selectors)
	if err != nil {
		t.Fatalf("CollectValuesByType: %v", err)
	}
	wantValues := []string{"https://app.example.com/login"}
	if diff := cmp.Diff(wantValues, values["route"]); diff != "" {
		t.Fatalf("unexpected route values (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(wantValues, values["html"]); diff != "" {
		t.Fatalf("unexpected html values (-want +got):\n%s", diff)
	}
}

func writeArtifactsFile(t *testing.T, path string, artifacts []Artifact) {
	t.Helper()

	writer := NewWriterV2(path, "test.com")
	if err := writer.WriteArtifacts(artifacts); err != nil {
		t.Fatalf("WriteArtifacts(%q): %v", path, err)
	}
}
