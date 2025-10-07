package artifacts

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"passive-rec/internal/pipeline"
)

func TestCollectArtifactsByTypeMultiTypeRecords(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	artifact := pipeline.Artifact{
		Type:   "route",
		Types:  []string{"route", "html"},
		Value:  "https://app.example.com/login",
		Active: false,
	}

	path := filepath.Join(dir, "artifacts.jsonl")
	writeArtifactsFile(t, path, []pipeline.Artifact{artifact})

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

	for _, art := range []*pipeline.Artifact{&routeArtifacts[0], &htmlArtifacts[0]} {
		if len(art.Types) != 2 {
			t.Fatalf("expected two types, got %v", art.Types)
		}
		if !hasType(art.Types, "route") || !hasType(art.Types, "html") {
			t.Fatalf("expected artifact types to include route and html, got %v", art.Types)
		}
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

func writeArtifactsFile(t *testing.T, path string, artifacts []pipeline.Artifact) {
	t.Helper()

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("Create(%q): %v", path, err)
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	for _, artifact := range artifacts {
		if err := encoder.Encode(artifact); err != nil {
			t.Fatalf("Encode artifact: %v", err)
		}
	}
}

func hasType(types []string, typ string) bool {
	if typ == "" {
		return false
	}
	for _, candidate := range types {
		if candidate == typ {
			return true
		}
	}
	return false
}
