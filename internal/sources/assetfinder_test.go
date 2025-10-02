package sources

import "testing"

func TestIsAssetfinderEmpty(t *testing.T) {
	cases := map[string]bool{
		"no assets were discovered":     true,
		"  no assets were discovered  ": true,
		"No Assets Were Discovered":     true,
		" assets were discovered":       false,
		"something else":                false,
		"":                              false,
	}

	for input, want := range cases {
		if got := isAssetfinderEmpty(input); got != want {
			t.Fatalf("isAssetfinderEmpty(%q) = %v, want %v", input, got, want)
		}
	}
}
