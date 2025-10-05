package sources

import "testing"

func TestClassifyLinkfinderEndpoint(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantJS     bool
		wantHTML   bool
		undetected bool
	}{
		{name: "javascript absolute", input: "https://example.com/app/main.js", wantJS: true},
		{name: "html absolute", input: "https://example.com/index.html", wantHTML: true},
		{name: "relative path", input: "api/v1/users", undetected: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyLinkfinderEndpoint(tt.input)
			if got.isJS != tt.wantJS {
				t.Fatalf("isJS mismatch: got %v want %v", got.isJS, tt.wantJS)
			}
			if got.isHTML != tt.wantHTML {
				t.Fatalf("isHTML mismatch: got %v want %v", got.isHTML, tt.wantHTML)
			}
			if got.undetected != tt.undetected {
				t.Fatalf("undetected mismatch: got %v want %v", got.undetected, tt.undetected)
			}
		})
	}
}

func TestNormalizeScope(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "example.com", want: "example.com"},
		{input: "https://sub.example.com", want: "sub.example.com"},
		{input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := normalizeScope(tt.input); got != tt.want {
				t.Fatalf("normalizeScope(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
