package pipeline

import (
	"strings"
	"testing"
)

func TestValidateDomain(t *testing.T) {
	validator := NewOutputValidator(false)

	tests := []struct {
		name      string
		domain    string
		wantValid bool
		wantWarn  bool
	}{
		{"valid simple", "example.com", true, false},
		{"valid subdomain", "sub.example.com", true, false},
		{"valid multi-level", "deep.sub.example.com", true, false},
		{"with protocol", "https://example.com", true, true},
		{"with path", "example.com/path", true, true},
		{"with port", "example.com:443", true, true},
		{"empty", "", false, false},
		{"invalid chars", "exam ple.com", false, false},
		{"too long label", strings.Repeat("a", 64) + ".com", false, false},
		{"ip address", "192.168.1.1", true, true},
		{"localhost", "localhost", true, false},
		{"single label", "example", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateDomain(tt.domain)
			if result.IsValid() != tt.wantValid {
				t.Errorf("ValidateDomain(%q).IsValid() = %v, want %v (errors: %v)",
					tt.domain, result.IsValid(), tt.wantValid, result.Errors)
			}
			if result.HasWarnings() != tt.wantWarn {
				t.Errorf("ValidateDomain(%q).HasWarnings() = %v, want %v (warnings: %v)",
					tt.domain, result.HasWarnings(), tt.wantWarn, result.Warnings)
			}
		})
	}
}

func TestValidateURL(t *testing.T) {
	validator := NewOutputValidator(false)

	tests := []struct {
		name      string
		url       string
		wantValid bool
		wantWarn  bool
	}{
		{"valid http", "http://example.com", true, false},
		{"valid https", "https://example.com/path", true, false},
		{"valid with port", "https://example.com:8080/api", true, true}, // puerto genera warning
		{"valid with query", "https://api.example.com?key=value", true, false},
		{"no scheme", "example.com/path", false, true}, // sin esquema es inválido
		{"empty", "", false, false},
		{"invalid host", "https://", false, false},
		{"unusual scheme", "ftp://example.com", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.ValidateURL(tt.url)
			if result.IsValid() != tt.wantValid {
				t.Errorf("ValidateURL(%q).IsValid() = %v, want %v (errors: %v)",
					tt.url, result.IsValid(), tt.wantValid, result.Errors)
			}
			if result.HasWarnings() != tt.wantWarn {
				t.Errorf("ValidateURL(%q).HasWarnings() = %v, want %v (warnings: %v)",
					tt.url, result.HasWarnings(), tt.wantWarn, result.Warnings)
			}
		})
	}
}

func TestValidateDomainBatch(t *testing.T) {
	validator := NewOutputValidator(false)

	domains := []string{
		"example.com",
		"sub.example.com",
		"another.com",
		"invalid domain",
		"",
	}

	result, err := validator.ValidateDomainBatch(domains, "test-tool")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Total != 5 {
		t.Errorf("expected total=5, got %d", result.Total)
	}
	if result.Valid != 3 {
		t.Errorf("expected valid=3, got %d", result.Valid)
	}
	if result.Invalid != 2 {
		t.Errorf("expected invalid=2, got %d", result.Invalid)
	}
}

func TestValidateURLBatch(t *testing.T) {
	validator := NewOutputValidator(false)

	urls := []string{
		"https://example.com",
		"http://api.example.com/v1",
		"https://sub.example.com:8080",
		"not a url",
		"",
	}

	result, err := validator.ValidateURLBatch(urls, "test-tool")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Total != 5 {
		t.Errorf("expected total=5, got %d", result.Total)
	}
	if result.Valid != 3 {
		t.Errorf("expected valid=3, got %d", result.Valid)
	}
	if result.Invalid != 2 {
		t.Errorf("expected invalid=2, got %d", result.Invalid)
	}
}

func TestValidateBatchStrict(t *testing.T) {
	validator := NewOutputValidator(true)

	// Crear un batch con >50% inválidos
	domains := []string{
		"valid.com",
		"invalid domain",
		"another invalid",
		"",
	}

	result, err := validator.ValidateDomainBatch(domains, "test-tool")
	if err == nil {
		t.Error("expected error for batch with >50% invalid in strict mode")
	}
	if result == nil {
		t.Fatal("expected result even with error")
	}
	if result.Invalid <= result.Valid {
		t.Error("expected more invalid than valid")
	}
}

func TestSanitizeDomain(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"EXAMPLE.COM", "example.com"},
		{"https://example.com", "example.com"},
		{"example.com/path", "example.com"},
		{"example.com:8080", "example.com"},
		{"  example.com  ", "example.com"},
		{"https://example.com:8080/path", "example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := SanitizeDomain(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeDomain(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"https://example.com", "https://example.com"},
		{"  https://example.com  ", "https://example.com"},
		{"example.com", "https://example.com"},
		{"http://example.com/path", "http://example.com/path"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := SanitizeURL(tt.input)
			if result != tt.expected {
				t.Errorf("SanitizeURL(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestValidateOutput(t *testing.T) {
	validator := NewOutputValidator(false)

	tests := []struct {
		name      string
		output    string
		tool      string
		wantValid bool
	}{
		{"domain", "example.com", "subfinder", true},
		{"url", "https://example.com", "waybackurls", true},
		{"empty", "", "test", false},
		{"invalid", "not a valid domain or url!", "test", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := validator.ValidateOutput(tt.output, tt.tool)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.IsValid() != tt.wantValid {
				t.Errorf("ValidateOutput(%q) = %v, want %v", tt.output, result.IsValid(), tt.wantValid)
			}
		})
	}
}

func TestValidatorStrictMode(t *testing.T) {
	strictValidator := NewOutputValidator(true)
	lenientValidator := NewOutputValidator(false)

	// Dominio sin TLD
	domain := "example"

	strictResult := strictValidator.ValidateDomain(domain)
	lenientResult := lenientValidator.ValidateDomain(domain)

	// En modo strict, debería ser un error
	if strictResult.IsValid() {
		t.Error("strict validator should reject domain without TLD")
	}

	// En modo lenient, debería ser solo una advertencia
	if !lenientResult.IsValid() {
		t.Error("lenient validator should accept domain without TLD (with warning)")
	}
	if !lenientResult.HasWarnings() {
		t.Error("lenient validator should have warning for domain without TLD")
	}
}
