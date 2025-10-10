package errors

import (
	"errors"
	"strings"
	"testing"
)

func TestWithSuggestion(t *testing.T) {
	baseErr := errors.New("test error")
	err := WithSuggestion(baseErr, "try this instead")

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "test error") {
		t.Errorf("error message should contain base error, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "try this instead") {
		t.Errorf("error message should contain suggestion, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "💡 Sugerencia") {
		t.Errorf("error message should contain suggestion label, got: %s", errMsg)
	}
}

func TestWithContext(t *testing.T) {
	baseErr := errors.New("test error")
	err := WithContext(baseErr, "tool", "amass")
	err = WithContext(err, "timeout", "120s")

	errMsg := err.Error()
	if !strings.Contains(errMsg, "tool: amass") {
		t.Errorf("error message should contain context, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "timeout: 120s") {
		t.Errorf("error message should contain all context, got: %s", errMsg)
	}
}

func TestNewMissingBinaryError(t *testing.T) {
	err := NewMissingBinaryError("amass", "/usr/bin", "/usr/local/bin")

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "amass") {
		t.Errorf("error message should contain binary name, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "go run ./cmd/install-deps") {
		t.Errorf("error message should contain installation suggestion, got: %s", errMsg)
	}

	// Verificar que es el tipo correcto
	if !IsMissingBinary(err) {
		t.Error("IsMissingBinary should return true for missing binary error")
	}
}

func TestNewTimeoutError(t *testing.T) {
	err := NewTimeoutError("amass", 120, "took too long")

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "timeout") {
		t.Errorf("error message should contain 'timeout', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "120") {
		t.Errorf("error message should contain duration, got: %s", errMsg)
	}

	if !IsTimeout(err) {
		t.Error("IsTimeout should return true for timeout error")
	}
}

func TestNewInvalidOutputError(t *testing.T) {
	err := NewInvalidOutputError("subfinder", "not a valid domain", "123.456")

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "subfinder") {
		t.Errorf("error message should contain tool name, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "not a valid domain") {
		t.Errorf("error message should contain reason, got: %s", errMsg)
	}

	if !IsInvalidOutput(err) {
		t.Error("IsInvalidOutput should return true for invalid output error")
	}
}

func TestNewConfigurationError(t *testing.T) {
	err := NewConfigurationError("timeout", "-10", "must be positive", "use --timeout=120")

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "timeout") {
		t.Errorf("error message should contain field name, got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "use --timeout=120") {
		t.Errorf("error message should contain suggestion, got: %s", errMsg)
	}
}

func TestNewNetworkError(t *testing.T) {
	baseErr := errors.New("connection refused")
	err := NewNetworkError("fetch", "https://api.example.com", baseErr)

	if err == nil {
		t.Fatal("expected error, got nil")
	}

	errMsg := err.Error()
	if !strings.Contains(errMsg, "error de red") {
		t.Errorf("error message should contain 'error de red', got: %s", errMsg)
	}
	if !strings.Contains(errMsg, "fetch") {
		t.Errorf("error message should contain operation, got: %s", errMsg)
	}
}

func TestGetSuggestion(t *testing.T) {
	baseErr := errors.New("test error")
	err := WithSuggestion(baseErr, "my suggestion")

	suggestion := GetSuggestion(err)
	if suggestion != "my suggestion" {
		t.Errorf("expected 'my suggestion', got: %s", suggestion)
	}

	// Test con un error normal sin sugerencia
	normalErr := errors.New("normal error")
	suggestion2 := GetSuggestion(normalErr)
	if suggestion2 != "" {
		t.Errorf("expected empty suggestion for normal error, got: %s", suggestion2)
	}
}

func TestGetContext(t *testing.T) {
	baseErr := errors.New("test error")
	err := WithContext(baseErr, "key1", "value1")
	err = WithContext(err, "key2", "value2")

	ctx := GetContext(err)
	if ctx == nil {
		t.Fatal("expected context, got nil")
	}
	if ctx["key1"] != "value1" {
		t.Errorf("expected 'value1' for key1, got: %s", ctx["key1"])
	}
	if ctx["key2"] != "value2" {
		t.Errorf("expected 'value2' for key2, got: %s", ctx["key2"])
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input    string
		limit    int
		expected string
	}{
		{"short", 10, "short"},
		{"this is a very long string", 10, "this is..."},
		{"exactly10", 10, "exactly10"},
		{"", 5, ""},
	}

	for _, tt := range tests {
		result := truncate(tt.input, tt.limit)
		if result != tt.expected {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.limit, result, tt.expected)
		}
	}
}

func TestErrorUnwrap(t *testing.T) {
	baseErr := errors.New("base error")
	wrapped := WithSuggestion(baseErr, "some suggestion")

	unwrapped := errors.Unwrap(wrapped)
	if unwrapped != baseErr {
		t.Error("should be able to unwrap error")
	}

	if !errors.Is(wrapped, baseErr) {
		t.Error("errors.Is should work with wrapped errors")
	}
}
