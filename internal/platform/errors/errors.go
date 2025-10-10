// Package errors proporciona tipos de error mejorados con contexto y sugerencias
// para facilitar el debugging y mejorar la experiencia del usuario.
package errors

import (
	"errors"
	"fmt"
	"strings"
)

// ErrorWithSuggestion es un error que incluye una sugerencia para el usuario.
type ErrorWithSuggestion struct {
	Err        error
	Suggestion string
	Context    map[string]string
}

func (e *ErrorWithSuggestion) Error() string {
	var b strings.Builder
	b.WriteString(e.Err.Error())
	if e.Suggestion != "" {
		b.WriteString("\n\n💡 Sugerencia: ")
		b.WriteString(e.Suggestion)
	}
	if len(e.Context) > 0 {
		b.WriteString("\n\nContexto:")
		for k, v := range e.Context {
			fmt.Fprintf(&b, "\n  • %s: %s", k, v)
		}
	}
	return b.String()
}

func (e *ErrorWithSuggestion) Unwrap() error {
	return e.Err
}

// WithSuggestion envuelve un error con una sugerencia para el usuario.
func WithSuggestion(err error, suggestion string) error {
	if err == nil {
		return nil
	}
	return &ErrorWithSuggestion{
		Err:        err,
		Suggestion: suggestion,
		Context:    make(map[string]string),
	}
}

// WithContext añade contexto adicional a un error.
func WithContext(err error, key, value string) error {
	if err == nil {
		return nil
	}

	// Si ya es un ErrorWithSuggestion, añadir el contexto
	var suggErr *ErrorWithSuggestion
	if errors.As(err, &suggErr) {
		if suggErr.Context == nil {
			suggErr.Context = make(map[string]string)
		}
		suggErr.Context[key] = value
		return suggErr
	}

	// Crear un nuevo error con contexto
	newErr := &ErrorWithSuggestion{
		Err:     err,
		Context: map[string]string{key: value},
	}
	return newErr
}

// MissingBinaryError representa el error cuando un binario no está disponible.
type MissingBinaryError struct {
	Binary      string
	SearchPaths []string
}

func (e *MissingBinaryError) Error() string {
	return fmt.Sprintf("'%s' no encontrado en PATH", e.Binary)
}

// NewMissingBinaryError crea un error mejorado para binarios faltantes.
func NewMissingBinaryError(binary string, searchPaths ...string) error {
	baseErr := &MissingBinaryError{
		Binary:      binary,
		SearchPaths: searchPaths,
	}

	suggestion := fmt.Sprintf("Instálalo con: go run ./cmd/install-deps\n"+
		"O verifica que esté en tu PATH: which %s", binary)

	err := WithSuggestion(baseErr, suggestion)
	err = WithContext(err, "binary", binary)

	if len(searchPaths) > 0 {
		err = WithContext(err, "searched_paths", strings.Join(searchPaths, ", "))
	}

	return err
}

// TimeoutError representa un error de timeout con información adicional.
type TimeoutError struct {
	Tool     string
	Duration int
	Reason   string
}

func (e *TimeoutError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("timeout después de %ds: %s", e.Duration, e.Reason)
	}
	return fmt.Sprintf("timeout después de %ds", e.Duration)
}

// NewTimeoutError crea un error mejorado para timeouts.
func NewTimeoutError(tool string, duration int, reason string) error {
	baseErr := &TimeoutError{
		Tool:     tool,
		Duration: duration,
		Reason:   reason,
	}

	suggestion := fmt.Sprintf("Intenta aumentar el timeout con: --timeout=%d\n"+
		"O ejecuta solo esta herramienta con: --tools=%s",
		duration+60, tool)

	err := WithSuggestion(baseErr, suggestion)
	err = WithContext(err, "tool", tool)
	err = WithContext(err, "timeout_seconds", fmt.Sprintf("%d", duration))

	return err
}

// InvalidOutputError representa un error cuando el output es inválido.
type InvalidOutputError struct {
	Tool   string
	Reason string
	Sample string
}

func (e *InvalidOutputError) Error() string {
	msg := fmt.Sprintf("output inválido de %s: %s", e.Tool, e.Reason)
	if e.Sample != "" {
		msg += fmt.Sprintf(" (muestra: %q)", truncate(e.Sample, 50))
	}
	return msg
}

// NewInvalidOutputError crea un error mejorado para outputs inválidos.
func NewInvalidOutputError(tool, reason, sample string) error {
	baseErr := &InvalidOutputError{
		Tool:   tool,
		Reason: reason,
		Sample: sample,
	}

	suggestion := "Verifica que la herramienta esté actualizada: go run ./cmd/install-deps\n" +
		"Si el problema persiste, reporta un issue en GitHub"

	err := WithSuggestion(baseErr, suggestion)
	err = WithContext(err, "tool", tool)

	return err
}

// ConfigurationError representa un error de configuración.
type ConfigurationError struct {
	Field  string
	Value  string
	Reason string
}

func (e *ConfigurationError) Error() string {
	return fmt.Sprintf("configuración inválida para '%s': %s", e.Field, e.Reason)
}

// NewConfigurationError crea un error mejorado para problemas de configuración.
func NewConfigurationError(field, value, reason, suggestion string) error {
	baseErr := &ConfigurationError{
		Field:  field,
		Value:  value,
		Reason: reason,
	}

	err := WithSuggestion(baseErr, suggestion)
	err = WithContext(err, "field", field)
	if value != "" {
		err = WithContext(err, "value", value)
	}

	return err
}

// NetworkError representa un error de red con información adicional.
type NetworkError struct {
	Operation string
	URL       string
	Err       error
}

func (e *NetworkError) Error() string {
	return fmt.Sprintf("error de red durante %s: %v", e.Operation, e.Err)
}

func (e *NetworkError) Unwrap() error {
	return e.Err
}

// NewNetworkError crea un error mejorado para problemas de red.
func NewNetworkError(operation, url string, err error) error {
	baseErr := &NetworkError{
		Operation: operation,
		URL:       url,
		Err:       err,
	}

	suggestion := "Verifica tu conexión a internet\n" +
		"Si usas un proxy, verifica la configuración con: --proxy=http://..."

	wrappedErr := WithSuggestion(baseErr, suggestion)
	wrappedErr = WithContext(wrappedErr, "operation", operation)
	if url != "" {
		wrappedErr = WithContext(wrappedErr, "url", truncate(url, 100))
	}

	return wrappedErr
}

// truncate limita una cadena a n caracteres, añadiendo "..." si es necesario.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

// GetSuggestion extrae la sugerencia de un error si existe.
func GetSuggestion(err error) string {
	var suggErr *ErrorWithSuggestion
	if errors.As(err, &suggErr) {
		return suggErr.Suggestion
	}
	return ""
}

// GetContext extrae el contexto de un error si existe.
func GetContext(err error) map[string]string {
	var suggErr *ErrorWithSuggestion
	if errors.As(err, &suggErr) {
		return suggErr.Context
	}
	return nil
}

// IsMissingBinary verifica si un error es por un binario faltante.
func IsMissingBinary(err error) bool {
	var missingErr *MissingBinaryError
	return errors.As(err, &missingErr)
}

// IsTimeout verifica si un error es por timeout.
func IsTimeout(err error) bool {
	var timeoutErr *TimeoutError
	return errors.As(err, &timeoutErr)
}

// IsInvalidOutput verifica si un error es por output inválido.
func IsInvalidOutput(err error) bool {
	var invalidErr *InvalidOutputError
	return errors.As(err, &invalidErr)
}
