// Package pipeline proporciona validación de outputs del pipeline de recon.
package pipeline

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"

	apperrors "passive-rec/internal/platform/errors"
)

// OutputValidator valida outputs de herramientas del pipeline.
type OutputValidator struct {
	strict bool
}

// NewOutputValidator crea un nuevo validador de outputs.
func NewOutputValidator(strict bool) *OutputValidator {
	return &OutputValidator{strict: strict}
}

// ValidationResult contiene el resultado de una validación.
type ValidationResult struct {
	Valid    bool
	Warnings []string
	Errors   []string
}

// IsValid retorna true si no hay errores (warnings están permitidos).
func (r *ValidationResult) IsValid() bool {
	return len(r.Errors) == 0
}

// HasWarnings retorna true si hay advertencias.
func (r *ValidationResult) HasWarnings() bool {
	return len(r.Warnings) > 0
}

// regex para validar dominios (simplificada pero funcional)
var domainRegex = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)

// ValidateDomain valida que una cadena sea un dominio válido.
func (v *OutputValidator) ValidateDomain(domain string) *ValidationResult {
	result := &ValidationResult{}

	domain = strings.TrimSpace(domain)
	if domain == "" {
		result.Errors = append(result.Errors, "dominio vacío")
		return result
	}

	// Eliminar protocolo si existe
	if strings.Contains(domain, "://") {
		result.Warnings = append(result.Warnings, "dominio contiene protocolo")
		domain = strings.Split(domain, "://")[1]
	}

	// Eliminar path si existe
	if strings.Contains(domain, "/") {
		parts := strings.Split(domain, "/")
		domain = parts[0]
		if len(parts) > 1 {
			result.Warnings = append(result.Warnings, "dominio contiene path")
		}
	}

	// Eliminar puerto si existe
	if strings.Contains(domain, ":") {
		host, port, err := net.SplitHostPort(domain)
		if err == nil {
			domain = host
			result.Warnings = append(result.Warnings, fmt.Sprintf("dominio contiene puerto: %s", port))
		}
	}

	// Validar longitud
	if len(domain) > 253 {
		result.Errors = append(result.Errors, "dominio demasiado largo (max 253 caracteres)")
		return result
	}

	// Validar con regex
	if !domainRegex.MatchString(domain) {
		result.Errors = append(result.Errors, "formato de dominio inválido")
		return result
	}

	// Validar que tenga al menos un punto (excepto localhost)
	if !strings.Contains(domain, ".") && domain != "localhost" {
		if v.strict {
			result.Errors = append(result.Errors, "dominio sin TLD")
		} else {
			result.Warnings = append(result.Warnings, "dominio sin TLD")
		}
	}

	// Validar IP addresses (son técnicamente válidas pero posiblemente no deseadas)
	if net.ParseIP(domain) != nil {
		result.Warnings = append(result.Warnings, "parece ser una dirección IP en lugar de un dominio")
	}

	result.Valid = len(result.Errors) == 0
	return result
}

// ValidateURL valida que una cadena sea una URL válida.
func (v *OutputValidator) ValidateURL(rawURL string) *ValidationResult {
	result := &ValidationResult{}

	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		result.Errors = append(result.Errors, "URL vacía")
		return result
	}

	// Parsear la URL
	parsed, err := url.Parse(rawURL)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("error parseando URL: %v", err))
		return result
	}

	// Validar que tenga scheme
	if parsed.Scheme == "" {
		if v.strict {
			result.Errors = append(result.Errors, "URL sin esquema (http/https)")
		} else {
			result.Warnings = append(result.Warnings, "URL sin esquema (http/https)")
		}
	} else if parsed.Scheme != "http" && parsed.Scheme != "https" {
		result.Warnings = append(result.Warnings, fmt.Sprintf("esquema inusual: %s", parsed.Scheme))
	}

	// Validar que tenga host
	if parsed.Host == "" {
		result.Errors = append(result.Errors, "URL sin host")
		return result
	}

	// Validar el host como dominio
	hostValidation := v.ValidateDomain(parsed.Host)
	if !hostValidation.IsValid() {
		for _, e := range hostValidation.Errors {
			result.Errors = append(result.Errors, fmt.Sprintf("host inválido: %s", e))
		}
	}
	result.Warnings = append(result.Warnings, hostValidation.Warnings...)

	result.Valid = len(result.Errors) == 0
	return result
}

// ValidateBatch valida un lote de outputs y retorna estadísticas.
type BatchValidationResult struct {
	Total       int
	Valid       int
	Invalid     int
	WithWarning int
	Errors      map[string]int // contador de tipos de error
}

// ValidateDomainBatch valida un batch de dominios.
func (v *OutputValidator) ValidateDomainBatch(domains []string, tool string) (*BatchValidationResult, error) {
	batch := &BatchValidationResult{
		Total:  len(domains),
		Errors: make(map[string]int),
	}

	for _, domain := range domains {
		result := v.ValidateDomain(domain)

		if result.IsValid() {
			batch.Valid++
			if result.HasWarnings() {
				batch.WithWarning++
			}
		} else {
			batch.Invalid++
			for _, err := range result.Errors {
				batch.Errors[err]++
			}
		}
	}

	// Si hay muchos inválidos, retornar error
	if v.strict && batch.Invalid > 0 {
		invalidPercent := float64(batch.Invalid) / float64(batch.Total) * 100
		if invalidPercent > 50 {
			return batch, apperrors.NewInvalidOutputError(
				tool,
				fmt.Sprintf("%.1f%% de los outputs son inválidos", invalidPercent),
				fmt.Sprintf("%d/%d dominios", batch.Invalid, batch.Total),
			)
		}
	}

	return batch, nil
}

// ValidateURLBatch valida un batch de URLs.
func (v *OutputValidator) ValidateURLBatch(urls []string, tool string) (*BatchValidationResult, error) {
	batch := &BatchValidationResult{
		Total:  len(urls),
		Errors: make(map[string]int),
	}

	for _, rawURL := range urls {
		result := v.ValidateURL(rawURL)

		if result.IsValid() {
			batch.Valid++
			if result.HasWarnings() {
				batch.WithWarning++
			}
		} else {
			batch.Invalid++
			for _, err := range result.Errors {
				batch.Errors[err]++
			}
		}
	}

	// Si hay muchos inválidos, retornar error
	if v.strict && batch.Invalid > 0 {
		invalidPercent := float64(batch.Invalid) / float64(batch.Total) * 100
		if invalidPercent > 50 {
			return batch, apperrors.NewInvalidOutputError(
				tool,
				fmt.Sprintf("%.1f%% de los outputs son inválidos", invalidPercent),
				fmt.Sprintf("%d/%d URLs", batch.Invalid, batch.Total),
			)
		}
	}

	return batch, nil
}

// ValidateOutput es un helper que detecta automáticamente el tipo y valida.
func (v *OutputValidator) ValidateOutput(output, tool string) (*ValidationResult, error) {
	output = strings.TrimSpace(output)
	if output == "" {
		return &ValidationResult{
			Valid:  false,
			Errors: []string{"output vacío"},
		}, nil
	}

	// Detectar si es URL o dominio
	if strings.HasPrefix(output, "http://") || strings.HasPrefix(output, "https://") {
		return v.ValidateURL(output), nil
	}

	// Por defecto, tratar como dominio
	return v.ValidateDomain(output), nil
}

// SanitizeDomain intenta limpiar un dominio para que sea válido.
func SanitizeDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain)

	// Eliminar protocolo
	if strings.Contains(domain, "://") {
		parts := strings.Split(domain, "://")
		if len(parts) > 1 {
			domain = parts[1]
		}
	}

	// Eliminar path
	if strings.Contains(domain, "/") {
		domain = strings.Split(domain, "/")[0]
	}

	// Eliminar puerto
	if strings.Contains(domain, ":") {
		host, _, err := net.SplitHostPort(domain)
		if err == nil {
			domain = host
		}
	}

	// Eliminar espacios y caracteres de control
	domain = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, domain)

	return domain
}

// SanitizeURL intenta limpiar una URL para que sea válida.
func SanitizeURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)

	// Eliminar espacios y caracteres de control
	rawURL = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 {
			return -1
		}
		return r
	}, rawURL)

	// Si no tiene esquema, asumir https
	if !strings.Contains(rawURL, "://") {
		rawURL = "https://" + rawURL
	}

	return rawURL
}
