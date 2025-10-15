package pipeline

import (
	"net/url"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// InputSanitizer proporciona funciones de sanitización y validación de inputs.
// Protege contra inputs maliciosos o malformados de herramientas externas.
type InputSanitizer struct {
	maxInputLength  int
	maxURLLength    int
	allowedSchemes  map[string]bool
	dangerousChars  *regexp.Regexp
	controlChars    *regexp.Regexp
	unicodeSanitize bool
}

// NewInputSanitizer crea un nuevo sanitizador con configuración por defecto.
func NewInputSanitizer() *InputSanitizer {
	return &InputSanitizer{
		maxInputLength: 8192,  // 8KB max input
		maxURLLength:   2048,  // 2KB max URL
		allowedSchemes: map[string]bool{
			"http":  true,
			"https": true,
			"ftp":   true,
			"ftps":  true,
		},
		// Caracteres peligrosos que pueden indicar injection
		dangerousChars: regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`),
		// Control characters (excepto \t, \n, \r)
		controlChars:    regexp.MustCompile(`[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]`),
		unicodeSanitize: true,
	}
}

// SanitizeResult encapsula el resultado de una sanitización.
type SanitizeResult struct {
	Value    string
	Modified bool
	Valid    bool
	Reason   string
}

// SanitizeDomain sanitiza y valida un dominio.
func (s *InputSanitizer) SanitizeDomain(raw string) SanitizeResult {
	if raw == "" {
		return SanitizeResult{Valid: false, Reason: "empty input"}
	}

	// Verificar longitud
	if len(raw) > s.maxInputLength {
		return SanitizeResult{Valid: false, Reason: "input too long"}
	}

	original := raw
	value := strings.TrimSpace(raw)

	// Remover caracteres de control
	if s.controlChars.MatchString(value) {
		value = s.controlChars.ReplaceAllString(value, "")
	}

	// Sanitizar unicode si está habilitado
	if s.unicodeSanitize {
		value = s.sanitizeUnicode(value)
	}

	// Convertir a lowercase
	value = strings.ToLower(value)

	// Remover esquema si existe
	if strings.Contains(value, "://") {
		if u, err := url.Parse(value); err == nil && u.Host != "" {
			value = u.Host
		}
	}

	// Remover puerto
	if idx := strings.LastIndex(value, ":"); idx > 0 {
		port := value[idx+1:]
		// Solo remover si parece un puerto (números)
		if s.isNumeric(port) {
			value = value[:idx]
		}
	}

	// Remover path
	if idx := strings.Index(value, "/"); idx > 0 {
		value = value[:idx]
	}

	// Validar formato de dominio
	if !s.isValidDomain(value) {
		return SanitizeResult{
			Value:    value,
			Modified: original != value,
			Valid:    false,
			Reason:   "invalid domain format",
		}
	}

	return SanitizeResult{
		Value:    value,
		Modified: original != value,
		Valid:    true,
	}
}

// SanitizeURL sanitiza y valida una URL.
func (s *InputSanitizer) SanitizeURL(raw string) SanitizeResult {
	if raw == "" {
		return SanitizeResult{Valid: false, Reason: "empty input"}
	}

	// Verificar longitud
	if len(raw) > s.maxURLLength {
		return SanitizeResult{Valid: false, Reason: "URL too long"}
	}

	original := raw
	value := strings.TrimSpace(raw)

	// Remover caracteres peligrosos
	if s.dangerousChars.MatchString(value) {
		value = s.dangerousChars.ReplaceAllString(value, "")
	}

	// Sanitizar unicode
	if s.unicodeSanitize {
		value = s.sanitizeUnicode(value)
	}

	// Parsear URL
	u, err := url.Parse(value)
	if err != nil {
		return SanitizeResult{
			Value:    value,
			Modified: original != value,
			Valid:    false,
			Reason:   "invalid URL: " + err.Error(),
		}
	}

	// Validar esquema
	if u.Scheme != "" && !s.allowedSchemes[strings.ToLower(u.Scheme)] {
		return SanitizeResult{
			Value:    value,
			Modified: original != value,
			Valid:    false,
			Reason:   "disallowed scheme: " + u.Scheme,
		}
	}

	// Validar host
	if u.Host == "" {
		return SanitizeResult{
			Value:    value,
			Modified: original != value,
			Valid:    false,
			Reason:   "missing host",
		}
	}

	// Reconstruir URL sanitizada
	sanitized := u.String()

	return SanitizeResult{
		Value:    sanitized,
		Modified: original != sanitized,
		Valid:    true,
	}
}

// SanitizeCertificate sanitiza datos de certificado.
func (s *InputSanitizer) SanitizeCertificate(raw map[string]any) (map[string]any, bool) {
	if raw == nil {
		return nil, false
	}

	sanitized := make(map[string]any)

	// Sanitizar common_name
	if cn, ok := raw["common_name"].(string); ok {
		result := s.SanitizeDomain(cn)
		if result.Valid {
			sanitized["common_name"] = result.Value
		}
	}

	// Sanitizar dns_names
	if names, ok := raw["dns_names"].([]interface{}); ok {
		var sanitizedNames []string
		for _, name := range names {
			if nameStr, ok := name.(string); ok {
				result := s.SanitizeDomain(nameStr)
				if result.Valid {
					sanitizedNames = append(sanitizedNames, result.Value)
				}
			}
		}
		if len(sanitizedNames) > 0 {
			sanitized["dns_names"] = sanitizedNames
		}
	}

	// Copiar otros campos seguros (strings simples)
	safeFields := []string{"issuer", "not_before", "not_after", "serial_number"}
	for _, field := range safeFields {
		if val, ok := raw[field].(string); ok {
			// Sanitizar pero permitir el valor
			sanitized[field] = s.sanitizeString(val, 512)
		}
	}

	return sanitized, len(sanitized) > 0
}

// sanitizeString sanitiza un string genérico removiendo caracteres peligrosos.
func (s *InputSanitizer) sanitizeString(value string, maxLen int) string {
	if value == "" {
		return ""
	}

	// Truncar si es muy largo
	if len(value) > maxLen {
		value = value[:maxLen]
	}

	// Remover control characters
	if s.controlChars.MatchString(value) {
		value = s.controlChars.ReplaceAllString(value, "")
	}

	return strings.TrimSpace(value)
}

// sanitizeUnicode remueve o normaliza caracteres unicode peligrosos.
func (s *InputSanitizer) sanitizeUnicode(value string) string {
	if !utf8.ValidString(value) {
		// Remover bytes inválidos
		value = strings.ToValidUTF8(value, "")
	}

	// Remover caracteres unicode de control y dirección
	var builder strings.Builder
	for _, r := range value {
		// Permitir solo categorías seguras
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsSpace(r) ||
			unicode.IsPunct(r) || unicode.IsSymbol(r) {
			// Excluir rangos peligrosos
			if r < 0xFFF0 { // Excluir specials
				builder.WriteRune(r)
			}
		}
	}

	return builder.String()
}

// isValidDomain verifica si un string es un dominio válido.
func (s *InputSanitizer) isValidDomain(value string) bool {
	if value == "" {
		return false
	}

	// Longitud razonable
	if len(value) < 3 || len(value) > 253 {
		return false
	}

	// Debe contener al menos un punto
	if !strings.Contains(value, ".") {
		return false
	}

	// Validar labels
	labels := strings.Split(value, ".")
	if len(labels) < 2 {
		return false
	}

	for _, label := range labels {
		if !s.isValidDomainLabel(label) {
			return false
		}
	}

	return true
}

// isValidDomainLabel verifica si un label de dominio es válido.
func (s *InputSanitizer) isValidDomainLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}

	// No puede empezar o terminar con guión
	if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
		return false
	}

	// Solo letras, dígitos y guiones
	for _, r := range label {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' {
			return false
		}
	}

	return true
}

// isNumeric verifica si un string solo contiene dígitos.
func (s *InputSanitizer) isNumeric(str string) bool {
	for _, r := range str {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(str) > 0
}
