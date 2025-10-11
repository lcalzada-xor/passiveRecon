package netutil

import (
	"net"
	"net/url"
	"strings"
)

// Scope representa los límites canónicos de un escaneo.
type Scope struct {
	hostname string // host normalizado tal cual lo dio el usuario (subdominios incluidos)
	ip       net.IP // si el objetivo es una IP
}

// NewScope construye un Scope desde el target dado. Si no se puede
// normalizar como dominio/IP válido, devuelve nil (sin filtrado).
func NewScope(target string) *Scope {
	normalized := NormalizeDomain(target)
	if normalized == "" {
		return nil
	}

	// Caso IP
	if ip := net.ParseIP(normalized); ip != nil {
		return &Scope{hostname: normalized, ip: ip}
	}

	// Caso dominio
	return &Scope{
		hostname: normalized,
	}
}

// AllowsDomain indica si el dominio proporcionado cae dentro del scope.
func (s *Scope) AllowsDomain(candidate string) bool {
	if s == nil {
		return true
	}

	normalized := NormalizeDomain(candidate)
	if normalized == "" {
		return false
	}

	// Si el scope es IP, solo aceptamos esa misma IP exacta.
	if s.ip != nil {
		// El candidato debe ser IP y coincidir exactamente.
		if net.ParseIP(normalized) == nil {
			return false
		}
		return normalized == s.hostname
	}

	// Si el scope es dominio, rechazamos IPs.
	if net.ParseIP(normalized) != nil {
		return false
	}

	// Coincidencia exacta con el hostname
	if normalized == s.hostname {
		return true
	}

	// Subdominios bajo el hostname (p. ej. si hostname es sub.example.com, permite a.sub.example.com)
	return strings.HasSuffix(normalized, "."+s.hostname)
}

// AllowsRoute indica si una ruta/URL pertenece al scope.
// Las rutas relativas (sin host) siempre están permitidas.
func (s *Scope) AllowsRoute(route string) bool {
	if s == nil {
		return true
	}

	trimmed := strings.TrimSpace(route)
	if trimmed == "" {
		return false
	}

	// URLs esquema-relativas: //host/path
	if strings.HasPrefix(trimmed, "//") {
		if parsed, err := url.Parse("http:" + trimmed); err == nil {
			if host := parsed.Hostname(); host != "" {
				return s.AllowsDomain(host)
			}
		}
		// Fallback conservador: quitar los dos slashes e intentar como dominio
		return s.AllowsDomain(strings.TrimPrefix(trimmed, "//"))
	}

	// Rutas/fragmentos relativos: pertenecen al scope actual
	switch trimmed[0] {
	case '/', '.', '#', '?':
		return true
	}

	// Valores sin esquema ni // (p. ej., "example.com" o "sub.example.com/path")
	// Si es un dominio "desnudo" lo tratamos como dominio; si trae path, NormalizeDomain lo resolverá.
	if !strings.Contains(trimmed, "://") {
		return s.AllowsDomain(trimmed)
	}

	// URLs absolutas con esquema
	parsed, err := url.Parse(trimmed)
	if err != nil {
		// Fallback robusto: delegar en AllowsDomain para extraer host con nuestra lógica
		return s.AllowsDomain(trimmed)
	}

	host := parsed.Hostname()
	if host == "" {
		// URLs como mailto:, javascript:, data:, etc., sin host: no salen del scope
		return true
	}
	return s.AllowsDomain(host)
}
