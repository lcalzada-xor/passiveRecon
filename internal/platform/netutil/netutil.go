package netutil

import (
	"net"
	"net/url"
	"strings"
)

// NormalizeDomain extrae un nombre de dominio canónico desde una línea dada.
// - Ignora líneas vacías, con comentarios (#...), o tokens tras espacios.
// - Acepta URLs con o sin esquema, con credenciales, puertos y literales IPv6.
// - Elimina brackets en IPv6 y puertos. Mantiene subdominios (incluido "www").
// - Rechaza comodines (*) y hostnames de una sola etiqueta que no sean IP.
// Devuelve el dominio en minúsculas o "" si no hay un dominio válido.
func NormalizeDomain(line string) string {
	// 1) Preliminares rápidos
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") {
		return ""
	}

	// Quedarnos solo con el primer token (antes de espacios/tabs)
	if i := strings.IndexAny(trimmed, " \t"); i >= 0 {
		trimmed = trimmed[:i]
	}
	if trimmed == "" {
		return ""
	}

	candidate := trimmed

	// 2) Parseo tipo URL (añadimos esquema si falta)
	var (
		parsed *url.URL
		err    error
	)
	if strings.Contains(candidate, "://") {
		parsed, err = url.Parse(candidate)
	} else {
		parsed, err = url.Parse("http://" + candidate)
	}
	if err == nil && parsed != nil {
		// url.URL ya quita credenciales en Hostname()
		// Si Hostname() es razonable (no es el caso de IPv6 sin brackets),
		// preferimos Hostname(); si no, usamos Host (para conservar literal).
		hostPort := parsed.Host
		hostname := parsed.Hostname()
		if hostname != "" && (strings.Count(hostPort, ":") <= 1 || strings.Contains(hostPort, "[")) {
			candidate = hostname
		} else if hostPort != "" {
			candidate = hostPort
		}
	}

	if candidate == "" {
		return ""
	}

	// 3) Limpiezas adicionales cuando el parseo previo no lo cubrió
	//    (credenciales y path/query/fragment por si venían en el input crudo)
	if at := strings.LastIndexByte(candidate, '@'); at >= 0 {
		candidate = candidate[at+1:]
	}
	if i := strings.IndexAny(candidate, "/?#"); i >= 0 {
		candidate = candidate[:i]
	}
	if candidate == "" {
		return ""
	}

	// 4) Quitar puerto si existe
	if host, _, err := net.SplitHostPort(candidate); err == nil {
		candidate = host
	}

	// 5) Quitar brackets de IPv6
	if strings.HasPrefix(candidate, "[") && strings.HasSuffix(candidate, "]") {
		candidate = strings.Trim(candidate, "[]")
	}

	// 6) Normalización final
	lowered := strings.ToLower(strings.TrimSuffix(candidate, ".")) // tolera FQDN con punto final

	// Reglas de filtrado finales
	if lowered == "" || strings.Contains(lowered, "*") {
		return ""
	}

	// Aceptar IPs tal cual
	if ip := net.ParseIP(lowered); ip != nil {
		return lowered
	}

	// Rechazar single-label hostnames no-IP (sin punto)
	if !strings.Contains(lowered, ".") {
		return ""
	}

	return lowered
}
