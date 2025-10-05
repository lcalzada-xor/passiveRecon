package netutil

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Scope represents the canonical domain boundaries for a scan.
type Scope struct {
	hostname    string
	registrable string
	ip          net.IP
}

// NewScope builds a Scope from the provided target. If the target cannot
// be normalised into a domain the returned scope is nil and no filtering
// will be enforced.
func NewScope(target string) *Scope {
	normalized := NormalizeDomain(target)
	if normalized == "" {
		return nil
	}

	if ip := net.ParseIP(normalized); ip != nil {
		return &Scope{hostname: normalized, ip: ip}
	}

	registrable := normalized
	if effective, err := publicsuffix.EffectiveTLDPlusOne(normalized); err == nil && effective != "" {
		registrable = strings.ToLower(effective)
	}

	return &Scope{
		hostname:    normalized,
		registrable: registrable,
	}
}

// AllowsDomain reports whether the provided domain falls within the
// configured scope. Domains outside of scope are rejected.
func (s *Scope) AllowsDomain(candidate string) bool {
	if s == nil {
		return true
	}

	normalized := NormalizeDomain(candidate)
	if normalized == "" {
		return false
	}

	if s.ip != nil {
		if net.ParseIP(normalized) == nil {
			return false
		}
		return normalized == s.hostname
	}

	if net.ParseIP(normalized) != nil {
		return false
	}

	if s.registrable == "" {
		return normalized == s.hostname
	}

	if normalized == s.hostname || normalized == s.registrable {
		return true
	}

	return strings.HasSuffix(normalized, "."+s.registrable)
}

// AllowsRoute reports whether the route belongs to the configured scope.
// Relative paths (no host) are always allowed. When the route contains a
// host, it must fall inside the scope boundaries.
func (s *Scope) AllowsRoute(route string) bool {
	if s == nil {
		return true
	}

	trimmed := strings.TrimSpace(route)
	if trimmed == "" {
		return false
	}

	if strings.HasPrefix(trimmed, "//") {
		if parsed, err := url.Parse("http:" + trimmed); err == nil {
			if host := parsed.Hostname(); host != "" {
				return s.AllowsDomain(host)
			}
		}
		host := strings.TrimPrefix(trimmed, "//")
		return s.AllowsDomain(host)
	}

	// Relative paths or fragments lack host information and are assumed to
	// belong to the current scope.
	switch trimmed[0] {
	case '/', '.', '#', '?':
		return true
	}

	if !strings.Contains(trimmed, "://") && !strings.HasPrefix(trimmed, "//") {
		// Non-schemed values (like bare domains) are treated as domains.
		return s.AllowsDomain(trimmed)
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		// Fall back to domain validation using the best-effort host guess.
		host := trimmed
		if idx := strings.Index(trimmed, "/"); idx != -1 {
			host = trimmed[:idx]
		}
		return s.AllowsDomain(host)
	}

	host := parsed.Hostname()
	if host == "" {
		return true
	}
	return s.AllowsDomain(host)
}
