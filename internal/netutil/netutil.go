package netutil

import (
	"net"
	"net/url"
	"strings"
)

// NormalizeDomain extracts a canonical domain name from the provided line.
// It handles optional URL schemes, credentials, ports, IPv6 literals and
// strips wildcard entries. Subdomains are preserved, including common prefixes
// such as "www".
func NormalizeDomain(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "#") {
		return ""
	}
	if idx := strings.IndexAny(trimmed, " \t"); idx != -1 {
		trimmed = trimmed[:idx]
	}
	if trimmed == "" {
		return ""
	}

	candidate := trimmed
	var parsed *url.URL
	var err error
	if strings.Contains(candidate, "://") {
		parsed, err = url.Parse(candidate)
	} else {
		parsed, err = url.Parse("http://" + candidate)
	}
	if err == nil && parsed != nil {
		hostPort := parsed.Host
		hostname := parsed.Hostname()
		if hostname != "" && !(strings.Count(hostPort, ":") > 1 && !strings.Contains(hostPort, "[")) {
			candidate = hostname
		} else if hostPort != "" {
			candidate = hostPort
		}
	}

	if candidate == "" {
		return ""
	}

	if at := strings.LastIndex(candidate, "@"); at != -1 {
		candidate = candidate[at+1:]
	}

	if idx := strings.IndexAny(candidate, "/?#"); idx != -1 {
		candidate = candidate[:idx]
	}

	if candidate == "" {
		return ""
	}

	if host, _, err := net.SplitHostPort(candidate); err == nil {
		candidate = host
	}

	if strings.HasPrefix(candidate, "[") && strings.HasSuffix(candidate, "]") {
		candidate = strings.Trim(candidate, "[]")
	}

	lowered := strings.ToLower(candidate)

	if strings.Contains(lowered, "*") {
		return ""
	}

	if net.ParseIP(lowered) == nil && !strings.Contains(lowered, ".") {
		return ""
	}

	return lowered
}
