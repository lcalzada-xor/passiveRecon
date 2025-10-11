package artifacts

import (
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CurrentSchemaVersion define la versión actual del schema de artifacts.
const CurrentSchemaVersion = "1.0"

// Artifact representa un hallazgo generado por el pipeline y serializado en el
// manifiesto JSONL.
type Artifact struct {
	Type        string         `json:"type"`
	Types       []string       `json:"types,omitempty"`
	Value       string         `json:"value"`
	Active      bool           `json:"active"`
	Up          bool           `json:"up"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	Tool        string         `json:"tool,omitempty"`
	Tools       []string       `json:"tools,omitempty"`
	Occurrences int            `json:"occurrences,omitempty"`
	FirstSeen   string         `json:"first_seen,omitempty"` // ISO 8601 timestamp
	LastSeen    string         `json:"last_seen,omitempty"`  // ISO 8601 timestamp
	Version     string         `json:"version,omitempty"`    // Schema version
}

// Key representa la identidad lógica de un artefacto normalizado.
type Key struct {
	Type   string
	Value  string
	Active bool
}

// Normalize limpia y consolida la información de un artefacto. Devuelve el
// artefacto normalizado junto con un indicador que señala si el proceso fue
// exitoso.
func Normalize(tool string, artifact Artifact) (Artifact, bool) {
	artifact.Type = strings.TrimSpace(artifact.Type)
	artifact.Value = strings.TrimSpace(artifact.Value)
	if artifact.Value == "" {
		return Artifact{}, false
	}

	primary, extras, ok := consolidateTypes(artifact.Type, artifact.Types...)
	if !ok {
		return Artifact{}, false
	}
	artifact.Type = primary
	artifact.Types = extras

	artifact.Metadata = normalizeMetadata(artifact.Metadata)
	artifact.Tool = strings.TrimSpace(artifact.Tool)
	if artifact.Tool == "" {
		artifact.Tool = strings.TrimSpace(tool)
	}
	artifact.Tools = nil
	artifact.Occurrences = 0

	// Establecer versión del schema si no está presente
	if artifact.Version == "" {
		artifact.Version = CurrentSchemaVersion
	}

	// Establecer timestamp de primera vista si no está presente
	if artifact.FirstSeen == "" {
		artifact.FirstSeen = time.Now().UTC().Format(time.RFC3339)
	}

	// Actualizar timestamp de última vista
	artifact.LastSeen = time.Now().UTC().Format(time.RFC3339)

	return artifact, true
}

// KeyFor devuelve la clave de deduplicación asociada al artefacto indicado.
func KeyFor(artifact Artifact) Key {
	category := keyCategory(artifact.Type)
	key := Key{
		Type:   category,
		Value:  strings.TrimSpace(artifact.Value),
		Active: artifact.Active,
	}
	if key.Type == "route" {
		if canonical := canonicalRouteKey(key.Value); canonical != "" {
			key.Value = canonical
		}
	}
	if key.Type == "" {
		key.Type = "?"
	}
	return key
}

// MergeMetadata fusiona los metadatos entrantes con los existentes en el
// artefacto destino respetando la semántica esperada para la clave "raw".
func MergeMetadata(dst *Artifact, metadata map[string]any) {
	if dst == nil || metadata == nil {
		return
	}
	if dst.Metadata == nil {
		dst.Metadata = make(map[string]any, len(metadata))
	}
	for key, value := range metadata {
		if key == "" || value == nil {
			continue
		}
		if key == "raw" {
			mergeRawMetadata(dst.Metadata, value)
			continue
		}
		if _, exists := dst.Metadata[key]; !exists {
			dst.Metadata[key] = value
		}
	}
}

// MergeTypes combina el tipo principal y los adicionales asegurando una vista
// coherente en el artefacto destino.
func MergeTypes(dst *Artifact, primary string, types []string) {
	if dst == nil {
		return
	}
	extras := append([]string{}, dst.Types...)
	extras = append(extras, primary)
	extras = append(extras, types...)
	normalizedPrimary, merged, ok := consolidateTypes(dst.Type, extras...)
	if !ok {
		dst.Type = ""
		dst.Types = nil
		return
	}
	dst.Type = normalizedPrimary
	dst.Types = merged
}

// ExtractRouteBase devuelve la forma normalizada de una ruta para efectos de
// deduplicación y comparación.
func ExtractRouteBase(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ""
	}
	if idx := strings.IndexAny(trimmed, " \t"); idx != -1 {
		trimmed = trimmed[:idx]
	}
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return ""
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	if u.Scheme == "" && u.Host == "" {
		return trimmed
	}

	if scheme := strings.ToLower(u.Scheme); scheme != "" {
		u.Scheme = scheme
	}

	if host := u.Hostname(); host != "" {
		hostname := strings.ToLower(host)
		port := u.Port()
		if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
			port = ""
		}
		normalizedHost := hostname
		if port != "" {
			normalizedHost = net.JoinHostPort(hostname, port)
		}
		if u.User != nil {
			normalizedHost = u.User.String() + "@" + normalizedHost
		}
		u.Host = normalizedHost
	}

	return strings.TrimSpace(u.String())
}

func canonicalRouteKey(value string) string {
	base := ExtractRouteBase(value)
	if base == "" {
		return ""
	}

	parsed, err := url.Parse(base)
	if err != nil || parsed == nil {
		trimmed := strings.TrimSpace(base)
		trimmed = strings.TrimPrefix(trimmed, "http://")
		trimmed = strings.TrimPrefix(trimmed, "https://")
		return trimmed
	}

	host := parsed.Hostname()
	if host == "" {
		trimmed := strings.TrimSpace(base)
		trimmed = strings.TrimPrefix(trimmed, "http://")
		trimmed = strings.TrimPrefix(trimmed, "https://")
		return trimmed
	}

	hostname := strings.ToLower(host)
	port := parsed.Port()
	if (parsed.Scheme == "http" && port == "80") || (parsed.Scheme == "https" && port == "443") {
		port = ""
	}

	normalizedHost := hostname
	if port != "" {
		normalizedHost = net.JoinHostPort(hostname, port)
	}
	if parsed.User != nil {
		normalizedHost = parsed.User.String() + "@" + normalizedHost
	}

	var builder strings.Builder
	builder.Grow(len(normalizedHost) + len(base))
	builder.WriteString(normalizedHost)

	path := parsed.EscapedPath()
	if path != "" && path != "/" {
		builder.WriteString(path)
	} else if path == "/" {
		builder.WriteString("/")
	}

	if parsed.RawQuery != "" {
		builder.WriteByte('?')
		builder.WriteString(parsed.RawQuery)
	}

	if parsed.Fragment != "" {
		builder.WriteByte('#')
		builder.WriteString(parsed.Fragment)
	}

	result := strings.TrimSpace(builder.String())
	if result == "" {
		return base
	}
	return result
}

func keyCategory(typ string) string {
	switch strings.TrimSpace(typ) {
	case "", "route", "html", "js", "image", "maps", "json", "api", "wasm", "svg", "crawl", "meta-route":
		return "route"
	default:
		return strings.TrimSpace(typ)
	}
}

func normalizeMetadata(metadata map[string]any) map[string]any {
	if len(metadata) == 0 {
		return nil
	}
	cleaned := make(map[string]any)
	for key, value := range metadata {
		key = strings.TrimSpace(key)
		if key == "" || value == nil {
			continue
		}
		cleaned[key] = value
	}
	if len(cleaned) == 0 {
		return nil
	}
	return cleaned
}

func consolidateTypes(primary string, extras ...string) (string, []string, bool) {
	typeSet := make(map[string]struct{})
	addType := func(value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			typeSet[value] = struct{}{}
		}
	}
	addType(primary)
	for _, value := range extras {
		addType(value)
	}
	if len(typeSet) == 0 {
		return "", nil, false
	}

	ordered := make([]string, 0, len(typeSet))
	for typ := range typeSet {
		ordered = append(ordered, typ)
	}
	sort.Strings(ordered)

	normalizedPrimary := strings.TrimSpace(primary)
	if normalizedPrimary == "" {
		normalizedPrimary = ordered[0]
	} else if _, ok := typeSet[normalizedPrimary]; !ok {
		normalizedPrimary = ordered[0]
	}

	extrasList := make([]string, 0, len(ordered)-1)
	for _, typ := range ordered {
		if typ == normalizedPrimary {
			continue
		}
		extrasList = append(extrasList, typ)
	}
	if len(extrasList) == 0 {
		extrasList = nil
	}
	return normalizedPrimary, extrasList, true
}

func mergeRawMetadata(target map[string]any, incoming any) {
	if target == nil || incoming == nil {
		return
	}

	addRaw := func(list []string, candidate string) []string {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			return list
		}
		for _, existing := range list {
			if existing == candidate {
				return list
			}
		}
		return append(list, candidate)
	}

	switch src := incoming.(type) {
	case string:
		if existing, ok := target["raw"]; ok {
			switch current := existing.(type) {
			case string:
				if strings.TrimSpace(current) == strings.TrimSpace(src) || strings.TrimSpace(src) == "" {
					return
				}
				target["raw"] = []string{strings.TrimSpace(current), strings.TrimSpace(src)}
			case []string:
				target["raw"] = addRaw(current, src)
			case []any:
				var list []string
				for _, candidate := range current {
					if s, ok := candidate.(string); ok {
						list = addRaw(list, s)
					}
				}
				target["raw"] = addRaw(list, src)
			default:
				target["raw"] = strings.TrimSpace(src)
			}
			return
		}
		trimmed := strings.TrimSpace(src)
		if trimmed != "" {
			target["raw"] = trimmed
		}
	case []string:
		var list []string
		if existing, ok := target["raw"]; ok {
			switch current := existing.(type) {
			case string:
				list = addRaw(list, current)
			case []string:
				list = append(list, current...)
			case []any:
				for _, candidate := range current {
					if s, ok := candidate.(string); ok {
						list = addRaw(list, s)
					}
				}
			}
		}
		for _, candidate := range src {
			list = addRaw(list, candidate)
		}
		if len(list) == 1 {
			target["raw"] = list[0]
		} else if len(list) > 1 {
			target["raw"] = list
		}
	case []any:
		var list []string
		if existing, ok := target["raw"]; ok {
			switch current := existing.(type) {
			case string:
				list = addRaw(list, current)
			case []string:
				list = append(list, current...)
			case []any:
				for _, candidate := range current {
					if s, ok := candidate.(string); ok {
						list = addRaw(list, s)
					}
				}
			}
		}
		for _, candidate := range src {
			if s, ok := candidate.(string); ok {
				list = addRaw(list, s)
			}
		}
		if len(list) == 1 {
			target["raw"] = list[0]
		} else if len(list) > 1 {
			target["raw"] = list
		}
	default:
		if _, ok := target["raw"]; !ok {
			target["raw"] = src
		}
	}
}
