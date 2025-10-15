package artifacts

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strings"
	"time"
)

// CurrentSchemaVersion define la versión actual del schema de artifacts (interno, se mapea a v2.0 en disco).
const CurrentSchemaVersion = "1.0"

// Schema v2.0 - Formato compacto y optimizado para escalabilidad

const (
	// SchemaV2 es la versión del nuevo formato
	SchemaV2 = "2.0"

	// Estados posibles en el formato v2
	StateInactiveDown = "down"
	StateInactiveUp   = "up"
	StateActiveDown   = "active_down"
	StateActiveUp     = "active_up"
)

// Artifact representa un hallazgo generado por el pipeline (formato interno v1).
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

// HeaderV2 representa la primera línea del archivo artifacts v2.
// Contiene metadata global del scan y configuración.
type HeaderV2 struct {
	Schema  string            `json:"$"`                 // Schema version (always "2.0")
	Created int64             `json:"@"`                 // Unix timestamp (epoch seconds)
	Target  string            `json:"target"`            // Target domain/IP
	Tools   []string          `json:"tools,omitempty"`   // Catálogo de tools usadas (opcional)
	Aliases map[string]string `json:"aliases,omitempty"` // Aliases para valores comunes (opcional)
}

// ArtifactV2 representa un hallazgo en formato v2 (compacto).
type ArtifactV2 struct {
	T   string         `json:"t"`             // Type (domain, certificate, route, etc.)
	V   interface{}    `json:"v"`             // Value (string o object según tipo)
	St  string         `json:"st"`            // State (up, down, active_up, active_down)
	Tl  string         `json:"tl,omitempty"`  // Tool name (primary)
	Tls []string       `json:"tls,omitempty"` // Tools array (all tools that found this artifact)
	N   int            `json:"n,omitempty"`   // Occurrences count
	Ts  []int64        `json:"ts,omitempty"`  // Timestamps relativos en milisegundos [first_seen] o [first_seen, last_seen]
	Ty  []string       `json:"ty,omitempty"`  // Secondary types (opcional)
	M   map[string]any `json:"m,omitempty"`   // Metadata adicional (opcional)
}

// CertificateV2 representa un certificado SSL/TLS en formato compacto.
type CertificateV2 struct {
	CN  string   `json:"cn"`               // Common Name
	DNS []string `json:"dns,omitempty"`    // DNS Names
	Iss string   `json:"iss"`              // Issuer (puede ser alias o completo)
	NB  string   `json:"nb"`               // Not Before (formato: YYYY-MM-DD o full timestamp)
	NA  string   `json:"na"`               // Not After
	SN  string   `json:"sn"`               // Serial Number (truncado a 16 chars si es muy largo)
	Src string   `json:"source,omitempty"` // Source (opcional)
}

// GFFindingV2 representa un hallazgo de gf/pattern matching en formato compacto.
type GFFindingV2 struct {
	Res string   `json:"res"`           // Resource (URL)
	Ev  string   `json:"ev"`            // Evidence
	L   int      `json:"l,omitempty"`   // Line number
	Ctx string   `json:"ctx,omitempty"` // Context (opcional, puede omitirse si es muy largo)
	R   []string `json:"r,omitempty"`   // Rules matched
}

// ToV2 convierte un Artifact v1 a ArtifactV2 (formato compacto).
func ToV2(v1 Artifact, baseTime time.Time) ArtifactV2 {
	v2 := ArtifactV2{
		T:   v1.Type,
		Tl:  v1.Tool,
		Tls: v1.Tools,
		N:   v1.Occurrences,
		Ty:  v1.Types,
		M:   v1.Metadata,
	}

	// Convertir estado
	v2.St = stateToV2(v1.Active, v1.Up)

	// Convertir value según el tipo
	v2.V = convertValueToV2(v1.Type, v1.Value, v1.Metadata)

	// Convertir timestamps a relativos (milisegundos desde baseTime)
	v2.Ts = timestampsToRelative(v1.FirstSeen, v1.LastSeen, baseTime)

	// Limpiar metadata redundante
	v2.M = cleanMetadataForV2(v2.M, v1.Type)

	return v2
}

// ToV1 convierte un ArtifactV2 a Artifact v1 (retrocompatibilidad).
func ToV1(v2 ArtifactV2, baseTime time.Time) Artifact {
	v1 := Artifact{
		Type:        v2.T,
		Types:       v2.Ty,
		Tool:        v2.Tl,
		Tools:       v2.Tls,
		Occurrences: v2.N,
		Metadata:    v2.M,
		Version:     CurrentSchemaVersion,
	}

	// Convertir estado
	v1.Active, v1.Up = stateFromV2(v2.St)

	// Convertir value
	v1.Value = convertValueToV1(v2.V)

	// Convertir timestamps
	v1.FirstSeen, v1.LastSeen = timestampsFromRelative(v2.Ts, baseTime)

	// Reconstruir tools array si no hay Tls pero sí Tool
	if len(v1.Tools) == 0 && v1.Tool != "" {
		v1.Tools = []string{v1.Tool}
	}

	return v1
}

// stateToV2 convierte los flags active/up a un estado compacto.
func stateToV2(active, up bool) string {
	switch {
	case active && up:
		return StateActiveUp
	case active && !up:
		return StateActiveDown
	case !active && up:
		return StateInactiveUp
	default:
		return StateInactiveDown
	}
}

// stateFromV2 extrae los flags active/up desde un estado v2.
func stateFromV2(state string) (active, up bool) {
	switch state {
	case StateActiveUp:
		return true, true
	case StateActiveDown:
		return true, false
	case StateInactiveUp:
		return false, true
	case StateInactiveDown:
		return false, false
	default:
		return false, true // Default: inactive, up
	}
}

// convertValueToV2 optimiza el campo value según el tipo de artefacto.
func convertValueToV2(typ, value string, metadata map[string]any) interface{} {
	switch typ {
	case "certificate":
		// Parsear el JSON del certificado y compactarlo
		var cert map[string]any
		if err := json.Unmarshal([]byte(value), &cert); err == nil {
			return certificateToCompact(cert)
		}
		return value

	case "gfFinding":
		// Extraer información del metadata para crear GFFindingV2
		if metadata != nil {
			return gfFindingToCompact(value, metadata)
		}
		return value

	default:
		return value
	}
}

// convertValueToV1 convierte un value v2 a string v1.
func convertValueToV1(value interface{}) string {
	switch v := value.(type) {
	case string:
		return v
	case map[string]interface{}:
		// Verificar si es un certificado compacto y expandirlo
		if isCompactCertificate(v) {
			expanded := certificateFromCompact(v)
			if data, err := json.Marshal(expanded); err == nil {
				return string(data)
			}
		}
		// Verificar si es un gfFinding compacto y reconstruir string original
		if isCompactGFFinding(v) {
			return gfFindingFromCompact(v)
		}
		// Si es un objeto, serializarlo como JSON
		if data, err := json.Marshal(v); err == nil {
			return string(data)
		}
		return ""
	default:
		if data, err := json.Marshal(v); err == nil {
			return string(data)
		}
		return ""
	}
}

// isCompactGFFinding verifica si un map es un gfFinding en formato v2.
func isCompactGFFinding(m map[string]interface{}) bool {
	_, hasRes := m["res"]
	_, hasEv := m["ev"]
	return hasRes && hasEv
}

// gfFindingFromCompact reconstruye el value string original de un gfFinding.
func gfFindingFromCompact(compact map[string]interface{}) string {
	var builder strings.Builder

	// Agregar resource
	if res, ok := compact["res"].(string); ok && res != "" {
		builder.WriteString(res)
	}

	// Agregar line number
	if line, ok := compact["l"].(float64); ok && line > 0 {
		if builder.Len() > 0 {
			builder.WriteString(":")
		}
		builder.WriteString(fmt.Sprintf("#%d", int(line)))
	}

	// Agregar evidence
	if ev, ok := compact["ev"].(string); ok && ev != "" {
		if builder.Len() > 0 {
			builder.WriteString(" -> ")
		}
		builder.WriteString(ev)
	}

	return builder.String()
}

// isCompactCertificate verifica si un map es un certificado en formato v2.
func isCompactCertificate(m map[string]interface{}) bool {
	// Un certificado v2 tiene campos "cn", "iss", "nb", "na", "sn"
	_, hasCN := m["cn"]
	_, hasIss := m["iss"]
	return hasCN && hasIss
}

// certificateFromCompact expande un certificado compacto v2 a formato v1.
func certificateFromCompact(compact map[string]interface{}) map[string]interface{} {
	expanded := make(map[string]interface{})

	if cn, ok := compact["cn"].(string); ok {
		expanded["common_name"] = cn
	}

	if dns, ok := compact["dns"].([]interface{}); ok {
		expanded["dns_names"] = dns
	}

	if iss, ok := compact["iss"].(string); ok {
		expanded["issuer"] = expandIssuer(iss)
	}

	if nb, ok := compact["nb"].(string); ok {
		expanded["not_before"] = expandDate(nb)
	}

	if na, ok := compact["na"].(string); ok {
		expanded["not_after"] = expandDate(na)
	}

	if sn, ok := compact["sn"].(string); ok {
		expanded["serial_number"] = sn
	}

	// Copiar source si existe
	if source, ok := compact["source"].(string); ok {
		expanded["source"] = source
	}

	return expanded
}

// expandDate expande una fecha compacta (YYYY-MM-DD) a timestamp completo.
func expandDate(date string) string {
	// Si ya es un timestamp completo, devolverlo tal cual
	if len(date) > 10 {
		return date
	}
	// Si es solo fecha, agregar la hora
	return date + "T00:00:00Z"
}

// certificateToCompact convierte un certificado a formato compacto.
func certificateToCompact(cert map[string]any) CertificateV2 {
	compact := CertificateV2{}

	if cn, ok := cert["common_name"].(string); ok {
		compact.CN = cn
	}

	if dnsNames, ok := cert["dns_names"].([]interface{}); ok {
		for _, name := range dnsNames {
			if str, ok := name.(string); ok {
				compact.DNS = append(compact.DNS, str)
			}
		}
	}

	if issuer, ok := cert["issuer"].(string); ok {
		compact.Iss = compactIssuer(issuer)
	}

	if nb, ok := cert["not_before"].(string); ok {
		compact.NB = compactDate(nb)
	}

	if na, ok := cert["not_after"].(string); ok {
		compact.NA = compactDate(na)
	}

	if sn, ok := cert["serial_number"].(string); ok {
		compact.SN = truncateSerial(sn)
	}

	if source, ok := cert["source"].(string); ok {
		compact.Src = source
	}

	return compact
}

// gfFindingToCompact convierte un gfFinding a formato compacto.
func gfFindingToCompact(value string, metadata map[string]any) GFFindingV2 {
	compact := GFFindingV2{}

	if resource, ok := metadata["resource"].(string); ok {
		compact.Res = resource
	}

	if evidence, ok := metadata["evidence"].(string); ok {
		compact.Ev = evidence
	}

	if line, ok := metadata["line"].(float64); ok {
		compact.L = int(line)
	}

	// Context es opcional, solo incluir si no es demasiado largo
	if context, ok := metadata["context"].(string); ok {
		if len(context) < 200 {
			compact.Ctx = context
		}
	}

	if rules, ok := metadata["rules"].([]interface{}); ok {
		for _, rule := range rules {
			if str, ok := rule.(string); ok {
				compact.R = append(compact.R, str)
			}
		}
	}

	return compact
}

// compactIssuer reduce el issuer a un alias corto si es común.
func compactIssuer(issuer string) string {
	// Mapeo de issuers comunes a aliases cortos
	commonIssuers := map[string]string{
		"C=US, O=Google Trust Services, CN=WR3":                "GTS_WR3",
		"C=US, O=Google Trust Services LLC, CN=GTS CA 1D4":     "GTS_1D4",
		"C=US, O=Google Trust Services, CN=GTS CA 1D2":         "GTS_1D2",
		"C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3": "LE_X3",
		"C=US, O=Let's Encrypt, CN=R3":                         "LE_R3",
	}

	if alias, ok := commonIssuers[issuer]; ok {
		return alias
	}
	return issuer
}

// expandIssuer convierte un alias de issuer a su forma completa.
func expandIssuer(issuer string) string {
	aliases := map[string]string{
		"GTS_WR3": "C=US, O=Google Trust Services, CN=WR3",
		"GTS_1D4": "C=US, O=Google Trust Services LLC, CN=GTS CA 1D4",
		"GTS_1D2": "C=US, O=Google Trust Services, CN=GTS CA 1D2",
		"LE_X3":   "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3",
		"LE_R3":   "C=US, O=Let's Encrypt, CN=R3",
	}

	if full, ok := aliases[issuer]; ok {
		return full
	}
	return issuer
}

// compactDate reduce un timestamp ISO 8601 a solo fecha (YYYY-MM-DD).
func compactDate(timestamp string) string {
	if len(timestamp) >= 10 {
		return timestamp[:10]
	}
	return timestamp
}

// truncateSerial trunca un serial number largo a 16 caracteres.
func truncateSerial(serial string) string {
	// Eliminar prefijo "00" si existe
	serial = strings.TrimPrefix(serial, "00")

	if len(serial) <= 16 {
		return serial
	}
	// Mantener primeros 16 caracteres
	return serial[:16]
}

// timestampsToRelative convierte timestamps ISO 8601 a milisegundos relativos.
func timestampsToRelative(firstSeen, lastSeen string, baseTime time.Time) []int64 {
	if firstSeen == "" {
		return nil
	}

	first, err := time.Parse(time.RFC3339, firstSeen)
	if err != nil {
		return nil
	}

	firstMs := first.Sub(baseTime).Milliseconds()

	// Si first_seen == last_seen, solo guardar uno
	if lastSeen == "" || firstSeen == lastSeen {
		return []int64{firstMs}
	}

	last, err := time.Parse(time.RFC3339, lastSeen)
	if err != nil {
		return []int64{firstMs}
	}

	lastMs := last.Sub(baseTime).Milliseconds()
	return []int64{firstMs, lastMs}
}

// timestampsFromRelative convierte milisegundos relativos a timestamps ISO 8601.
func timestampsFromRelative(ts []int64, baseTime time.Time) (firstSeen, lastSeen string) {
	if len(ts) == 0 {
		return "", ""
	}

	first := baseTime.Add(time.Duration(ts[0]) * time.Millisecond)
	firstSeen = first.UTC().Format(time.RFC3339)

	if len(ts) > 1 {
		last := baseTime.Add(time.Duration(ts[1]) * time.Millisecond)
		lastSeen = last.UTC().Format(time.RFC3339)
	} else {
		lastSeen = firstSeen
	}

	return firstSeen, lastSeen
}

// cleanMetadataForV2 elimina campos redundantes del metadata.
func cleanMetadataForV2(metadata map[string]any, typ string) map[string]any {
	if metadata == nil {
		return nil
	}

	cleaned := make(map[string]any)
	for k, v := range metadata {
		// Para certificados y gfFindings, omitir campos que se mueven a la estructura compacta
		if typ == "certificate" && k == "source" {
			continue
		}
		if typ == "gfFinding" && (k == "resource" || k == "evidence" || k == "line" || k == "context" || k == "rules") {
			continue
		}

		// Mantener todos los demás campos, incluido "raw" para routes, etc.
		cleaned[k] = v
	}

	if len(cleaned) == 0 {
		return nil
	}
	return cleaned
}

// NewHeaderV2 crea un header v2 con timestamp actual.
func NewHeaderV2(target string, tools []string) HeaderV2 {
	return HeaderV2{
		Schema:  SchemaV2,
		Created: time.Now().UTC().Unix(),
		Target:  target,
		Tools:   tools,
	}
}

// ============================================================================
// Funciones de normalización y manipulación de Artifacts (formato interno v1)
// ============================================================================

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
