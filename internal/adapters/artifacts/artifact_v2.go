package artifacts

import (
	"encoding/json"
	"strings"
	"time"
)

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

// HeaderV2 representa la primera línea del archivo artifacts v2.
// Contiene metadata global del scan y configuración.
type HeaderV2 struct {
	Schema    string `json:"$"`              // Schema version (always "2.0")
	Created   int64  `json:"@"`              // Unix timestamp (epoch seconds)
	Target    string `json:"target"`         // Target domain/IP
	Tools     []string `json:"tools,omitempty"` // Catálogo de tools usadas (opcional)
	Aliases   map[string]string `json:"aliases,omitempty"` // Aliases para valores comunes (opcional)
}

// ArtifactV2 representa un hallazgo en formato v2 (compacto).
type ArtifactV2 struct {
	T  string         `json:"t"`            // Type (domain, certificate, route, etc.)
	V  interface{}    `json:"v"`            // Value (string o object según tipo)
	St string         `json:"st"`           // State (up, down, active_up, active_down)
	Tl string         `json:"tl,omitempty"` // Tool name
	N  int            `json:"n,omitempty"`  // Occurrences count
	Ts []int64        `json:"ts,omitempty"` // Timestamps relativos en milisegundos [first_seen] o [first_seen, last_seen]
	Ty []string       `json:"ty,omitempty"` // Secondary types (opcional)
	M  map[string]any `json:"m,omitempty"`  // Metadata adicional (opcional)
}

// CertificateV2 representa un certificado SSL/TLS en formato compacto.
type CertificateV2 struct {
	CN  string   `json:"cn"`            // Common Name
	DNS []string `json:"dns,omitempty"` // DNS Names
	Iss string   `json:"iss"`           // Issuer (puede ser alias o completo)
	NB  string   `json:"nb"`            // Not Before (formato: YYYY-MM-DD o full timestamp)
	NA  string   `json:"na"`            // Not After
	SN  string   `json:"sn"`            // Serial Number (truncado a 16 chars si es muy largo)
	Src string   `json:"source,omitempty"` // Source (opcional)
}

// GFFindingV2 representa un hallazgo de gf/pattern matching en formato compacto.
type GFFindingV2 struct {
	Res  string   `json:"res"`          // Resource (URL)
	Ev   string   `json:"ev"`           // Evidence
	L    int      `json:"l,omitempty"`  // Line number
	Ctx  string   `json:"ctx,omitempty"` // Context (opcional, puede omitirse si es muy largo)
	R    []string `json:"r,omitempty"`  // Rules matched
}

// ToV2 convierte un Artifact v1 a ArtifactV2 (formato compacto).
func ToV2(v1 Artifact, baseTime time.Time) ArtifactV2 {
	v2 := ArtifactV2{
		T:  v1.Type,
		Tl: v1.Tool,
		N:  v1.Occurrences,
		Ty: v1.Types,
		M:  v1.Metadata,
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

	// Reconstruir tools array
	if v1.Tool != "" {
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
		"C=US, O=Google Trust Services, CN=WR3":                 "GTS_WR3",
		"C=US, O=Google Trust Services LLC, CN=GTS CA 1D4":      "GTS_1D4",
		"C=US, O=Google Trust Services, CN=GTS CA 1D2":          "GTS_1D2",
		"C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3":  "LE_X3",
		"C=US, O=Let's Encrypt, CN=R3":                          "LE_R3",
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
