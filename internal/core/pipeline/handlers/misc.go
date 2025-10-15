package handlers

import (
	"encoding/json"
	"regexp"
	"strings"
)

// MetaHandler procesa artifacts de tipo meta.
type MetaHandler struct {
	BaseHandler
	ansiRegex *regexp.Regexp
}

// NewMetaHandler crea un nuevo handler de meta.
func NewMetaHandler() *MetaHandler {
	return &MetaHandler{
		BaseHandler: NewBaseHandler("meta", "meta:"),
		ansiRegex:   regexp.MustCompile(`\x1b\[[0-9;]*m`),
	}
}

// CanHandle determina si la línea es meta.
func (h *MetaHandler) CanHandle(line string, isActive bool) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	return h.HasPrefix(trimmed)
}

// Handle procesa una línea de meta.
func (h *MetaHandler) Handle(ctx *HandlerContext, line string, isActive bool, tool string) bool {
	if ctx == nil || ctx.Store == nil {
		return true
	}

	content := strings.TrimSpace(h.StripPrefix(line))
	if content == "" {
		return true
	}

	// Normalizar contenido (remover ANSI sequences)
	normalized := h.normalizeMetaContent(content)
	if normalized == "" {
		return true
	}

	RecordArtifact(ctx, tool, ArtifactRequest{
		Type:   "meta",
		Value:  normalized,
		Active: isActive,
		Up:     true,
		Tool:   h.inferToolFromMessage(normalized),
		Metadata: map[string]any{
			"raw": strings.TrimSpace(line),
		},
	})

	return true
}

// normalizeMetaContent normaliza el contenido meta removiendo ANSI sequences.
func (h *MetaHandler) normalizeMetaContent(content string) string {
	if h.ansiRegex == nil {
		return content
	}
	cleaned := h.ansiRegex.ReplaceAllString(content, "")
	return strings.TrimSpace(cleaned)
}

// inferToolFromMessage intenta inferir la tool desde el mensaje.
func (h *MetaHandler) inferToolFromMessage(msg string) string {
	lower := strings.ToLower(msg)
	tools := []string{"subfinder", "amass", "assetfinder", "wayback", "gau", "httpx", "dnsx"}
	for _, tool := range tools {
		if strings.Contains(lower, tool) {
			return tool
		}
	}
	return ""
}

// GFFindingHandler procesa artifacts de tipo finding (gf patterns).
type GFFindingHandler struct {
	BaseHandler
}

// NewGFFindingHandler crea un nuevo handler de GF findings.
func NewGFFindingHandler() *GFFindingHandler {
	return &GFFindingHandler{
		BaseHandler: NewBaseHandler("gffinding", "gffinding:"),
	}
}

// CanHandle determina si la línea es un GF finding.
func (h *GFFindingHandler) CanHandle(line string, isActive bool) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	return h.HasPrefix(trimmed)
}

// Handle procesa una línea de GF finding.
func (h *GFFindingHandler) Handle(ctx *HandlerContext, line string, isActive bool, tool string) bool {
	if ctx == nil || ctx.Store == nil {
		return true
	}

	payload := strings.TrimSpace(h.StripPrefix(line))
	if payload == "" {
		return true
	}

	// Parsear JSON
	var data struct {
		Resource string   `json:"resource"`
		Line     int      `json:"line"`
		Evidence string   `json:"evidence"`
		Context  string   `json:"context"`
		Rules    []string `json:"rules"`
	}

	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return true
	}

	evidence := strings.TrimSpace(data.Evidence)
	if evidence == "" {
		return true
	}

	resource := strings.TrimSpace(data.Resource)
	contextValue := strings.TrimSpace(data.Context)
	rules := h.normalizeGFRules(data.Rules)

	// Construir valor del finding
	value := h.buildGFFindingValue(resource, data.Line, evidence)

	// Construir metadata
	metadata := map[string]any{"evidence": evidence}
	if resource != "" {
		metadata["resource"] = resource
	}
	if data.Line > 0 {
		metadata["line"] = data.Line
	}
	if contextValue != "" {
		metadata["context"] = contextValue
	}
	if len(rules) > 0 {
		metadata["rules"] = rules
	}

	// Crear artifact con Type+Subtype
	RecordArtifact(ctx, tool, ArtifactRequest{
		Type:     "finding",
		Subtype:  "gf",
		Value:    value,
		Active:   isActive,
		Up:       true,
		Metadata: metadata,
		Types:    rules, // Rules como tipos legacy
	})

	return true
}

// normalizeGFRules normaliza y deduplica las reglas.
func (h *GFFindingHandler) normalizeGFRules(rules []string) []string {
	if len(rules) == 0 {
		return nil
	}

	seen := make(map[string]bool)
	var normalized []string

	for _, rule := range rules {
		trimmed := strings.TrimSpace(rule)
		if trimmed == "" || seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		normalized = append(normalized, trimmed)
	}

	return normalized
}

// buildGFFindingValue construye el valor para el artifact de finding.
func (h *GFFindingHandler) buildGFFindingValue(resource string, line int, evidence string) string {
	var parts []string

	if resource != "" {
		parts = append(parts, resource)
	}

	if line > 0 {
		parts = append(parts, "#"+itoa(line))
	}

	if evidence != "" {
		parts = append(parts, "-> "+evidence)
	}

	if len(parts) == 0 {
		return evidence
	}

	return strings.Join(parts, " ")
}

// itoa convierte un int a string.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf) - 1
	for n > 0 {
		buf[i] = byte('0' + n%10)
		n /= 10
		i--
	}
	return string(buf[i+1:])
}

// RDAPHandler procesa artifacts de tipo rdap.
type RDAPHandler struct {
	BaseHandler
}

// NewRDAPHandler crea un nuevo handler de RDAP.
func NewRDAPHandler() *RDAPHandler {
	return &RDAPHandler{
		BaseHandler: NewBaseHandler("rdap", "rdap:"),
	}
}

// CanHandle determina si la línea es RDAP.
func (h *RDAPHandler) CanHandle(line string, isActive bool) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	// RDAP solo en modo pasivo
	if isActive {
		return false
	}
	return h.HasPrefix(trimmed)
}

// Handle procesa una línea de RDAP.
func (h *RDAPHandler) Handle(ctx *HandlerContext, line string, isActive bool, tool string) bool {
	if ctx == nil || ctx.Store == nil {
		return true
	}

	// RDAP solo en modo pasivo
	if isActive {
		return true
	}

	content := strings.TrimSpace(h.StripPrefix(line))
	if content == "" {
		return true
	}

	RecordArtifact(ctx, tool, ArtifactRequest{
		Type:   "rdap",
		Value:  content,
		Active: false,
		Up:     true,
		Tool:   h.inferToolFromRDAP(content),
	})

	return true
}

// inferToolFromRDAP intenta inferir la tool desde el contenido RDAP.
func (h *RDAPHandler) inferToolFromRDAP(content string) string {
	if strings.Contains(strings.ToLower(content), "rdap") {
		return "rdap"
	}
	return ""
}

// RelationHandler procesa artifacts de tipo relation (DNS relations).
type RelationHandler struct {
	BaseHandler
}

// NewRelationHandler crea un nuevo handler de relations.
func NewRelationHandler() *RelationHandler {
	return &RelationHandler{
		BaseHandler: NewBaseHandler("relation", ""),
	}
}

// CanHandle determina si la línea es una relation.
func (h *RelationHandler) CanHandle(line string, isActive bool) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	return strings.Contains(trimmed, "-->")
}

// Handle procesa una línea de relation.
func (h *RelationHandler) Handle(ctx *HandlerContext, line string, isActive bool, tool string) bool {
	if ctx == nil || ctx.Store == nil {
		return true
	}

	trimmed := strings.TrimSpace(line)
	if !strings.Contains(trimmed, "-->") {
		return false
	}

	payload, metadata := h.parseRelation(trimmed)
	if payload == "" {
		return false
	}

	RecordArtifact(ctx, tool, ArtifactRequest{
		Type:     "dns",
		Value:    payload,
		Active:   isActive,
		Up:       true,
		Metadata: metadata,
	})

	return true
}

// parseRelation parsea una línea de relation.
func (h *RelationHandler) parseRelation(line string) (string, map[string]any) {
	parts := strings.Split(line, "-->")
	if len(parts) != 2 {
		return "", nil
	}

	from := strings.TrimSpace(parts[0])
	to := strings.TrimSpace(parts[1])

	if from == "" || to == "" {
		return "", nil
	}

	// Formato: "from --> to"
	payload := from + " --> " + to

	metadata := map[string]any{
		"from": from,
		"to":   to,
		"type": "relation",
	}

	return payload, metadata
}
