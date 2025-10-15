package handlers

import (
	"encoding/json"
	"strings"
)

// DNSHandler procesa artifacts de tipo dns.
type DNSHandler struct {
	BaseHandler
}

// DNSArtifact representa un registro DNS parseado.
type DNSArtifact struct {
	Host  string   `json:"host,omitempty"`
	Type  string   `json:"type,omitempty"`
	Value string   `json:"value,omitempty"`
	Raw   string   `json:"raw,omitempty"`
	PTR   []string `json:"ptr,omitempty"`
}

// NewDNSHandler crea un nuevo handler de DNS.
func NewDNSHandler() *DNSHandler {
	return &DNSHandler{
		BaseHandler: NewBaseHandler("dns", "dns:"),
	}
}

// CanHandle determina si la línea es un registro DNS.
func (h *DNSHandler) CanHandle(line string, isActive bool) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	return h.HasPrefix(trimmed)
}

// Handle procesa una línea de DNS y crea el artifact correspondiente.
func (h *DNSHandler) Handle(ctx *HandlerContext, line string, isActive bool, tool string) bool {
	if ctx == nil || ctx.Store == nil {
		return true
	}

	// Remover prefijo
	payload := strings.TrimSpace(h.StripPrefix(line))
	if payload == "" {
		return true
	}

	// Parsear el registro DNS
	var record DNSArtifact
	metadata := make(map[string]any)

	if err := json.Unmarshal([]byte(payload), &record); err == nil {
		// Parseo exitoso - construir valor limpio
		cleanValue := h.buildCleanValue(record, payload)

		// Construir metadata
		h.buildMetadata(&record, payload, metadata)

		// Crear artifact
		RecordArtifact(ctx, tool, ArtifactRequest{
			Type:     "dns",
			Value:    cleanValue,
			Active:   isActive,
			Up:       true,
			Metadata: metadata,
		})
	} else {
		// Fallo en parseo - almacenar payload raw
		metadata["raw"] = payload

		RecordArtifact(ctx, tool, ArtifactRequest{
			Type:     "dns",
			Value:    payload,
			Active:   isActive,
			Up:       true,
			Metadata: metadata,
		})
	}

	return true
}

// buildCleanValue construye un valor legible para el artifact DNS.
func (h *DNSHandler) buildCleanValue(record DNSArtifact, payload string) string {
	host := strings.TrimSpace(record.Host)
	recordType := strings.TrimSpace(record.Type)
	value := strings.TrimSpace(record.Value)

	// Formato preferido: host [TYPE] value
	if host != "" && recordType != "" && value != "" {
		return host + " [" + recordType + "] " + value
	}

	// Fallback a raw si existe
	if raw := strings.TrimSpace(record.Raw); raw != "" {
		return raw
	}

	// Último fallback: solo el host
	if host != "" {
		return host
	}

	return payload
}

// buildMetadata construye el metadata para el artifact DNS.
func (h *DNSHandler) buildMetadata(record *DNSArtifact, payload string, metadata map[string]any) {
	host := strings.TrimSpace(record.Host)
	recordType := strings.TrimSpace(record.Type)
	value := strings.TrimSpace(record.Value)

	if host != "" {
		metadata["host"] = host
	}
	if recordType != "" {
		metadata["type"] = recordType
	}
	if value != "" {
		metadata["value"] = value
	}

	// Raw siempre va en metadata
	raw := strings.TrimSpace(record.Raw)
	if raw == "" {
		raw = payload
	}
	if raw != "" {
		metadata["raw"] = raw
	}

	// PTR records si existen
	if len(record.PTR) > 0 {
		metadata["ptr"] = record.PTR
	}
}
