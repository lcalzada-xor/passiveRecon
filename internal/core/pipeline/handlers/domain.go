package handlers

import (
	"strings"

	"passive-rec/internal/platform/netutil"
)

const (
	keyspaceDomainPassive = "domain:passive"
	keyspaceDomainActive  = "domain:active"
)

// DomainHandler procesa artifacts de tipo domain.
type DomainHandler struct {
	BaseHandler
}

// NewDomainHandler crea un nuevo handler de dominios.
func NewDomainHandler() *DomainHandler {
	return &DomainHandler{
		BaseHandler: NewBaseHandler("domain", ""),
	}
}

// CanHandle determina si la línea es un dominio válido.
func (h *DomainHandler) CanHandle(line string, isActive bool) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	// No manejar líneas con prefijos especiales
	if strings.Contains(trimmed, ":") {
		// Permitir dominios con puertos, pero no otros prefijos
		if !strings.Contains(trimmed, "://") && strings.Count(trimmed, ":") == 1 {
			parts := strings.Split(trimmed, ":")
			if len(parts) == 2 {
				// Verificar si la segunda parte es un número (puerto)
				port := strings.TrimSpace(parts[1])
				if len(port) > 0 && len(port) <= 5 {
					for _, r := range port {
						if r < '0' || r > '9' {
							return false
						}
					}
					return true
				}
			}
		}
		return false
	}

	// Verificar que parezca un dominio
	normalized := netutil.NormalizeDomain(trimmed)
	return normalized != ""
}

// Handle procesa una línea de dominio y crea el artifact correspondiente.
func (h *DomainHandler) Handle(ctx *HandlerContext, line string, isActive bool, tool string) bool {
	if ctx == nil || ctx.Store == nil {
		return true
	}

	trimmed := strings.TrimSpace(line)
	key := netutil.NormalizeDomain(trimmed)
	if key == "" {
		return false
	}

	// Validar scope
	if ctx.Scope != nil && !ctx.Scope.AllowsDomain(key) {
		return true
	}

	// Crear metadata si el valor raw difiere del normalizado
	var metadata map[string]any
	if trimmed != key {
		metadata = map[string]any{
			"raw": trimmed,
		}
	}

	// Marcar como visto en deduplicación
	MarkSeen(ctx, keyspaceDomainPassive, key)
	if isActive {
		MarkSeen(ctx, keyspaceDomainActive, key)
	}

	// Registrar artifact
	RecordArtifact(ctx, tool, ArtifactRequest{
		Type:     "domain",
		Value:    key,
		Active:   isActive,
		Up:       true,
		Metadata: metadata,
	})

	return true
}
