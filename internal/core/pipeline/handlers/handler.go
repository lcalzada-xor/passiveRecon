package handlers

import (
	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/core/pipeline"
)

// ArtifactHandler es la interfaz Strategy para procesar artifacts específicos.
// Cada handler implementa la lógica de parsing, validación y creación para un tipo de artifact.
type ArtifactHandler interface {
	// Name devuelve el nombre identificador del handler
	Name() string

	// CanHandle determina si este handler puede procesar la línea dada
	CanHandle(line string, isActive bool) bool

	// Handle procesa la línea y crea artifacts
	// Retorna true si la línea fue procesada exitosamente
	Handle(ctx *HandlerContext, line string, isActive bool, tool string) bool
}

// HandlerContext proporciona acceso a los recursos compartidos del pipeline.
type HandlerContext struct {
	// Store es donde se registran los artifacts procesados
	Store pipeline.ArtifactStore

	// Dedup gestiona la deduplicación de artifacts
	Dedup pipeline.Deduplicator

	// Scope valida si un artifact está dentro del scope configurado
	Scope ScopeValidator

	// ActiveMode indica si el pipeline está en modo activo
	ActiveMode bool
}

// ScopeValidator valida si un valor está dentro del scope del scan.
type ScopeValidator interface {
	AllowsDomain(domain string) bool
	AllowsRoute(route string) bool
}

// ArtifactRequest encapsula la información necesaria para crear un artifact.
type ArtifactRequest struct {
	Type     string
	Subtype  string
	Value    string
	Active   bool
	Up       bool
	Tool     string
	Metadata map[string]any
	Types    []string // Legacy types for compatibility
}

// RecordArtifact es un helper para crear y registrar un artifact de manera consistente.
func RecordArtifact(ctx *HandlerContext, tool string, req ArtifactRequest) {
	if ctx == nil || ctx.Store == nil {
		return
	}

	artifact := artifacts.Artifact{
		Type:     req.Type,
		Subtype:  req.Subtype,
		Value:    req.Value,
		Active:   req.Active,
		Up:       req.Up,
		Tool:     req.Tool,
		Metadata: req.Metadata,
		Types:    req.Types,
	}

	// Si no se especificó tool en el request, usar el del parámetro
	if artifact.Tool == "" {
		artifact.Tool = tool
	}

	ctx.Store.Record(tool, artifact)
}

// MarkSeen registra un artifact en el sistema de deduplicación.
func MarkSeen(ctx *HandlerContext, keyspace, key string) {
	if ctx == nil || ctx.Dedup == nil {
		return
	}
	_ = ctx.Dedup.Seen(keyspace, key)
}

// BaseHandler proporciona funcionalidad común para todos los handlers.
type BaseHandler struct {
	name   string
	prefix string
}

// NewBaseHandler crea un nuevo BaseHandler.
func NewBaseHandler(name, prefix string) BaseHandler {
	return BaseHandler{
		name:   name,
		prefix: prefix,
	}
}

// Name implementa ArtifactHandler.
func (h BaseHandler) Name() string {
	return h.name
}

// HasPrefix verifica si la línea tiene el prefijo esperado.
func (h BaseHandler) HasPrefix(line string) bool {
	if h.prefix == "" {
		return true
	}
	return len(line) > len(h.prefix) && line[:len(h.prefix)] == h.prefix
}

// StripPrefix remueve el prefijo de la línea.
func (h BaseHandler) StripPrefix(line string) string {
	if h.prefix == "" {
		return line
	}
	if !h.HasPrefix(line) {
		return line
	}
	return line[len(h.prefix):]
}
