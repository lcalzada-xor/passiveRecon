package handlers

import (
	"strings"
)

// Registry gestiona todos los handlers disponibles.
type Registry struct {
	handlers []ArtifactHandler
}

// NewRegistry crea un nuevo registry con todos los handlers disponibles.
func NewRegistry() *Registry {
	return &Registry{
		handlers: []ArtifactHandler{
			// Handlers con prefijo (prioridad alta)
			NewDNSHandler(),
			NewMetaHandler(),
			NewGFFindingHandler(),
			NewRDAPHandler(),
			NewCertificateHandler(),

			// Handlers sin prefijo (prioridad baja, orden importa)
			NewRelationHandler(), // Debe ir antes de RouteHandler
			NewRouteHandler(),    // Maneja rutas y categorías
			NewDomainHandler(),   // Debe ir al final como fallback
		},
	}
}

// Handle procesa una línea usando el primer handler que la acepte.
// Retorna true si algún handler procesó la línea.
func (r *Registry) Handle(ctx *HandlerContext, line string, isActive bool, tool string) bool {
	if r == nil {
		return false
	}

	for _, handler := range r.handlers {
		if handler.CanHandle(line, isActive) {
			return handler.Handle(ctx, line, isActive, tool)
		}
	}

	return false
}

// GetHandler devuelve un handler por nombre.
func (r *Registry) GetHandler(name string) ArtifactHandler {
	if r == nil {
		return nil
	}

	name = strings.ToLower(strings.TrimSpace(name))
	for _, handler := range r.handlers {
		if strings.ToLower(handler.Name()) == name {
			return handler
		}
	}

	return nil
}

// ListHandlers devuelve todos los handlers registrados.
func (r *Registry) ListHandlers() []ArtifactHandler {
	if r == nil {
		return nil
	}
	return r.handlers
}
