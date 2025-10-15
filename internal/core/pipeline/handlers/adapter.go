package handlers

import (
	"passive-rec/internal/core/pipeline"
)

// Adapter adapta el nuevo sistema de handlers a la interfaz Handler existente.
type Adapter struct {
	handler  ArtifactHandler
	registry *Registry
	ctx      *HandlerContext
}

// NewAdapter crea un nuevo adapter que envuelve un ArtifactHandler.
func NewAdapter(handler ArtifactHandler, ctx *HandlerContext) *Adapter {
	return &Adapter{
		handler: handler,
		ctx:     ctx,
	}
}

// NewRegistryAdapter crea un adapter que usa todo el registry.
func NewRegistryAdapter(registry *Registry, ctx *HandlerContext) *Adapter {
	return &Adapter{
		registry: registry,
		ctx:      ctx,
	}
}

// Name implementa pipeline.Handler.
func (a *Adapter) Name() string {
	if a.handler != nil {
		return a.handler.Name()
	}
	return "registry"
}

// Prefix implementa pipeline.Handler.
func (a *Adapter) Prefix() string {
	// Los nuevos handlers no usan el sistema de prefijos del adapter
	return ""
}

// Handle implementa pipeline.Handler.
func (a *Adapter) Handle(ctx *pipeline.Context, line string, isActive bool, tool string) bool {
	if a.ctx == nil {
		// Crear contexto desde pipeline.Context
		a.ctx = contextFromPipeline(ctx)
	}

	if a.registry != nil {
		// Usar el registry completo
		return a.registry.Handle(a.ctx, line, isActive, tool)
	}

	if a.handler != nil {
		// Usar handler específico
		if a.handler.CanHandle(line, isActive) {
			return a.handler.Handle(a.ctx, line, isActive, tool)
		}
	}

	return false
}

// contextFromPipeline convierte un pipeline.Context al nuevo HandlerContext.
func contextFromPipeline(ctx *pipeline.Context) *HandlerContext {
	if ctx == nil {
		return nil
	}

	return &HandlerContext{
		Store:      ctx.Store,
		Dedup:      ctx.Dedup,
		Scope:      &ScopeAdapter{ctx: ctx},
		ActiveMode: ctx.InActiveMode(),
	}
}

// BuildHandlerRegistry construye un HandlerRegistry del sistema legacy usando adapters.
func BuildHandlerRegistry(ctx *pipeline.Context) *pipeline.HandlerRegistry {
	hctx := contextFromPipeline(ctx)
	registry := NewRegistry()

	legacyRegistry := pipeline.NewHandlerRegistry()

	// Crear adapter para el registry completo como fallback
	adapter := NewRegistryAdapter(registry, hctx)
	legacyRegistry.Register(WrapWithLegacyHandler("strategy-handlers", "", adapter.Handle))

	return legacyRegistry
}

// WrapWithLegacyHandler crea un pipeline.Handler desde una función.
func WrapWithLegacyHandler(name, prefix string, fn func(*pipeline.Context, string, bool, string) bool) pipeline.Handler {
	return pipeline.NewHandler(name, prefix, fn)
}

// ScopeAdapter adapta pipeline.Context a ScopeValidator.
type ScopeAdapter struct {
	ctx *pipeline.Context
}

// AllowsDomain implementa ScopeValidator.
func (s *ScopeAdapter) AllowsDomain(domain string) bool {
	if s.ctx == nil {
		return true
	}
	return s.ctx.ScopeAllowsDomain(domain)
}

// AllowsRoute implementa ScopeValidator.
func (s *ScopeAdapter) AllowsRoute(route string) bool {
	if s.ctx == nil {
		return true
	}
	return s.ctx.ScopeAllowsRoute(route)
}
