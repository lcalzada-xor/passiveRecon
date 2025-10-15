package pipeline

type Context struct {
	S     *Sink
	Store ArtifactStore
	Dedup *Dedupe
}

// ScopeAllowsDomain verifica si un dominio está dentro del scope.
func (c *Context) ScopeAllowsDomain(domain string) bool {
	if c == nil || c.S == nil {
		return true
	}
	return c.S.scopeAllowsDomain(domain)
}

// ScopeAllowsRoute verifica si una ruta está dentro del scope.
func (c *Context) ScopeAllowsRoute(route string) bool {
	if c == nil || c.S == nil {
		return true
	}
	return c.S.scopeAllowsRoute(route)
}

// InActiveMode retorna true si el sink está en modo activo.
func (c *Context) InActiveMode() bool {
	if c == nil || c.S == nil {
		return false
	}
	return c.S.inActiveMode()
}
