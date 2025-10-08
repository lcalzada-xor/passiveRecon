package pipeline

import "strings"

type Handler interface {
	Name() string
	Prefix() string
	Handle(*Context, string, bool, string) bool
}

type handlerFunc struct {
	name   string
	prefix string
	fn     func(*Context, string, bool, string) bool
}

func (h *handlerFunc) Name() string   { return h.name }
func (h *handlerFunc) Prefix() string { return h.prefix }
func (h *handlerFunc) Handle(ctx *Context, line string, isActive bool, tool string) bool {
	if h.fn == nil {
		return false
	}
	return h.fn(ctx, line, isActive, tool)
}

func NewHandler(name, prefix string, fn func(*Context, string, bool, string) bool) Handler {
	prefix = strings.TrimSpace(prefix)
	if prefix != "" && !strings.HasSuffix(prefix, ":") {
		prefix += ":"
	}
	return &handlerFunc{name: name, prefix: prefix, fn: fn}
}

type HandlerRegistry struct {
	prefixHandlers map[string]Handler
	fallback       []Handler
}

func NewHandlerRegistry() *HandlerRegistry {
	return &HandlerRegistry{prefixHandlers: make(map[string]Handler)}
}

func (r *HandlerRegistry) Register(h Handler) {
	if r == nil || h == nil {
		return
	}
	if prefix := h.Prefix(); prefix != "" {
		r.prefixHandlers[prefix] = h
		return
	}
	r.fallback = append(r.fallback, h)
}

func (r *HandlerRegistry) Lookup(prefix string) Handler {
	if r == nil || prefix == "" {
		return nil
	}
	return r.prefixHandlers[prefix]
}

func (r *HandlerRegistry) Fallbacks() []Handler {
	if r == nil {
		return nil
	}
	return r.fallback
}
