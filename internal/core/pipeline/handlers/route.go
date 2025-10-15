package handlers

import (
	"strings"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/adapters/routes"
	"passive-rec/internal/types"
)

const (
	keyspaceRoutePassive = "route:passive"
	keyspaceRouteActive  = "route:active"
)

// RouteHandler procesa artifacts de tipo route y sus categorías especializadas.
type RouteHandler struct {
	BaseHandler
}

// NewRouteHandler crea un nuevo handler de rutas.
func NewRouteHandler() *RouteHandler {
	return &RouteHandler{
		BaseHandler: NewBaseHandler("route", ""),
	}
}

// CanHandle determina si la línea es una ruta/URL válida.
func (h *RouteHandler) CanHandle(line string, isActive bool) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}

	// No manejar líneas con prefijos especiales (excepto route categories)
	if idx := strings.Index(trimmed, ":"); idx > 0 {
		prefix := strings.ToLower(trimmed[:idx])
		// Permitir categorías de route conocidas
		knownCategories := map[string]bool{
			"route": true, "js": true, "html": true, "css": true,
			"image": true, "font": true, "video": true, "doc": true,
			"archive": true, "json": true, "api": true, "maps": true,
			"wasm": true, "svg": true, "crawl": true, "meta-route": true,
		}
		if !knownCategories[prefix] {
			return false
		}
	}

	base := artifacts.ExtractRouteBase(trimmed)
	if base == "" {
		return false
	}

	// Verificar que sea una URL válida o ruta
	return strings.Contains(base, "://") || strings.HasPrefix(base, "/") || strings.Contains(base, "/")
}

// Handle procesa una línea de ruta y crea los artifacts correspondientes.
func (h *RouteHandler) Handle(ctx *HandlerContext, line string, isActive bool, tool string) bool {
	if ctx == nil || ctx.Store == nil {
		return true
	}

	trimmed := strings.TrimSpace(line)

	// Detectar si tiene prefijo de categoría
	category, payload := h.extractCategory(trimmed)

	// Extraer base URL
	base := artifacts.ExtractRouteBase(payload)
	if base == "" {
		return false
	}

	// Verificar scope
	if ctx.Scope != nil && !ctx.Scope.AllowsRoute(base) {
		return true
	}

	// Si tiene categoría explícita, procesarla
	if category != "" {
		return h.handleCategorizedRoute(ctx, category, base, payload, isActive, tool)
	}

	// Si no tiene categoría, procesar como route genérico y detectar categorías
	return h.handleGenericRoute(ctx, base, trimmed, isActive, tool)
}

// extractCategory extrae el prefijo de categoría si existe.
func (h *RouteHandler) extractCategory(line string) (string, string) {
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return "", line
	}

	prefix := strings.ToLower(strings.TrimSpace(line[:idx]))
	payload := strings.TrimSpace(line[idx+1:])

	knownCategories := map[string]bool{
		"js": true, "html": true, "css": true, "image": true,
		"font": true, "video": true, "doc": true, "archive": true,
		"json": true, "api": true, "maps": true, "wasm": true,
		"svg": true, "crawl": true, "meta-route": true,
	}

	if knownCategories[prefix] {
		return prefix, payload
	}

	return "", line
}

// handleCategorizedRoute procesa una ruta con categoría explícita.
func (h *RouteHandler) handleCategorizedRoute(ctx *HandlerContext, category, base, value string, isActive bool, tool string) bool {
	// Mapear categoría legacy a Type+Subtype
	typ, subtype := h.mapCategoryToType(category)

	// Determinar keyspace
	typeDef, _ := types.Get(typ, subtype)
	keyspace := typeDef.KeyspacePrefix + ":passive"
	if isActive {
		keyspace = typeDef.KeyspacePrefix + ":active"
	}

	// Crear metadata
	metadata := h.buildMetadata(value, base, isActive)

	// Verificar status si es activo
	if isActive {
		if status, ok := parseActiveRouteStatus(value, base); ok {
			metadata["status"] = status
			if status <= 0 || status >= 400 {
				// Crear artifact con Up=false
				h.createArtifact(ctx, typ, subtype, base, false, isActive, tool, metadata, []string{"route"})
				return true
			}
		}
	}

	// Marcar como visto
	MarkSeen(ctx, keyspace, base)

	// Crear artifact
	extras := []string{"route"}
	h.createArtifact(ctx, typ, subtype, base, true, isActive, tool, metadata, extras)

	return true
}

// handleGenericRoute procesa una ruta sin categoría explícita.
func (h *RouteHandler) handleGenericRoute(ctx *HandlerContext, base, trimmed string, isActive bool, tool string) bool {
	metadata := h.buildMetadata(trimmed, base, isActive)

	// Verificar status si es activo
	if isActive {
		MarkSeen(ctx, keyspaceRoutePassive, base)

		if status, ok := parseActiveRouteStatus(trimmed, base); ok {
			metadata["status"] = status
			if status <= 0 || status >= 400 {
				RecordArtifact(ctx, tool, ArtifactRequest{
					Type:     "route",
					Value:    base,
					Active:   true,
					Up:       false,
					Metadata: metadata,
				})
				return true
			}
		}
	}

	// Marcar como visto
	keyspace := keyspaceRoutePassive
	if isActive {
		keyspace = keyspaceRouteActive
	}
	MarkSeen(ctx, keyspace, base)

	// Detectar categorías especializadas
	var hasSpecializedCategory bool
	if !isActive || shouldCategorizeActiveRoute(trimmed, base) {
		categories := routes.DetectCategories(base)
		hasSpecializedCategory = len(categories) > 0
		if hasSpecializedCategory {
			h.writeRouteCategories(ctx, base, categories, isActive, tool)
		}
	}

	// Solo crear artifact "route" genérico si no tiene categoría especializada
	if !hasSpecializedCategory {
		RecordArtifact(ctx, tool, ArtifactRequest{
			Type:     "route",
			Value:    base,
			Active:   isActive,
			Up:       true,
			Metadata: metadata,
		})
	}

	return true
}

// buildMetadata construye el metadata para un artifact de ruta.
func (h *RouteHandler) buildMetadata(value, base string, isActive bool) map[string]any {
	metadata := make(map[string]any)
	if strings.TrimSpace(value) != base {
		metadata["raw"] = value
	}
	if len(metadata) == 0 {
		return nil
	}
	return metadata
}

// createArtifact es un helper para crear artifacts con Type+Subtype.
func (h *RouteHandler) createArtifact(ctx *HandlerContext, typ, subtype, value string, up, isActive bool, tool string, metadata map[string]any, extras []string) {
	RecordArtifact(ctx, tool, ArtifactRequest{
		Type:     typ,
		Subtype:  subtype,
		Value:    value,
		Active:   isActive,
		Up:       up,
		Metadata: metadata,
		Types:    extras,
	})
}

// mapCategoryToType mapea categorías legacy a Type+Subtype.
func (h *RouteHandler) mapCategoryToType(category string) (string, string) {
	mapping := map[string][2]string{
		"js":         {"resource", "javascript"},
		"html":       {"resource", "html"},
		"css":        {"resource", "css"},
		"image":      {"resource", "image"},
		"font":       {"resource", "font"},
		"video":      {"resource", "video"},
		"doc":        {"resource", "document"},
		"archive":    {"resource", "archive"},
		"json":       {"data", "json"},
		"xml":        {"data", "xml"},
		"api":        {"endpoint", "rest"},
		"maps":       {"meta", "sourcemap"},
		"wasm":       {"meta", "wasm"},
		"svg":        {"meta", "svg"},
		"crawl":      {"meta", "crawl"},
		"meta-route": {"meta", "route"},
	}

	if mapped, ok := mapping[category]; ok {
		return mapped[0], mapped[1]
	}

	return "route", ""
}

// writeRouteCategories crea artifacts para cada categoría detectada.
func (h *RouteHandler) writeRouteCategories(ctx *HandlerContext, route string, categories []routes.Category, isActive bool, tool string) {
	for _, cat := range categories {
		var typ, subtype string

		switch cat {
		case routes.CategoryJS:
			typ, subtype = "resource", "javascript"
		case routes.CategoryHTML:
			typ, subtype = "resource", "html"
		case routes.CategoryCSS:
			typ, subtype = "resource", "css"
		case routes.CategoryImages:
			typ, subtype = "resource", "image"
		case routes.CategoryFonts:
			typ, subtype = "resource", "font"
		case routes.CategoryVideo:
			typ, subtype = "resource", "video"
		case routes.CategoryDocs:
			typ, subtype = "resource", "document"
		case routes.CategoryArchives:
			typ, subtype = "resource", "archive"
		case routes.CategoryJSON:
			typ, subtype = "data", "json"
		case routes.CategoryAPI:
			typ, subtype = "endpoint", "rest"
		case routes.CategoryMaps:
			typ, subtype = "meta", "sourcemap"
		case routes.CategoryWASM:
			typ, subtype = "meta", "wasm"
		case routes.CategorySVG:
			typ, subtype = "meta", "svg"
		case routes.CategoryCrawl:
			typ, subtype = "meta", "crawl"
		case routes.CategoryMeta:
			typ, subtype = "meta", "route"
		default:
			continue
		}

		// Obtener keyspace del registry
		typeDef, _ := types.Get(typ, subtype)
		keyspace := typeDef.KeyspacePrefix + ":passive"
		if isActive {
			keyspace = typeDef.KeyspacePrefix + ":active"
		}

		MarkSeen(ctx, keyspace, route)

		h.createArtifact(ctx, typ, subtype, route, true, isActive, tool, nil, []string{"route"})
	}
}

// parseActiveRouteStatus extrae el status code de una línea activa.
func parseActiveRouteStatus(line, base string) (int, bool) {
	trimmed := strings.TrimSpace(line)
	if base == "" || trimmed == base {
		return 0, false
	}

	suffix := strings.TrimSpace(strings.TrimPrefix(trimmed, base))
	if suffix == "" || !strings.HasPrefix(suffix, "[") {
		return 0, false
	}

	var status int
	_, err := parseStatusFromSuffix(suffix, &status)
	return status, err == nil
}

// shouldCategorizeActiveRoute determina si una ruta activa debe categorizarse.
func shouldCategorizeActiveRoute(line, base string) bool {
	trimmed := strings.TrimSpace(line)
	if base == "" || trimmed == base {
		return true
	}

	suffix := strings.TrimSpace(strings.TrimPrefix(trimmed, base))
	if suffix == "" || !strings.HasPrefix(suffix, "[") {
		return true
	}

	var status int
	_, err := parseStatusFromSuffix(suffix, &status)
	if err != nil {
		return true
	}

	return status > 0 && status < 400
}

// parseStatusFromSuffix extrae el status code del sufijo.
func parseStatusFromSuffix(suffix string, status *int) (string, error) {
	// Implementación simplificada - en producción usar lógica de parseutil.go
	if !strings.HasPrefix(suffix, "[") {
		return suffix, nil
	}

	end := strings.Index(suffix, "]")
	if end < 0 {
		return suffix, nil
	}

	codeStr := strings.TrimSpace(suffix[1:end])
	var code int
	if _, err := parseIntSafe(codeStr, &code); err == nil {
		*status = code
		return strings.TrimSpace(suffix[end+1:]), nil
	}

	return suffix, nil
}

// parseIntSafe intenta parsear un entero de forma segura.
func parseIntSafe(s string, out *int) (string, error) {
	// Implementación simplificada
	var num int
	for i, r := range s {
		if r < '0' || r > '9' {
			if i == 0 {
				return s, nil
			}
			*out = num
			return s[i:], nil
		}
		num = num*10 + int(r-'0')
	}
	*out = num
	return "", nil
}
