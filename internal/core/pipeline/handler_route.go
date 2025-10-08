package pipeline

import (
	"strings"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/adapters/routes"
)

type CategorySpec struct {
	Name             string
	Prefix           string
	WriterKey        string
	PassiveKeyspace  string
	ActiveKeyspace   string
	ArtifactType     string
	IncludeRouteType bool
	NormalizePassive bool
	CheckScope       bool
	ImageWriterKey   string
	ImagePassiveKey  string
	ImageActiveKey   string
	Custom           func(*Context, CategorySpec, string, bool, string) bool
}

var categorySpecs map[string]CategorySpec

func HandleCategory(ctx *Context, spec CategorySpec, line string, isActive bool, tool string) bool {
	if spec.Custom != nil {
		return spec.Custom(ctx, spec, line, isActive, tool)
	}
	return defaultCategoryHandler(ctx, spec, line, isActive, tool)
}

func defaultCategoryHandler(ctx *Context, spec CategorySpec, line string, isActive bool, tool string) bool {
	if ctx == nil || ctx.S == nil || ctx.Store == nil {
		return true
	}
	value := strings.TrimSpace(line)
	if spec.Prefix != "" {
		if !strings.HasPrefix(value, spec.Prefix) {
			return false
		}
		value = strings.TrimSpace(strings.TrimPrefix(value, spec.Prefix))
	}
	if value == "" {
		return true
	}
	base := artifacts.ExtractRouteBase(value)
	if spec.CheckScope && base != "" && !ctx.S.scopeAllowsRoute(base) {
		return true
	}
	artifactValue := base
	if artifactValue == "" {
		artifactValue = value
	}
	var extras []string
	if spec.IncludeRouteType && base != "" {
		extras = []string{"route"}
	}
	metadata := make(map[string]any)
	if artifactValue != value {
		metadata["raw"] = value
	}
	if isActive {
		if status, ok := parseActiveRouteStatus(value, base); ok {
			metadata["status"] = status
			if status <= 0 || status >= 400 {
				ctx.Store.Record(tool, artifacts.Artifact{
					Type:     spec.ArtifactType,
					Types:    extras,
					Value:    artifactValue,
					Active:   true,
					Up:       false,
					Metadata: metadata,
				})
				return true
			}
		}
	}
	keyspace := spec.PassiveKeyspace
	if isActive {
		keyspace = spec.ActiveKeyspace
	}
	key := artifactValue
	if key == "" {
		key = value
	}
	if keyspace != "" && ctx.Dedup != nil && ctx.Dedup.Seen(keyspace, key) {
		ctx.Store.Record(tool, artifacts.Artifact{
			Type:     spec.ArtifactType,
			Types:    extras,
			Value:    artifactValue,
			Active:   isActive,
			Up:       true,
			Metadata: metadata,
		})
		return true
	}
	writer := ctx.S.writer(spec.WriterKey, isActive)
	if writer == nil {
		return true
	}
	if isActive || !spec.NormalizePassive {
		if isActive {
			_ = writer.WriteRaw(value)
		} else {
			_ = writer.WriteURL(value)
		}
	} else {
		normalized := artifactValue
		if normalized == "" {
			normalized = value
		}
		_ = writer.WriteURL(normalized)
	}
	ctx.Store.Record(tool, artifacts.Artifact{
		Type:     spec.ArtifactType,
		Types:    extras,
		Value:    artifactValue,
		Active:   isActive,
		Up:       true,
		Metadata: metadata,
	})
	return true
}

func handleJS(ctx *Context, line string, isActive bool, tool string) bool {
	return HandleCategory(ctx, categorySpecs["js"], line, isActive, tool)
}

func handleMaps(ctx *Context, line string, isActive bool, tool string) bool {
	return HandleCategory(ctx, categorySpecs["maps"], line, isActive, tool)
}

func handleJSONCategory(ctx *Context, line string, isActive bool, tool string) bool {
	return HandleCategory(ctx, categorySpecs["json"], line, isActive, tool)
}

func handleAPICategory(ctx *Context, line string, isActive bool, tool string) bool {
	return HandleCategory(ctx, categorySpecs["api"], line, isActive, tool)
}

func handleWASMCategory(ctx *Context, line string, isActive bool, tool string) bool {
	return HandleCategory(ctx, categorySpecs["wasm"], line, isActive, tool)
}

func handleSVGCategory(ctx *Context, line string, isActive bool, tool string) bool {
	return HandleCategory(ctx, categorySpecs["svg"], line, isActive, tool)
}

func handleCrawlCategory(ctx *Context, line string, isActive bool, tool string) bool {
	return HandleCategory(ctx, categorySpecs["crawl"], line, isActive, tool)
}

func handleMetaCategory(ctx *Context, line string, isActive bool, tool string) bool {
	return HandleCategory(ctx, categorySpecs["meta-route"], line, isActive, tool)
}

func handleHTML(ctx *Context, line string, isActive bool, tool string) bool {
	return HandleCategory(ctx, categorySpecs["html"], line, isActive, tool)
}

func handleRoute(ctx *Context, line string, isActive bool, tool string) bool {
	return HandleCategory(ctx, categorySpecs["route"], line, isActive, tool)
}

func htmlCategoryHandler(ctx *Context, spec CategorySpec, line string, isActive bool, tool string) bool {
	if ctx == nil || ctx.S == nil || ctx.Store == nil {
		return true
	}
	value := strings.TrimSpace(strings.TrimPrefix(line, spec.Prefix))
	if value == "" {
		return true
	}
	base := artifacts.ExtractRouteBase(value)
	if base != "" && !ctx.S.scopeAllowsRoute(base) {
		return true
	}
	imageTarget := value
	if base != "" {
		imageTarget = base
	}
	artifactValue := base
	if artifactValue == "" {
		artifactValue = value
	}
	var extras []string
	if base != "" {
		extras = []string{"route"}
	}
	metadata := make(map[string]any)
	if strings.TrimSpace(value) != artifactValue {
		metadata["raw"] = value
	}
	if isActive {
		if status, ok := parseActiveRouteStatus(value, base); ok {
			metadata["status"] = status
			if status <= 0 || status >= 400 {
				artifactType := spec.ArtifactType
				if isImageURL(imageTarget) {
					artifactType = "image"
				}
				ctx.Store.Record(tool, artifacts.Artifact{
					Type:     artifactType,
					Types:    extras,
					Value:    artifactValue,
					Active:   true,
					Up:       false,
					Metadata: metadata,
				})
				return true
			}
		}
	}
	if isImageURL(imageTarget) {
		imageKeyspace := spec.ImagePassiveKey
		if isActive {
			imageKeyspace = spec.ImageActiveKey
		}
		key := value
		if ctx.Dedup != nil && imageKeyspace != "" && ctx.Dedup.Seen(imageKeyspace, key) {
			ctx.Store.Record(tool, artifacts.Artifact{
				Type:     "image",
				Types:    extras,
				Value:    artifactValue,
				Active:   isActive,
				Up:       true,
				Metadata: metadata,
			})
			return true
		}
		writer := ctx.S.writer(spec.ImageWriterKey, isActive)
		if writer == nil {
			return true
		}
		if isActive {
			_ = writer.WriteRaw(value)
			ctx.Store.Record(tool, artifacts.Artifact{
				Type:     "image",
				Types:    extras,
				Value:    artifactValue,
				Active:   true,
				Up:       true,
				Metadata: metadata,
			})
			return true
		}
		_ = writer.WriteURL(value)
		ctx.Store.Record(tool, artifacts.Artifact{
			Type:     "image",
			Types:    extras,
			Value:    artifactValue,
			Active:   false,
			Up:       true,
			Metadata: metadata,
		})
		return true
	}
	keyspace := spec.PassiveKeyspace
	if isActive {
		keyspace = spec.ActiveKeyspace
	}
	key := value
	if ctx.Dedup != nil && keyspace != "" && ctx.Dedup.Seen(keyspace, key) {
		ctx.Store.Record(tool, artifacts.Artifact{
			Type:     spec.ArtifactType,
			Types:    extras,
			Value:    artifactValue,
			Active:   isActive,
			Up:       true,
			Metadata: metadata,
		})
		return true
	}
	writer := ctx.S.writer(spec.WriterKey, isActive)
	if writer == nil {
		return true
	}
	if isActive {
		_ = writer.WriteRaw(value)
	} else {
		_ = writer.WriteURL(value)
	}
	ctx.Store.Record(tool, artifacts.Artifact{
		Type:     spec.ArtifactType,
		Types:    extras,
		Value:    artifactValue,
		Active:   isActive,
		Up:       true,
		Metadata: metadata,
	})
	return true
}

func routeCategoryHandler(ctx *Context, spec CategorySpec, line string, isActive bool, tool string) bool {
	if ctx == nil || ctx.S == nil || ctx.Store == nil {
		return true
	}
	trimmed := strings.TrimSpace(line)
	base := artifacts.ExtractRouteBase(line)
	if base == "" {
		return false
	}
	if !(strings.Contains(base, "://") || strings.HasPrefix(base, "/") || strings.Contains(base, "/")) {
		return false
	}
	if !ctx.S.scopeAllowsRoute(base) {
		return true
	}
	metadata := make(map[string]any)
	if trimmed != base {
		metadata["raw"] = trimmed
	}
	if isActive {
		if ctx.Dedup != nil && !ctx.Dedup.Seen(keyspaceRoutePassive, base) {
			if writer := ctx.S.writer(writerRoutes, false); writer != nil {
				_ = writer.WriteURL(base)
			}
		}
		if status, ok := parseActiveRouteStatus(trimmed, base); ok {
			metadata["status"] = status
			if status <= 0 || status >= 400 {
				ctx.Store.Record(tool, artifacts.Artifact{
					Type:     spec.ArtifactType,
					Value:    base,
					Active:   true,
					Up:       false,
					Metadata: metadata,
				})
				return true
			}
		}
	}
	keyspace := keyspaceRoutePassive
	if isActive {
		keyspace = keyspaceRouteActive
	}
	key := base
	if key == "" {
		key = trimmed
	}
	if key == "" {
		key = line
	}
	if ctx.Dedup != nil && ctx.Dedup.Seen(keyspace, key) {
		ctx.Store.Record(tool, artifacts.Artifact{
			Type:     spec.ArtifactType,
			Value:    base,
			Active:   isActive,
			Up:       true,
			Metadata: metadata,
		})
		return true
	}
	if !isActive || shouldCategorizeActiveRoute(line, base) {
		writeRouteCategories(ctx, base, isActive, tool)
	}
	writer := ctx.S.writer(writerRoutes, isActive)
	if writer == nil {
		return true
	}
	_ = writer.WriteURL(line)
	ctx.Store.Record(tool, artifacts.Artifact{
		Type:     spec.ArtifactType,
		Value:    base,
		Active:   isActive,
		Up:       true,
		Metadata: metadata,
	})
	return true
}

func writeRouteCategories(ctx *Context, route string, isActive bool, tool string) {
	if ctx == nil || ctx.S == nil || ctx.Store == nil {
		return
	}
	if route == "" {
		return
	}
	categories := routes.DetectCategories(route)
	if len(categories) == 0 {
		return
	}
	for _, cat := range categories {
		switch cat {
		case routes.CategoryMaps:
			HandleCategory(ctx, categorySpecs["maps"], "maps:"+route, isActive, tool)
		case routes.CategoryJSON:
			HandleCategory(ctx, categorySpecs["json"], "json:"+route, isActive, tool)
		case routes.CategoryAPI:
			HandleCategory(ctx, categorySpecs["api"], "api:"+route, isActive, tool)
		case routes.CategoryWASM:
			HandleCategory(ctx, categorySpecs["wasm"], "wasm:"+route, isActive, tool)
		case routes.CategorySVG:
			HandleCategory(ctx, categorySpecs["svg"], "svg:"+route, isActive, tool)
		case routes.CategoryCrawl:
			HandleCategory(ctx, categorySpecs["crawl"], "crawl:"+route, isActive, tool)
		case routes.CategoryMeta:
			HandleCategory(ctx, categorySpecs["meta-route"], "meta-route:"+route, isActive, tool)
		}
	}
}

func init() {
	categorySpecs = map[string]CategorySpec{
		"route": {
			Name:             "route",
			WriterKey:        writerRoutes,
			PassiveKeyspace:  keyspaceRoutePassive,
			ActiveKeyspace:   keyspaceRouteActive,
			ArtifactType:     "route",
			IncludeRouteType: false,
			NormalizePassive: false,
			CheckScope:       true,
			Custom:           routeCategoryHandler,
		},
		"js": {
			Name:             "js",
			Prefix:           "js:",
			WriterKey:        writerRoutesJS,
			ArtifactType:     "js",
			IncludeRouteType: true,
			NormalizePassive: false,
			CheckScope:       true,
		},
		"html": {
			Name:             "html",
			Prefix:           "html:",
			WriterKey:        writerRoutesHTML,
			PassiveKeyspace:  keyspaceHTMLPassive,
			ActiveKeyspace:   keyspaceHTMLActive,
			ArtifactType:     "html",
			IncludeRouteType: true,
			NormalizePassive: false,
			CheckScope:       true,
			ImageWriterKey:   writerRoutesImages,
			ImagePassiveKey:  keyspaceImagePassive,
			ImageActiveKey:   keyspaceImageActive,
			Custom:           htmlCategoryHandler,
		},
		"maps": {
			Name:             "maps",
			Prefix:           "maps:",
			WriterKey:        writerRoutesMaps,
			PassiveKeyspace:  keyspaceMapsPassive,
			ActiveKeyspace:   keyspaceMapsActive,
			ArtifactType:     "maps",
			IncludeRouteType: true,
			NormalizePassive: true,
			CheckScope:       true,
		},
		"json": {
			Name:             "json",
			Prefix:           "json:",
			WriterKey:        writerRoutesJSON,
			PassiveKeyspace:  keyspaceJSONPassive,
			ActiveKeyspace:   keyspaceJSONActive,
			ArtifactType:     "json",
			IncludeRouteType: true,
			NormalizePassive: true,
			CheckScope:       true,
		},
		"api": {
			Name:             "api",
			Prefix:           "api:",
			WriterKey:        writerRoutesAPI,
			PassiveKeyspace:  keyspaceAPIPassive,
			ActiveKeyspace:   keyspaceAPIActive,
			ArtifactType:     "api",
			IncludeRouteType: true,
			NormalizePassive: true,
			CheckScope:       true,
		},
		"wasm": {
			Name:             "wasm",
			Prefix:           "wasm:",
			WriterKey:        writerRoutesWASM,
			PassiveKeyspace:  keyspaceWASMPassive,
			ActiveKeyspace:   keyspaceWASMActive,
			ArtifactType:     "wasm",
			IncludeRouteType: true,
			NormalizePassive: true,
			CheckScope:       true,
		},
		"svg": {
			Name:             "svg",
			Prefix:           "svg:",
			WriterKey:        writerRoutesSVG,
			PassiveKeyspace:  keyspaceSVGPassive,
			ActiveKeyspace:   keyspaceSVGActive,
			ArtifactType:     "svg",
			IncludeRouteType: true,
			NormalizePassive: true,
			CheckScope:       true,
		},
		"crawl": {
			Name:             "crawl",
			Prefix:           "crawl:",
			WriterKey:        writerRoutesCrawl,
			PassiveKeyspace:  keyspaceCrawlPassive,
			ActiveKeyspace:   keyspaceCrawlActive,
			ArtifactType:     "crawl",
			IncludeRouteType: true,
			NormalizePassive: true,
			CheckScope:       true,
		},
		"meta-route": {
			Name:             "meta-route",
			Prefix:           "meta-route:",
			WriterKey:        writerRoutesMeta,
			PassiveKeyspace:  keyspaceMetaRoutePass,
			ActiveKeyspace:   keyspaceMetaRouteAct,
			ArtifactType:     "meta-route",
			IncludeRouteType: true,
			NormalizePassive: false,
			CheckScope:       true,
		},
	}
}
