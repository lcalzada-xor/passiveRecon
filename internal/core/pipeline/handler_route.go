package pipeline

import (
	"strings"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/adapters/routes"
)

type CategorySpec struct {
	Name             string
	Prefix           string
	PassiveKeyspace  string
	ActiveKeyspace   string
	ArtifactType     string
	IncludeRouteType bool
	NormalizePassive bool
	CheckScope       bool
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
	if ctx.Dedup != nil {
		keyspace := spec.PassiveKeyspace
		if isActive {
			keyspace = spec.ActiveKeyspace
		}
		key := artifactValue
		if key == "" {
			key = value
		}
		if keyspace != "" {
			_ = ctx.Dedup.Seen(keyspace, key)
		}
	}
	if len(metadata) == 0 {
		metadata = nil
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
		if ctx.Dedup != nil {
			imageKeyspace := spec.ImagePassiveKey
			if isActive {
				imageKeyspace = spec.ImageActiveKey
			}
			if imageKeyspace != "" {
				_ = ctx.Dedup.Seen(imageKeyspace, value)
			}
		}
		if len(metadata) == 0 {
			metadata = nil
		}
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
	if ctx.Dedup != nil {
		keyspace := spec.PassiveKeyspace
		if isActive {
			keyspace = spec.ActiveKeyspace
		}
		if keyspace != "" {
			_ = ctx.Dedup.Seen(keyspace, value)
		}
	}
	if len(metadata) == 0 {
		metadata = nil
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
		if ctx.Dedup != nil {
			_ = ctx.Dedup.Seen(keyspaceRoutePassive, base)
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
	if ctx.Dedup != nil {
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
		if keyspace != "" {
			_ = ctx.Dedup.Seen(keyspace, key)
		}
	}
	if !isActive || shouldCategorizeActiveRoute(line, base) {
		writeRouteCategories(ctx, base, isActive, tool)
	}
	if len(metadata) == 0 {
		metadata = nil
	}
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
		case routes.CategoryJS:
			HandleCategory(ctx, categorySpecs["js"], "js:"+route, isActive, tool)
		case routes.CategoryHTML:
			HandleCategory(ctx, categorySpecs["html"], "html:"+route, isActive, tool)
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
			ArtifactType:     "js",
			IncludeRouteType: true,
			NormalizePassive: false,
			CheckScope:       true,
		},
		"html": {
			Name:             "html",
			Prefix:           "html:",
			PassiveKeyspace:  keyspaceHTMLPassive,
			ActiveKeyspace:   keyspaceHTMLActive,
			ArtifactType:     "html",
			IncludeRouteType: true,
			NormalizePassive: false,
			CheckScope:       true,
			ImagePassiveKey:  keyspaceImagePassive,
			ImageActiveKey:   keyspaceImageActive,
			Custom:           htmlCategoryHandler,
		},
		"maps": {
			Name:             "maps",
			Prefix:           "maps:",
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
			PassiveKeyspace:  keyspaceMetaRoutePass,
			ActiveKeyspace:   keyspaceMetaRouteAct,
			ArtifactType:     "meta-route",
			IncludeRouteType: true,
			NormalizePassive: false,
			CheckScope:       true,
		},
	}
}
