package pipeline

import (
	"strings"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/platform/netutil"
)

func handleDomain(ctx *Context, line string, isActive bool, tool string) bool {
	trimmed := strings.TrimSpace(line)
	key := netutil.NormalizeDomain(line)
	if key == "" {
		return false
	}
	if ctx == nil || ctx.S == nil || ctx.Store == nil {
		return true
	}
	if !ctx.S.scopeAllowsDomain(key) {
		return true
	}
	metadata := make(map[string]any)
	if trimmed != key {
		metadata["raw"] = trimmed
	}
	if ctx.Dedup != nil {
		_ = ctx.Dedup.Seen(keyspaceDomainPassive, key)
		if isActive {
			_ = ctx.Dedup.Seen(keyspaceDomainActive, key)
		}
	}
	ctx.Store.Record(tool, artifacts.Artifact{
		Type:     "domain",
		Value:    key,
		Active:   isActive,
		Up:       true,
		Metadata: metadata,
	})
	return true
}
