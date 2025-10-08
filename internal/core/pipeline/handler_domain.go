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
	if isActive {
		if ctx.Dedup != nil && !ctx.Dedup.Seen(keyspaceDomainPassive, key) {
			if writer := ctx.S.writer(writerDomains, false); writer != nil {
				_ = writer.WriteDomain(key)
			}
		}
	}
	writer := ctx.S.writer(writerDomains, isActive)
	if writer == nil {
		return true
	}
	space := keyspaceDomainPassive
	if isActive {
		space = keyspaceDomainActive
	}
	if ctx.Dedup != nil && ctx.Dedup.Seen(space, key) {
		ctx.Store.Record(tool, artifacts.Artifact{
			Type:     "domain",
			Value:    key,
			Active:   isActive,
			Up:       true,
			Metadata: metadata,
		})
		return true
	}
	_ = writer.WriteDomain(line)
	ctx.Store.Record(tool, artifacts.Artifact{
		Type:     "domain",
		Value:    key,
		Active:   isActive,
		Up:       true,
		Metadata: metadata,
	})
	return true
}
