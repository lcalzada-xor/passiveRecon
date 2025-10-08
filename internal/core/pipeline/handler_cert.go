package pipeline

import (
	"strings"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/platform/certs"
	"passive-rec/internal/platform/netutil"
)

func handleCert(ctx *Context, line string, isActive bool, tool string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}
	if strings.HasPrefix(trimmed, "cert:") {
		writeCertLine(ctx, strings.TrimSpace(strings.TrimPrefix(trimmed, "cert:")), isActive, tool)
		return true
	}
	return false
}

func writeCertLine(ctx *Context, line string, isActive bool, tool string) {
	if ctx == nil || ctx.S == nil || ctx.Store == nil {
		return
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	record, err := certs.Parse(line)
	if err != nil {
		return
	}
	filtered := record
	if filtered.CommonName != "" {
		domain := netutil.NormalizeDomain(filtered.CommonName)
		if domain == "" || !ctx.S.scopeAllowsDomain(domain) {
			filtered.CommonName = ""
		}
	}
	if len(filtered.DNSNames) > 0 {
		names := make([]string, 0, len(filtered.DNSNames))
		for _, name := range filtered.DNSNames {
			domain := netutil.NormalizeDomain(name)
			if domain == "" {
				continue
			}
			if !ctx.S.scopeAllowsDomain(domain) {
				continue
			}
			names = append(names, name)
		}
		filtered.DNSNames = names
	}
	names := filtered.AllNames()
	if len(names) == 0 {
		return
	}
	for _, name := range names {
		domain := netutil.NormalizeDomain(name)
		if domain == "" {
			continue
		}
		metadata := map[string]any{"source": "certificate"}
		trimmed := strings.TrimSpace(name)
		if trimmed != "" && trimmed != domain {
			metadata["raw"] = trimmed
		}
		if ctx.Dedup != nil {
			_ = ctx.Dedup.Seen(keyspaceDomainPassive, domain)
			if ctx.S.inActiveMode() {
				_ = ctx.Dedup.Seen(keyspaceDomainActive, domain)
			}
		}
		ctx.Store.Record(tool, artifacts.Artifact{
			Type:     "domain",
			Value:    domain,
			Active:   false,
			Up:       true,
			Metadata: metadata,
		})
		if ctx.S.inActiveMode() {
			ctx.Store.Record(tool, artifacts.Artifact{
				Type:     "domain",
				Value:    domain,
				Active:   true,
				Up:       true,
				Metadata: metadata,
			})
		}
	}
	serialized, err := filtered.Marshal()
	if err != nil {
		return
	}
	key := filtered.Key()
	if key == "" {
		key = strings.ToLower(serialized)
	}
	keyspace := keyspaceCertPassive
	if isActive {
		keyspace = keyspaceCertActive
	}
	meta := map[string]any{"names": names}
	if key != "" {
		meta["key"] = key
	}
	if ctx.Dedup != nil {
		_ = ctx.Dedup.Seen(keyspace, key)
	}
	if len(meta) == 0 {
		meta = nil
	}
	ctx.Store.Record(tool, artifacts.Artifact{
		Type:     "certificate",
		Value:    serialized,
		Active:   isActive,
		Up:       true,
		Tool:     filtered.Source,
		Metadata: meta,
	})
}
