package pipeline

import (
	"strings"

	"passive-rec/internal/artifacts"
	"passive-rec/internal/certs"
	"passive-rec/internal/netutil"
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
		if ctx.Dedup != nil && !ctx.Dedup.Seen(keyspaceDomainPassive, domain) {
			if writer := ctx.S.writer(writerDomains, false); writer != nil {
				_ = writer.WriteDomain(domain)
			}
		}
		if ctx.S.inActiveMode() {
			if ctx.Dedup != nil && !ctx.Dedup.Seen(keyspaceDomainActive, domain) {
				if writer := ctx.S.writer(writerDomains, true); writer != nil {
					_ = writer.WriteDomain(domain)
				}
			}
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
	if ctx.Dedup != nil && ctx.Dedup.Seen(keyspace, key) {
		meta := map[string]any{"names": names}
		if key != "" {
			meta["key"] = key
		}
		ctx.Store.Record(tool, artifacts.Artifact{
			Type:     "certificate",
			Value:    serialized,
			Active:   isActive,
			Tool:     filtered.Source,
			Metadata: meta,
		})
		return
	}
	target := ctx.S.writer(writerCerts, isActive)
	if target != nil {
		_ = target.WriteRaw(serialized)
	}
	meta := map[string]any{"names": names}
	if key != "" {
		meta["key"] = key
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
