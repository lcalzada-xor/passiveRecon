package pipeline

import (
	"encoding/json"
	"strings"

	"passive-rec/internal/artifacts"
)

type dnsArtifact struct {
	Host  string   `json:"host,omitempty"`
	Type  string   `json:"type,omitempty"`
	Value string   `json:"value,omitempty"`
	Raw   string   `json:"raw,omitempty"`
	PTR   []string `json:"ptr,omitempty"`
}

func handleDNS(ctx *Context, line string, isActive bool, tool string) bool {
	payload := strings.TrimSpace(strings.TrimPrefix(line, "dns:"))
	if payload == "" {
		return true
	}
	if ctx == nil || ctx.Store == nil {
		return true
	}
	metadata := make(map[string]any)
	var record dnsArtifact
	if err := json.Unmarshal([]byte(payload), &record); err == nil {
		if host := strings.TrimSpace(record.Host); host != "" {
			metadata["host"] = host
		}
		if recordType := strings.TrimSpace(record.Type); recordType != "" {
			metadata["type"] = recordType
		}
		if value := strings.TrimSpace(record.Value); value != "" {
			metadata["value"] = value
		}
		raw := strings.TrimSpace(record.Raw)
		if raw == "" {
			raw = payload
		}
		if raw != "" {
			metadata["raw"] = raw
		}
		if len(record.PTR) > 0 {
			metadata["ptr"] = record.PTR
		}
	} else {
		metadata["raw"] = payload
	}
	if len(metadata) == 0 {
		metadata = nil
	}
	ctx.Store.Record(tool, artifacts.Artifact{
		Type:     "dns",
		Value:    payload,
		Active:   isActive,
		Up:       true,
		Metadata: metadata,
	})
	return true
}

func handleRDAP(ctx *Context, line string, isActive bool, tool string) bool {
	if isActive {
		return true
	}
	content := strings.TrimSpace(strings.TrimPrefix(line, "rdap:"))
	if content == "" {
		return true
	}
	if ctx == nil || ctx.S == nil || ctx.Store == nil {
		return true
	}
	target := ctx.S.writer(writerRDAP, false)
	if target == nil {
		return true
	}
	_ = target.WriteRaw(content)
	ctx.Store.Record(tool, artifacts.Artifact{
		Type:   "rdap",
		Value:  content,
		Active: false,
		Up:     true,
		Tool:   inferToolFromMessage(content),
	})
	return true
}
