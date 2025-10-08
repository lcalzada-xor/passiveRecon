package pipeline

import (
	"encoding/json"
	"strings"

	"passive-rec/internal/artifacts"
)

func handleMeta(ctx *Context, line string, isActive bool, tool string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}
	if ctx == nil || ctx.S == nil || ctx.Store == nil {
		return true
	}
	target := ctx.S.writer(writerMeta, isActive)
	if target == nil {
		return true
	}
	if strings.HasPrefix(trimmed, "meta:") {
		content := strings.TrimSpace(strings.TrimPrefix(trimmed, "meta:"))
		if content == "" {
			return true
		}
		normalized := normalizeMetaContent(content)
		if normalized == "" {
			return true
		}
		_ = target.WriteRaw(normalized)
		ctx.Store.Record(tool, artifacts.Artifact{
			Type:   "meta",
			Value:  normalized,
			Active: isActive,
			Up:     true,
			Tool:   inferToolFromMessage(normalized),
			Metadata: map[string]any{
				"raw": trimmed,
			},
		})
		return true
	}
	return false
}

func handleGFFinding(ctx *Context, line string, isActive bool, tool string) bool {
	payload := strings.TrimSpace(strings.TrimPrefix(line, "gffinding:"))
	if payload == "" {
		return true
	}
	if ctx == nil || ctx.Store == nil {
		return true
	}
	var data struct {
		Resource string   `json:"resource"`
		Line     int      `json:"line"`
		Evidence string   `json:"evidence"`
		Context  string   `json:"context"`
		Rules    []string `json:"rules"`
	}
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return true
	}
	evidence := strings.TrimSpace(data.Evidence)
	if evidence == "" {
		return true
	}
	resource := strings.TrimSpace(data.Resource)
	contextValue := strings.TrimSpace(data.Context)
	rules := normalizeGFRules(data.Rules)
	value := buildGFFindingValue(resource, data.Line, evidence)
	metadata := map[string]any{"evidence": evidence}
	if resource != "" {
		metadata["resource"] = resource
	}
	if data.Line > 0 {
		metadata["line"] = data.Line
	}
	if contextValue != "" {
		metadata["context"] = contextValue
	}
	if len(rules) > 0 {
		metadata["rules"] = rules
	}
	ctx.Store.Record(tool, artifacts.Artifact{
		Type:     "gfFinding",
		Types:    rules,
		Value:    value,
		Active:   isActive,
		Up:       true,
		Metadata: metadata,
	})
	return true
}

func handleRelation(ctx *Context, line string, isActive bool, tool string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || !strings.Contains(trimmed, "-->") {
		return false
	}
	payload, metadata, ok := parseRelation(trimmed)
	if !ok {
		return false
	}
	if ctx == nil || ctx.Store == nil {
		return true
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
