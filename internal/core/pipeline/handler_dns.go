package pipeline

import (
	"encoding/json"
	"strings"

	"passive-rec/internal/adapters/artifacts"
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

	// Parse the DNS record
	var record dnsArtifact
	metadata := make(map[string]any)

	if err := json.Unmarshal([]byte(payload), &record); err == nil {
		// Build a clean value from the record components
		// Priority: host + type + value > raw > payload
		var cleanValue string
		host := strings.TrimSpace(record.Host)
		recordType := strings.TrimSpace(record.Type)
		value := strings.TrimSpace(record.Value)

		if host != "" && recordType != "" && value != "" {
			// Format: host [TYPE] value (clean, human-readable)
			cleanValue = host + " [" + recordType + "] " + value
		} else if raw := strings.TrimSpace(record.Raw); raw != "" {
			cleanValue = raw
		} else {
			cleanValue = host // fallback to just the host
		}

		// Store all components in metadata for full detail
		if host != "" {
			metadata["host"] = host
		}
		if recordType != "" {
			metadata["type"] = recordType
		}
		if value != "" {
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

		// Use the clean value instead of the full JSON payload
		ctx.Store.Record(tool, artifacts.Artifact{
			Type:     "dns",
			Value:    cleanValue,
			Active:   isActive,
			Up:       true,
			Metadata: metadata,
		})
	} else {
		// Failed to parse: store payload as-is
		metadata["raw"] = payload
		ctx.Store.Record(tool, artifacts.Artifact{
			Type:     "dns",
			Value:    payload,
			Active:   isActive,
			Up:       true,
			Metadata: metadata,
		})
	}

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
	if ctx == nil || ctx.Store == nil {
		return true
	}
	ctx.Store.Record(tool, artifacts.Artifact{
		Type:   "rdap",
		Value:  content,
		Active: false,
		Up:     true,
		Tool:   inferToolFromMessage(content),
	})
	return true
}
