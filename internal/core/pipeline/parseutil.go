package pipeline

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

func inferToolFromMessage(msg string) string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return ""
	}
	for len(msg) > 0 {
		r := rune(msg[0])
		if r == '[' || r == '(' {
			msg = strings.TrimLeft(msg, "[(")
			msg = strings.TrimLeft(msg, " ")
			continue
		}
		break
	}
	if msg == "" {
		return ""
	}
	end := len(msg)
	for i, r := range msg {
		if r == ' ' || r == ':' {
			end = i
			break
		}
	}
	token := strings.Trim(msg[:end], "[]():")
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	hasLetter := false
	for _, r := range token {
		if unicode.IsLetter(r) {
			hasLetter = true
			break
		}
	}
	if !hasLetter {
		return ""
	}
	return token
}

var (
	ansiEscapeSequence = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")
	ansiColorCode      = regexp.MustCompile(`\[[0-9;]*m`)
	ansiOSCSequence    = regexp.MustCompile("\x1b\\][^\x07]*\x07")
)

func stripANSI(input string) string {
	withoutOSC := ansiOSCSequence.ReplaceAllString(input, "")
	withoutEsc := ansiEscapeSequence.ReplaceAllString(withoutOSC, "")
	withoutCodes := ansiColorCode.ReplaceAllString(withoutEsc, "")
	return strings.ReplaceAll(withoutCodes, "\x1b", "")
}

func normalizeMetaContent(content string) string {
	cleaned := strings.TrimSpace(stripANSI(content))
	if cleaned == "" {
		return ""
	}
	if cleaned == "[" || cleaned == "]" {
		return ""
	}

	startsWithBracket := strings.HasPrefix(content, "[")
	endsWithBracket := strings.HasSuffix(content, "]")

	if startsWithBracket && !strings.HasPrefix(cleaned, "[") {
		cleaned = strings.TrimLeft(cleaned, "[")
		cleaned = "[" + strings.TrimSpace(cleaned)
	}

	if endsWithBracket && !strings.HasSuffix(cleaned, "]") {
		cleaned = strings.TrimRight(cleaned, "]")
		cleaned = strings.TrimSpace(cleaned) + "]"
	} else if startsWithBracket && !strings.HasSuffix(cleaned, "]") {
		cleaned = strings.TrimSpace(cleaned) + "]"
	}

	cleaned = strings.TrimSpace(cleaned)
	if cleaned == "[]" {
		return ""
	}
	return cleaned
}

func splitRelation(line string) (string, string, string) {
	parts := strings.Split(line, "-->")
	if len(parts) != 3 {
		return "", "", ""
	}
	left := strings.TrimSpace(parts[0])
	relation := strings.TrimSpace(parts[1])
	right := strings.TrimSpace(parts[2])
	if left == "" || relation == "" || right == "" {
		return "", "", ""
	}
	return left, relation, right
}

func normalizeGFRules(rules []string) []string {
	if len(rules) == 0 {
		return nil
	}
	set := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		set[rule] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	ordered := make([]string, 0, len(set))
	for rule := range set {
		ordered = append(ordered, rule)
	}
	sort.Strings(ordered)
	return ordered
}

func buildGFFindingValue(resource string, line int, evidence string) string {
	evidence = strings.TrimSpace(evidence)
	resource = strings.TrimSpace(resource)
	if resource == "" && line <= 0 {
		return evidence
	}
	var builder strings.Builder
	if resource != "" {
		builder.WriteString(resource)
	}
	if line > 0 {
		if builder.Len() > 0 {
			builder.WriteString(":")
		}
		builder.WriteString("#")
		builder.WriteString(strconv.Itoa(line))
	}
	if builder.Len() > 0 && evidence != "" {
		builder.WriteString(" -> ")
	}
	builder.WriteString(evidence)
	return builder.String()
}

func parseRelationNode(node string) (value, kind string) {
	trimmed := strings.TrimSpace(node)
	if trimmed == "" {
		return "", ""
	}
	if strings.HasSuffix(trimmed, ")") {
		if idx := strings.LastIndex(trimmed, "("); idx >= 0 {
			value = strings.TrimSpace(trimmed[:idx])
			kind = strings.TrimSpace(strings.TrimSuffix(trimmed[idx+1:], ")"))
			if value == "" {
				value = trimmed
			}
			return value, kind
		}
	}
	return trimmed, ""
}

func normalizeRelationType(raw string) string {
	cleaned := strings.TrimSpace(raw)
	if cleaned == "" {
		return ""
	}
	cleaned = strings.TrimSuffix(cleaned, "_record")
	cleaned = strings.TrimSuffix(cleaned, " record")
	cleaned = strings.TrimSpace(cleaned)
	if cleaned == "" {
		return ""
	}
	cleaned = strings.ReplaceAll(cleaned, "_", "")
	cleaned = strings.ToUpper(cleaned)
	return cleaned
}

func parseActiveRouteStatus(fullLine, base string) (int, bool) {
	if base == "" {
		return 0, false
	}
	if !strings.HasPrefix(fullLine, base) {
		return 0, false
	}
	meta := strings.TrimSpace(strings.TrimPrefix(fullLine, base))
	if meta == "" {
		return 0, false
	}
	if meta[0] != '[' {
		return 0, false
	}
	end := strings.IndexRune(meta, ']')
	if end <= 1 {
		return 0, false
	}
	inside := strings.TrimSpace(meta[1:end])
	if inside == "" {
		return 0, false
	}
	i := 0
	for i < len(inside) && inside[i] >= '0' && inside[i] <= '9' {
		i++
	}
	if i == 0 {
		return 0, false
	}
	code, err := strconv.Atoi(inside[:i])
	if err != nil {
		return 0, false
	}
	return code, true
}

func isImageURL(raw string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return false
	}

	target := raw
	if u, err := url.Parse(raw); err == nil {
		if u.Path != "" {
			target = u.Path
		}
	}

	if idx := strings.IndexAny(target, "?#"); idx != -1 {
		target = target[:idx]
	}

	ext := strings.ToLower(filepath.Ext(target))
	if ext == "" {
		return false
	}

	switch ext {
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tif", ".tiff", ".jfif", ".avif", ".apng", ".heic", ".heif":
		return true
	}

	return false
}

func shouldCategorizeActiveRoute(fullLine, base string) bool {
	status, ok := parseActiveRouteStatus(fullLine, base)
	if !ok {
		return true
	}
	if status <= 0 {
		return false
	}
	return status < 400
}

func parseRelation(line string) (artifactsJSON string, metadata map[string]any, ok bool) {
	leftRaw, relationRaw, rightRaw := splitRelation(line)
	if leftRaw == "" || relationRaw == "" || rightRaw == "" {
		return "", nil, false
	}

	leftValue, leftKind := parseRelationNode(leftRaw)
	rightValue, rightKind := parseRelationNode(rightRaw)
	if leftValue == "" || rightValue == "" {
		return "", nil, false
	}

	relation := strings.TrimSpace(relationRaw)
	recordType := normalizeRelationType(relation)

	record := dnsArtifact{Host: leftValue, Value: rightValue, Raw: line}
	if recordType != "" {
		record.Type = recordType
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return "", nil, false
	}

	metadata = map[string]any{"raw": line, "relationship": relation}
	if leftValue != "" {
		metadata["host"] = leftValue
	}
	if rightValue != "" {
		metadata["value"] = rightValue
	}
	if recordType != "" {
		metadata["type"] = recordType
	}
	if leftKind != "" {
		metadata["source_kind"] = leftKind
	}
	if rightKind != "" {
		metadata["target_kind"] = rightKind
	}

	return string(payload), metadata, true
}
