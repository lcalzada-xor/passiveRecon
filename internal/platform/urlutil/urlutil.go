// Package urlutil provides utilities for URL normalization and parsing.
package urlutil

import (
	"net/url"
	"path/filepath"
	"strings"
)

// ExtractExtension returns the file extension from a URL or path.
// It handles query strings and fragments correctly.
func ExtractExtension(rawURL string) string {
	clean := rawURL
	if idx := strings.IndexAny(clean, "?#"); idx != -1 {
		clean = clean[:idx]
	}
	return strings.ToLower(filepath.Ext(clean))
}

// ExtractPath returns the path component of a URL.
// If the input is not a valid URL, it attempts to extract a path-like component.
func ExtractPath(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		if parsed, err := url.Parse(trimmed); err == nil {
			if parsed.Path != "" {
				return parsed.Path
			}
		}
	}
	if idx := strings.Index(trimmed, "/"); idx != -1 {
		return trimmed[idx:]
	}
	return ""
}

// ShouldSkipByExtension checks if a URL should be skipped based on its extension.
// Useful for filtering low-priority resources like thumbnails.
func ShouldSkipByExtension(rawURL string, skipList map[string]struct{}) bool {
	path := ExtractPath(rawURL)
	if path == "" {
		return false
	}

	path = strings.ToLower(path)
	if idx := strings.IndexAny(path, "?#"); idx != -1 {
		path = path[:idx]
	}

	base := filepath.Base(path)
	if base == "" || base == "/" || base == "." {
		return false
	}

	// Check for specific filenames
	if base == "thumbs.db" {
		return true
	}

	ext := filepath.Ext(base)
	if ext != "" {
		if _, ok := skipList[ext]; ok {
			return true
		}
	}

	// Check for common patterns in filename
	name := strings.TrimSuffix(base, ext)
	if strings.Contains(name, "thumb") {
		switch ext {
		case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp":
			return true
		}
	}
	if strings.Contains(name, "sprite") {
		switch ext {
		case ".png", ".svg", ".jpg", ".jpeg", ".webp":
			return true
		}
	}

	return false
}

// NormalizeScope extracts and normalizes a scope from a target string.
// If the target is a URL, it extracts the hostname.
func NormalizeScope(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		if u, err := url.Parse(trimmed); err == nil {
			if host := u.Hostname(); host != "" {
				return host
			}
		}
	}
	return trimmed
}

// LowPriorityExtensions returns a map of file extensions that are typically low priority.
var LowPriorityExtensions = map[string]struct{}{
	".ico": {},
	".cur": {},
	".bmp": {},
	".gif": {},
	".pbm": {},
	".pgm": {},
	".pnm": {},
}
