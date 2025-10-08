package app

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"passive-rec/internal/platform/config"
)

const (
	cacheVersion  = 1
	cacheFileName = ".passive-cache.json"
)

type cacheEntry struct {
	Hash        string    `json:"hash"`
	CompletedAt time.Time `json:"completed_at"`
}

type executionCache struct {
	Version int                   `json:"version"`
	Steps   map[string]cacheEntry `json:"steps"`

	mu   sync.Mutex `json:"-"`
	path string     `json:"-"`
}

func loadExecutionCache(path string) (*executionCache, error) {
	cache := &executionCache{
		Version: cacheVersion,
		Steps:   make(map[string]cacheEntry),
		path:    path,
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cache, nil
		}
		return cache, err
	}

	if err := json.Unmarshal(data, cache); err != nil {
		return cache, err
	}

	cache.path = path
	if cache.Steps == nil {
		cache.Steps = make(map[string]cacheEntry)
	}
	if cache.Version != cacheVersion {
		cache.Version = cacheVersion
		cache.Steps = make(map[string]cacheEntry)
	}

	return cache, nil
}

func (c *executionCache) ShouldSkip(stepName, hash string, maxAge time.Duration) (bool, time.Time) {
	if c == nil {
		return false, time.Time{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	entry, ok := c.Steps[stepName]
	if !ok {
		return false, time.Time{}
	}
	if entry.Hash != hash {
		delete(c.Steps, stepName)
		_ = c.persistLocked()
		return false, time.Time{}
	}
	if maxAge > 0 && time.Since(entry.CompletedAt) > maxAge {
		delete(c.Steps, stepName)
		_ = c.persistLocked()
		return false, time.Time{}
	}
	return true, entry.CompletedAt
}

func (c *executionCache) MarkComplete(stepName, hash string) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.Steps == nil {
		c.Steps = make(map[string]cacheEntry)
	}
	c.Steps[stepName] = cacheEntry{Hash: hash, CompletedAt: time.Now().UTC()}
	return c.persistLocked()
}

func (c *executionCache) Invalidate(stepName string) error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.Steps[stepName]; !ok {
		return nil
	}
	delete(c.Steps, stepName)
	return c.persistLocked()
}

func (c *executionCache) Prune(maxAge time.Duration) error {
	if c == nil || maxAge <= 0 {
		return nil
	}
	cutoff := time.Now().Add(-maxAge)

	c.mu.Lock()
	defer c.mu.Unlock()

	changed := false
	for name, entry := range c.Steps {
		if entry.CompletedAt.Before(cutoff) {
			delete(c.Steps, name)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return c.persistLocked()
}

func (c *executionCache) persistLocked() error {
	if c == nil {
		return nil
	}
	if c.path == "" {
		return nil
	}
	snapshot := struct {
		Version int                   `json:"version"`
		Steps   map[string]cacheEntry `json:"steps"`
	}{Version: cacheVersion, Steps: c.Steps}

	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}

	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}

func computeRunHash(cfg *config.Config, ordered []string) string {
	if cfg == nil {
		return ""
	}

	hasher := sha256.New()
	write := func(parts ...string) {
		for _, part := range parts {
			hasher.Write([]byte(part))
			hasher.Write([]byte{0})
		}
	}

	normalizedTools := make([]string, len(cfg.Tools))
	for i, tool := range cfg.Tools {
		normalizedTools[i] = strings.ToLower(strings.TrimSpace(tool))
	}
	sort.Strings(normalizedTools)

	orderedCopy := append([]string(nil), ordered...)
	for i := range orderedCopy {
		orderedCopy[i] = strings.ToLower(strings.TrimSpace(orderedCopy[i]))
	}

	write("v1")
	write(strings.ToLower(strings.TrimSpace(cfg.Target)))
	write(strings.ToLower(strings.TrimSpace(cfg.OutDir)))
	write(strconv.FormatBool(cfg.Active))
	write(strconv.Itoa(cfg.Workers))
	write(strconv.Itoa(cfg.TimeoutS))
	write(strings.Join(normalizedTools, ","))
	write(strings.Join(orderedCopy, ","))
	write(strings.ToLower(strings.TrimSpace(cfg.Proxy)))
	write(cfg.CensysAPIID)
	write(cfg.CensysAPISecret)

	return hex.EncodeToString(hasher.Sum(nil))
}

func cachePathFor(outDir string) string {
	return filepath.Join(outDir, cacheFileName)
}
