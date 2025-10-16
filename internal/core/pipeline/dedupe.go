package pipeline

import "sync"

// Deduplicator es la interfaz para sistemas de deduplicación.
type Deduplicator interface {
	// Seen marca una key como vista en un keyspace y retorna true si ya existía
	Seen(keyspace, key string) bool
}

// Dedupe provides exact deduplication using an in-memory map.
//
// This implementation guarantees no false positives (every duplicate is caught)
// but memory usage grows linearly with the number of unique items. For most
// reconnaissance targets (< 100k unique items), this is the recommended approach.
//
// For very large scans (> 1M items) where memory is constrained and occasional
// duplicates are acceptable, consider using BloomDedupe instead (see bloomdedupe.go).
//
// Memory usage comparison for 1 million unique 50-byte strings:
//   - Dedupe (map):        ~100-150 MB (exact, no false positives)
//   - BloomDedupe (0.01):  ~1.2 MB (probabilistic, ~1% false positive rate)
type Dedupe struct {
	mu   sync.Mutex
	seen map[string]map[string]struct{}
}

// NewDedupe creates an empty deduplicator ready for use.
func NewDedupe() *Dedupe {
	return &Dedupe{seen: make(map[string]map[string]struct{})}
}

// Seen marks the key within the specified namespace and returns true if it was already seen.
// The namespace parameter allows maintaining separate deduplication sets (e.g., "domain:passive"
// vs "domain:active") to avoid cross-contamination between different artifact types.
func (d *Dedupe) Seen(space, key string) bool {
	if d == nil || space == "" || key == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	bucket := d.seen[space]
	if bucket == nil {
		bucket = make(map[string]struct{})
		d.seen[space] = bucket
	}
	if _, ok := bucket[key]; ok {
		return true
	}
	bucket[key] = struct{}{}
	return false
}

const (
	keyspaceDomainPassive  = "domain:passive"
	keyspaceDomainActive   = "domain:active"
	keyspaceRoutePassive   = "route:passive"
	keyspaceRouteActive    = "route:active"
	keyspaceHTMLPassive    = "html:passive"
	keyspaceHTMLActive     = "html:active"
	keyspaceImagePassive   = "image:passive"
	keyspaceImageActive    = "image:active"
	keyspaceMapsPassive    = "route:maps:passive"
	keyspaceMapsActive     = "route:maps:active"
	keyspaceJSONPassive    = "route:json:passive"
	keyspaceJSONActive     = "route:json:active"
	keyspaceAPIPassive     = "route:api:passive"
	keyspaceAPIActive      = "route:api:active"
	keyspaceWASMPassive    = "route:wasm:passive"
	keyspaceWASMActive     = "route:wasm:active"
	keyspaceSVGPassive     = "route:svg:passive"
	keyspaceSVGActive      = "route:svg:active"
	keyspaceCrawlPassive   = "route:crawl:passive"
	keyspaceCrawlActive    = "route:crawl:active"
	keyspaceMetaRoutePass  = "route:meta:passive"
	keyspaceMetaRouteAct   = "route:meta:active"
	keyspaceCSSPassive     = "route:css:passive"
	keyspaceCSSActive      = "route:css:active"
	keyspaceFontPassive    = "route:font:passive"
	keyspaceFontActive     = "route:font:active"
	keyspaceVideoPassive   = "route:video:passive"
	keyspaceVideoActive    = "route:video:active"
	keyspaceDocPassive     = "route:doc:passive"
	keyspaceDocActive      = "route:doc:active"
	keyspaceArchivePassive = "route:archive:passive"
	keyspaceArchiveActive  = "route:archive:active"
	keyspaceCertPassive    = "cert:passive"
	keyspaceCertActive     = "cert:active"
)
