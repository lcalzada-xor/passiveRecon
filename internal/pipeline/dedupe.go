package pipeline

import "sync"

// Dedupe ofrece una deduplicación simple basada en espacios de claves.
type Dedupe struct {
	mu   sync.Mutex
	seen map[string]map[string]struct{}
}

// NewDedupe crea una instancia vacía lista para usarse.
func NewDedupe() *Dedupe {
	return &Dedupe{seen: make(map[string]map[string]struct{})}
}

// Seen marca la clave dentro del espacio indicado y devuelve true si ya se había registrado.
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
	keyspaceDomainPassive = "domain:passive"
	keyspaceDomainActive  = "domain:active"
	keyspaceRoutePassive  = "route:passive"
	keyspaceRouteActive   = "route:active"
	keyspaceHTMLPassive   = "html:passive"
	keyspaceHTMLActive    = "html:active"
	keyspaceImagePassive  = "image:passive"
	keyspaceImageActive   = "image:active"
	keyspaceMapsPassive   = "route:maps:passive"
	keyspaceMapsActive    = "route:maps:active"
	keyspaceJSONPassive   = "route:json:passive"
	keyspaceJSONActive    = "route:json:active"
	keyspaceAPIPassive    = "route:api:passive"
	keyspaceAPIActive     = "route:api:active"
	keyspaceWASMPassive   = "route:wasm:passive"
	keyspaceWASMActive    = "route:wasm:active"
	keyspaceSVGPassive    = "route:svg:passive"
	keyspaceSVGActive     = "route:svg:active"
	keyspaceCrawlPassive  = "route:crawl:passive"
	keyspaceCrawlActive   = "route:crawl:active"
	keyspaceMetaRoutePass = "route:meta:passive"
	keyspaceMetaRouteAct  = "route:meta:active"
	keyspaceCertPassive   = "cert:passive"
	keyspaceCertActive    = "cert:active"
)
