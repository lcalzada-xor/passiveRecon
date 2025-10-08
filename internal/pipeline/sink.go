package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"passive-rec/internal/netutil"
)

const (
	defaultLineBuffer   = 1024
	lineBufferPerWorker = 256
)

const (
	toolMarker    = "\x00tool:"
	toolSeparator = "\x00"
)

const (
	writerDomains      = "domains"
	writerRoutes       = "routes"
	writerRoutesJS     = "routes:js"
	writerRoutesHTML   = "routes:html"
	writerRoutesImages = "routes:images"
	writerRDAP         = "rdap"
	writerRoutesMaps   = "routes:maps"
	writerRoutesJSON   = "routes:json"
	writerRoutesAPI    = "routes:api"
	writerRoutesWASM   = "routes:wasm"
	writerRoutesSVG    = "routes:svg"
	writerRoutesCrawl  = "routes:crawl"
	writerRoutesMeta   = "routes:meta"
	writerCerts        = "certs"
	writerMeta         = "meta"
)

// LineBufferSize calcula un tamaño de búfer recomendado para el canal de líneas
// en función del número de workers configurado.
func LineBufferSize(workers int) int {
	if workers < 1 {
		workers = 1
	}
	size := workers * lineBufferPerWorker
	if size < defaultLineBuffer {
		size = defaultLineBuffer
	}
	return size
}

type Sink struct {
	writers        CategoryWriters
	artifacts      ArtifactStore
	dedup          *Dedupe
	scope          *netutil.Scope
	activeMode     bool
	lines          chan string
	wg             sync.WaitGroup
	processing     int
	procMu         sync.Mutex
	cond           *sync.Cond
	handlerMetrics map[string]*handlerStats
	metricsMu      sync.Mutex
	registry       *HandlerRegistry
	ctx            *Context
}

func NewSink(outdir string, active bool, target string, lineBuffer int) (*Sink, error) {
	if lineBuffer <= 0 {
		lineBuffer = defaultLineBuffer
	}
	if err := os.MkdirAll(filepath.Join(outdir, "dns"), 0o755); err != nil {
		return nil, err
	}

	newWriter := func(subdir, name string) (sinkWriter, error) {
		if name == "" {
			return nil, nil
		}
		if err := ensureOutputFile(outdir, subdir, name); err != nil {
			return nil, err
		}
		return newLazyWriter(outdir, subdir, name), nil
	}

	createPair := func(subdir, passiveName, activeName string) (writerPair, error) {
		var pair writerPair
		if passiveName != "" {
			writer, err := newWriter(subdir, passiveName)
			if err != nil {
				return writerPair{}, err
			}
			pair.passive = writer
		}
		if activeName != "" {
			writer, err := newWriter(subdir, activeName)
			if err != nil {
				return writerPair{}, err
			}
			pair.active = writer
		}
		return pair, nil
	}

	writers := make(CategoryWriters)

	domainsPair, err := createPair("domains", "domains.passive", "domains.active")
	if err != nil {
		return nil, err
	}
	writers.add(writerDomains, domainsPair)

	routesPair, err := createPair("routes", "routes.passive", "routes.active")
	if err != nil {
		return nil, err
	}
	writers.add(writerRoutes, routesPair)

	rdapPair, err := createPair("rdap", "rdap.passive", "")
	if err != nil {
		return nil, err
	}
	writers.add(writerRDAP, rdapPair)

	jsPair, err := createPair(filepath.Join("routes", "js"), "js.passive", "js.active")
	if err != nil {
		return nil, err
	}
	writers.add(writerRoutesJS, jsPair)

	htmlPair, err := createPair(filepath.Join("routes", "html"), "html.passive", "html.active")
	if err != nil {
		return nil, err
	}
	writers.add(writerRoutesHTML, htmlPair)

	imagesPair, err := createPair(filepath.Join("routes", "images"), "", "images.active")
	if err != nil {
		return nil, err
	}
	writers.add(writerRoutesImages, imagesPair)

	certsPair, err := createPair("certs", "certs.passive", "certs.active")
	if err != nil {
		return nil, err
	}
	writers.add(writerCerts, certsPair)

	metaPair, err := createPair("", "meta.passive", "meta.active")
	if err != nil {
		return nil, err
	}
	writers.add(writerMeta, metaPair)

	writers.add(writerRoutesMaps, makeLazyWriterPair(outdir, filepath.Join("routes", "maps"), "maps.passive", "maps.active"))
	writers.add(writerRoutesJSON, makeLazyWriterPair(outdir, filepath.Join("routes", "json"), "json.passive", "json.active"))
	writers.add(writerRoutesAPI, makeLazyWriterPair(outdir, filepath.Join("routes", "api"), "api.passive", "api.active"))
	writers.add(writerRoutesWASM, makeLazyWriterPair(outdir, filepath.Join("routes", "wasm"), "wasm.passive", "wasm.active"))
	writers.add(writerRoutesSVG, makeLazyWriterPair(outdir, filepath.Join("routes", "svg"), "svg.passive", "svg.active"))
	writers.add(writerRoutesCrawl, makeLazyWriterPair(outdir, filepath.Join("routes", "crawl"), "crawl.passive", "crawl.active"))
	writers.add(writerRoutesMeta, makeLazyWriterPair(outdir, filepath.Join("routes", "meta"), "meta.passive", "meta.active"))

	if err := ensureOutputFile(outdir, "", "artifacts.jsonl"); err != nil {
		return nil, err
	}

	artifactsPath := filepath.Join(outdir, "artifacts.jsonl")
	store := newJSONLStore(artifactsPath)
	dedup := NewDedupe()

	s := &Sink{
		writers:        writers,
		artifacts:      store,
		dedup:          dedup,
		scope:          netutil.NewScope(target),
		activeMode:     active,
		lines:          make(chan string, lineBuffer),
		handlerMetrics: make(map[string]*handlerStats),
	}
	s.cond = sync.NewCond(&s.procMu)
	s.ctx = &Context{S: s, Store: store, Dedup: dedup}
	s.registry = buildHandlerRegistry()
	return s, nil
}

func buildHandlerRegistry() *HandlerRegistry {
	registry := NewHandlerRegistry()
	registry.Register(WithMetrics("handleDNS", NewHandler("handleDNS", "dns:", handleDNS)))
	registry.Register(WithMetrics("handleMeta", NewHandler("handleMeta", "meta:", handleMeta)))
	registry.Register(WithMetrics("handleGFFinding", NewHandler("handleGFFinding", "gffinding:", handleGFFinding)))
	registry.Register(WithMetrics("handleRDAP", NewHandler("handleRDAP", "rdap:", handleRDAP)))
	registry.Register(WithMetrics("handleJS", NewHandler("handleJS", "js:", handleJS)))
	registry.Register(WithMetrics("handleHTML", NewHandler("handleHTML", "html:", handleHTML)))
	registry.Register(WithMetrics("handleMaps", NewHandler("handleMaps", "maps:", handleMaps)))
	registry.Register(WithMetrics("handleJSONCategory", NewHandler("handleJSONCategory", "json:", handleJSONCategory)))
	registry.Register(WithMetrics("handleAPICategory", NewHandler("handleAPICategory", "api:", handleAPICategory)))
	registry.Register(WithMetrics("handleWASMCategory", NewHandler("handleWASMCategory", "wasm:", handleWASMCategory)))
	registry.Register(WithMetrics("handleSVGCategory", NewHandler("handleSVGCategory", "svg:", handleSVGCategory)))
	registry.Register(WithMetrics("handleCrawlCategory", NewHandler("handleCrawlCategory", "crawl:", handleCrawlCategory)))
	registry.Register(WithMetrics("handleMetaCategory", NewHandler("handleMetaCategory", "meta-route:", handleMetaCategory)))
	registry.Register(WithMetrics("handleCert", NewHandler("handleCert", "cert:", handleCert)))

	registry.Register(WithMetrics("handleRelation", NewHandler("handleRelation", "", handleRelation)))
	registry.Register(WithMetrics("handleMetaFallback", NewHandler("handleMeta", "", handleMeta)))
	registry.Register(WithMetrics("handleRoute", NewHandler("handleRoute", "", handleRoute)))
	registry.Register(WithMetrics("handleCertFallback", NewHandler("handleCert", "", handleCert)))
	registry.Register(WithMetrics("handleDomain", NewHandler("handleDomain", "", handleDomain)))
	return registry
}

func (s *Sink) Start(workers int) {
	if workers < 1 {
		workers = 1
	}
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for ln := range s.lines {
				s.beginLine()
				s.processLine(ln)
				s.finishLine()
			}
		}()
	}
}

func (s *Sink) In() chan<- string { return s.lines }

func (s *Sink) InWithTool(tool string) (chan<- string, func()) {
	tool = strings.TrimSpace(tool)
	if tool == "" || s == nil {
		return s.In(), func() {}
	}
	ch := make(chan string)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for line := range ch {
			s.lines <- WrapWithTool(tool, line)
		}
	}()
	cleanup := func() {
		close(ch)
		wg.Wait()
	}
	return ch, cleanup
}

func (s *Sink) beginLine() {
	s.procMu.Lock()
	s.processing++
	s.procMu.Unlock()
}

func (s *Sink) finishLine() {
	s.procMu.Lock()
	s.processing--
	if s.processing == 0 && len(s.lines) == 0 {
		s.cond.Broadcast()
	}
	s.procMu.Unlock()
}

// WrapWithTool anota una línea con el nombre del script que la generó para que el
// Sink pueda rastrear el origen del hallazgo.
func WrapWithTool(tool, line string) string {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return line
	}
	return toolMarker + tool + toolSeparator + line
}

func unwrapTool(line string) (string, string) {
	if !strings.HasPrefix(line, toolMarker) {
		return "", line
	}
	remainder := line[len(toolMarker):]
	idx := strings.Index(remainder, toolSeparator)
	if idx < 0 {
		return "", line
	}
	tool := strings.TrimSpace(remainder[:idx])
	rest := remainder[idx+len(toolSeparator):]
	return tool, rest
}

func (s *Sink) processLine(ln string) {
	if s == nil {
		return
	}
	tool, raw := unwrapTool(ln)
	line := strings.TrimSpace(raw)
	if line == "" {
		return
	}
	isActive := false
	if strings.HasPrefix(line, "active:") {
		isActive = true
		line = strings.TrimSpace(strings.TrimPrefix(line, "active:"))
		if line == "" {
			return
		}
	}

	prefix := extractPrefix(line)
	if prefix != "" {
		if handler := s.registry.Lookup(prefix); handler != nil {
			if handler.Handle(s.ctx, line, isActive, tool) {
				return
			}
		}
	}

	for _, handler := range s.registry.Fallbacks() {
		if handler.Handle(s.ctx, line, isActive, tool) {
			return
		}
	}
}

func extractPrefix(line string) string {
	idx := strings.Index(line, ":")
	if idx <= 0 {
		return ""
	}
	prefix := strings.ToLower(strings.TrimSpace(line[:idx]))
	if prefix == "" {
		return ""
	}
	return prefix + ":"
}

func (s *Sink) Flush() {
	s.procMu.Lock()
	for len(s.lines) > 0 || s.processing > 0 {
		s.cond.Wait()
	}
	s.procMu.Unlock()
	_ = s.artifacts.Flush()
}

func (s *Sink) Close() error {
	close(s.lines)
	s.wg.Wait()
	if err := s.artifacts.Flush(); err != nil {
		return err
	}
	if err := s.writers.closeAll(); err != nil {
		return err
	}
	return s.artifacts.Close()
}

// Helper para ejecutar una fuente con contexto y volcar al sink
type SourceFunc func(ctx context.Context, target string, out chan<- string) error

func (s *Sink) writer(key string, active bool) sinkWriter {
	pair := s.writers.pair(key)
	return pair.writer(active)
}

func (s *Sink) writerPair(key string) writerPair {
	return s.writers.pair(key)
}

func (s *Sink) inActiveMode() bool { return s != nil && s.activeMode }

func (s *Sink) scopeAllowsDomain(domain string) bool {
	if s == nil || s.scope == nil {
		return true
	}
	return s.scope.AllowsDomain(domain)
}

func (s *Sink) scopeAllowsRoute(route string) bool {
	if s == nil || s.scope == nil {
		return true
	}
	return s.scope.AllowsRoute(route)
}
