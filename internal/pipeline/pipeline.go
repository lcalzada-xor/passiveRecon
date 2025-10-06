package pipeline

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"passive-rec/internal/certs"
	"passive-rec/internal/netutil"
	"passive-rec/internal/out"
	"passive-rec/internal/routes"
)

type sinkWriter interface {
	WriteURL(string) error
	WriteRaw(string) error
	WriteDomain(string) error
	Close() error
}

type writerPair struct {
	passive sinkWriter
	active  sinkWriter
}

const (
	defaultLineBuffer   = 1024
	lineBufferPerWorker = 256
)

type lazyWriter struct {
	outdir  string
	subdir  string
	name    string
	mu      sync.RWMutex
	writer  *out.Writer
	initErr error
}

func newLazyWriter(outdir, subdir, name string) *lazyWriter {
	return &lazyWriter{outdir: outdir, subdir: subdir, name: name}
}

func (lw *lazyWriter) ensure() (*out.Writer, error) {
	lw.mu.RLock()
	if lw.initErr != nil {
		err := lw.initErr
		lw.mu.RUnlock()
		return nil, err
	}
	if lw.writer != nil {
		writer := lw.writer
		lw.mu.RUnlock()
		return writer, nil
	}
	lw.mu.RUnlock()

	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.initErr != nil {
		return nil, lw.initErr
	}
	if lw.writer != nil {
		return lw.writer, nil
	}
	targetDir := lw.outdir
	if lw.subdir != "" {
		targetDir = filepath.Join(targetDir, lw.subdir)
	}
	w, err := out.New(targetDir, lw.name)
	if err != nil {
		lw.initErr = err
		return nil, err
	}
	lw.writer = w
	return lw.writer, nil
}

func (lw *lazyWriter) WriteURL(u string) error {
	if lw == nil {
		return nil
	}
	if u == "" {
		return nil
	}
	w, err := lw.ensure()
	if err != nil {
		return err
	}
	return w.WriteURL(u)
}

func (lw *lazyWriter) WriteRaw(line string) error {
	if lw == nil {
		return nil
	}
	if line == "" {
		return nil
	}
	w, err := lw.ensure()
	if err != nil {
		return err
	}
	return w.WriteRaw(line)
}

func (lw *lazyWriter) WriteDomain(domain string) error {
	if lw == nil {
		return nil
	}
	if domain == "" {
		return nil
	}
	w, err := lw.ensure()
	if err != nil {
		return err
	}
	return w.WriteDomain(domain)
}

func (lw *lazyWriter) Close() error {
	if lw == nil {
		return nil
	}
	lw.mu.Lock()
	w := lw.writer
	lw.writer = nil
	lw.mu.Unlock()
	if w != nil {
		return w.Close()
	}
	return nil
}

type handlerStats struct {
	total time.Duration
	count uint64
}

// HandlerMetric resume el desempeño de un handler del pipeline.
type HandlerMetric struct {
	Name    string
	Count   uint64
	Total   time.Duration
	Average time.Duration
}

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
	Domains               writerPair
	Routes                writerPair
	RoutesJS              writerPair
	RoutesHTML            writerPair
	RoutesImages          writerPair
	RDAP                  writerPair
	RoutesMaps            writerPair
	RoutesJSON            writerPair
	RoutesAPI             writerPair
	RoutesWASM            writerPair
	RoutesSVG             writerPair
	RoutesCrawl           writerPair
	RoutesMetaFindings    writerPair
	Certs                 writerPair
	Meta                  writerPair
	wg                    sync.WaitGroup
	lines                 chan string
	handlerMetrics        map[string]*handlerStats
	metricsMu             sync.Mutex
	seenMu                sync.Mutex
	seenDomainsPassive    map[string]struct{}
	seenDomainsActive     map[string]struct{}
	seenRoutesPassive     map[string]struct{}
	seenRoutesActive      map[string]struct{}
	seenHTMLPassive       map[string]struct{}
	seenHTMLActive        map[string]struct{}
	seenHTMLImagesPassive map[string]struct{}
	seenHTMLImagesActive  map[string]struct{}
	seenRoutesMaps        map[string]struct{}
	seenRoutesJSON        map[string]struct{}
	seenRoutesAPI         map[string]struct{}
	seenRoutesWASM        map[string]struct{}
	seenRoutesSVG         map[string]struct{}
	seenRoutesCrawl       map[string]struct{}
	seenRoutesMeta        map[string]struct{}
	seenCertsPassive      map[string]struct{}
	seenCertsActive       map[string]struct{}
	procMu                sync.Mutex
	processing            int
	cond                  *sync.Cond
	activeMode            bool
	scope                 *netutil.Scope
}

func NewSink(outdir string, active bool, target string, lineBuffer int) (*Sink, error) {
	if lineBuffer <= 0 {
		lineBuffer = defaultLineBuffer
	}
	var opened []sinkWriter
	newWriter := func(subdir, name string) (*out.Writer, error) {
		targetDir := outdir
		if subdir != "" {
			targetDir = filepath.Join(outdir, subdir)
		}
		w, err := out.New(targetDir, name)
		if err != nil {
			for _, ow := range opened {
				_ = ow.Close()
			}
			return nil, err
		}
		opened = append(opened, w)
		return w, nil
	}

	if err := os.MkdirAll(filepath.Join(outdir, "dns"), 0o755); err != nil {
		return nil, err
	}

	dPassive, err := newWriter("domains", "domains.passive")
	if err != nil {
		return nil, err
	}
	dActive, err := newWriter("domains", "domains.active")
	if err != nil {
		return nil, err
	}
	rPassive, err := newWriter("routes", "routes.passive")
	if err != nil {
		return nil, err
	}
	rActive, err := newWriter("routes", "routes.active")
	if err != nil {
		return nil, err
	}
	rdapPassive, err := newWriter("rdap", "rdap.passive")
	if err != nil {
		return nil, err
	}
	jsPassive, err := newWriter(filepath.Join("routes", "js"), "js.passive")
	if err != nil {
		return nil, err
	}
	jsActive, err := newWriter(filepath.Join("routes", "js"), "js.active")
	if err != nil {
		return nil, err
	}
	htmlPassive, err := newWriter(filepath.Join("routes", "html"), "html.passive")
	if err != nil {
		return nil, err
	}
	htmlActive, err := newWriter(filepath.Join("routes", "html"), "html.active")
	if err != nil {
		return nil, err
	}
	imagesActive, err := newWriter(filepath.Join("routes", "images"), "images.active")
	if err != nil {
		return nil, err
	}
	cPassive, err := newWriter("certs", "certs.passive")
	if err != nil {
		return nil, err
	}
	cActive, err := newWriter("certs", "certs.active")
	if err != nil {
		return nil, err
	}
	mPassive, err := newWriter("", "meta.passive")
	if err != nil {
		return nil, err
	}
	mActive, err := newWriter("", "meta.active")
	if err != nil {
		return nil, err
	}

	s := &Sink{
		Domains:               writerPair{passive: dPassive, active: dActive},
		Routes:                writerPair{passive: rPassive, active: rActive},
		RoutesJS:              writerPair{passive: jsPassive, active: jsActive},
		RoutesHTML:            writerPair{passive: htmlPassive, active: htmlActive},
		RoutesImages:          writerPair{active: imagesActive},
		RDAP:                  writerPair{passive: rdapPassive},
		RoutesMaps:            writerPair{passive: newLazyWriter(outdir, filepath.Join("routes", "maps"), "maps.passive"), active: newLazyWriter(outdir, filepath.Join("routes", "maps"), "maps.active")},
		RoutesJSON:            writerPair{passive: newLazyWriter(outdir, filepath.Join("routes", "json"), "json.passive"), active: newLazyWriter(outdir, filepath.Join("routes", "json"), "json.active")},
		RoutesAPI:             writerPair{passive: newLazyWriter(outdir, filepath.Join("routes", "api"), "api.passive"), active: newLazyWriter(outdir, filepath.Join("routes", "api"), "api.active")},
		RoutesWASM:            writerPair{passive: newLazyWriter(outdir, filepath.Join("routes", "wasm"), "wasm.passive"), active: newLazyWriter(outdir, filepath.Join("routes", "wasm"), "wasm.active")},
		RoutesSVG:             writerPair{passive: newLazyWriter(outdir, filepath.Join("routes", "svg"), "svg.passive"), active: newLazyWriter(outdir, filepath.Join("routes", "svg"), "svg.active")},
		RoutesCrawl:           writerPair{passive: newLazyWriter(outdir, filepath.Join("routes", "crawl"), "crawl.passive"), active: newLazyWriter(outdir, filepath.Join("routes", "crawl"), "crawl.active")},
		RoutesMetaFindings:    writerPair{passive: newLazyWriter(outdir, filepath.Join("routes", "meta"), "meta.passive"), active: newLazyWriter(outdir, filepath.Join("routes", "meta"), "meta.active")},
		Certs:                 writerPair{passive: cPassive, active: cActive},
		Meta:                  writerPair{passive: mPassive, active: mActive},
		lines:                 make(chan string, lineBuffer),
		handlerMetrics:        make(map[string]*handlerStats),
		seenDomainsPassive:    make(map[string]struct{}),
		seenDomainsActive:     make(map[string]struct{}),
		seenRoutesPassive:     make(map[string]struct{}),
		seenRoutesActive:      make(map[string]struct{}),
		seenHTMLPassive:       make(map[string]struct{}),
		seenHTMLActive:        make(map[string]struct{}),
		seenHTMLImagesPassive: make(map[string]struct{}),
		seenHTMLImagesActive:  make(map[string]struct{}),
		seenRoutesMaps:        make(map[string]struct{}),
		seenRoutesJSON:        make(map[string]struct{}),
		seenRoutesAPI:         make(map[string]struct{}),
		seenRoutesWASM:        make(map[string]struct{}),
		seenRoutesSVG:         make(map[string]struct{}),
		seenRoutesCrawl:       make(map[string]struct{}),
		seenRoutesMeta:        make(map[string]struct{}),
		seenCertsPassive:      make(map[string]struct{}),
		seenCertsActive:       make(map[string]struct{}),
		activeMode:            active,
		scope:                 netutil.NewScope(target),
	}
	s.cond = sync.NewCond(&s.procMu)
	return s, nil
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

type lineHandler func(*Sink, string, bool) bool

var prefixHandlers = []struct {
	prefix  string
	name    string
	handler lineHandler
}{
	{prefix: "meta:", name: "handleMeta", handler: handleMeta},
	{prefix: "rdap:", name: "handleRDAP", handler: handleRDAP},
	{prefix: "js:", name: "handleJS", handler: handleJS},
	{prefix: "html:", name: "handleHTML", handler: handleHTML},
	{prefix: "maps:", name: "handleMaps", handler: handleMaps},
	{prefix: "json:", name: "handleJSONCategory", handler: handleJSONCategory},
	{prefix: "api:", name: "handleAPICategory", handler: handleAPICategory},
	{prefix: "wasm:", name: "handleWASMCategory", handler: handleWASMCategory},
	{prefix: "svg:", name: "handleSVGCategory", handler: handleSVGCategory},
	{prefix: "crawl:", name: "handleCrawlCategory", handler: handleCrawlCategory},
	{prefix: "meta-route:", name: "handleMetaCategory", handler: handleMetaCategory},
	{prefix: "cert:", name: "handleCert", handler: handleCert},
}

func (s *Sink) processLine(ln string) {
	l := strings.TrimSpace(ln)
	if l == "" {
		return
	}

	isActive := false
	if strings.HasPrefix(l, "active:") {
		isActive = true
		l = strings.TrimSpace(strings.TrimPrefix(l, "active:"))
		if l == "" {
			return
		}
	}

	for _, entry := range prefixHandlers {
		if strings.HasPrefix(l, entry.prefix) {
			if s.timedHandle(entry.name, entry.handler, l, isActive) {
				return
			}
		}
	}

	if s.timedHandle("handleMeta", handleMeta, l, isActive) {
		return
	}
	if s.timedHandle("handleRoute", handleRoute, l, isActive) {
		return
	}
	if s.timedHandle("handleCert", handleCert, l, isActive) {
		return
	}
	_ = s.timedHandle("handleDomain", handleDomain, l, isActive)
}

func (s *Sink) timedHandle(name string, handler lineHandler, line string, isActive bool) bool {
	start := time.Now()
	handled := handler(s, line, isActive)
	s.recordHandlerMetric(name, time.Since(start))
	return handled
}

func (s *Sink) recordHandlerMetric(name string, elapsed time.Duration) {
	s.metricsMu.Lock()
	stat := s.handlerMetrics[name]
	if stat == nil {
		stat = &handlerStats{}
		s.handlerMetrics[name] = stat
	}
	stat.total += elapsed
	stat.count++
	s.metricsMu.Unlock()
}

// HandlerMetrics devuelve una instantánea ordenada de las métricas recolectadas
// para cada handler. El orden es descendente por promedio y estable alfabéticamente
// en caso de empate para facilitar la inspección.
func (s *Sink) HandlerMetrics() []HandlerMetric {
	s.metricsMu.Lock()
	defer s.metricsMu.Unlock()
	metrics := make([]HandlerMetric, 0, len(s.handlerMetrics))
	for name, stat := range s.handlerMetrics {
		if stat == nil || stat.count == 0 {
			continue
		}
		avg := time.Duration(int64(stat.total) / int64(stat.count))
		metrics = append(metrics, HandlerMetric{
			Name:    name,
			Count:   stat.count,
			Total:   stat.total,
			Average: avg,
		})
	}
	sort.Slice(metrics, func(i, j int) bool {
		if metrics[i].Average == metrics[j].Average {
			return metrics[i].Name < metrics[j].Name
		}
		return metrics[i].Average > metrics[j].Average
	})
	return metrics
}

func handleMeta(s *Sink, line string, isActive bool) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}

	target := s.Meta.passive
	if isActive {
		target = s.Meta.active
	}
	if target == nil {
		return true
	}

	if strings.HasPrefix(trimmed, "meta:") {
		content := strings.TrimSpace(strings.TrimPrefix(trimmed, "meta:"))
		if content == "" {
			return true
		}
		_ = target.WriteRaw(content)
		return true
	}

	if strings.Contains(trimmed, "-->") || strings.Contains(trimmed, " (") {
		_ = target.WriteRaw(trimmed)
		return true
	}

	return false
}

func handleRDAP(s *Sink, line string, isActive bool) bool {
	if isActive {
		return true
	}
	content := strings.TrimSpace(strings.TrimPrefix(line, "rdap:"))
	if content == "" {
		return true
	}
	if s.RDAP.passive == nil {
		return true
	}
	_ = s.RDAP.passive.WriteRaw(content)
	return true
}

func handleJS(s *Sink, line string, isActive bool) bool {
	js := strings.TrimSpace(strings.TrimPrefix(line, "js:"))
	if js == "" {
		return true
	}
	base := extractRouteBase(js)
	if base != "" && s.scope != nil && !s.scope.AllowsRoute(base) {
		return true
	}
	if isActive {
		if status, ok := parseActiveRouteStatus(js, base); ok {
			if status <= 0 || status >= 400 {
				return true
			}
		}
		if s.RoutesJS.active != nil {
			_ = s.RoutesJS.active.WriteRaw(js)
		}
		return true
	}
	if s.RoutesJS.passive != nil {
		_ = s.RoutesJS.passive.WriteURL(js)
	}
	return true
}

func handleHTML(s *Sink, line string, isActive bool) bool {
	html := strings.TrimSpace(strings.TrimPrefix(line, "html:"))
	if html == "" {
		return true
	}

	base := html
	if isActive {
		base = extractRouteBase(html)
		if status, ok := parseActiveRouteStatus(html, base); ok {
			if status <= 0 || status >= 400 {
				return true
			}
		}
	}

	if base != "" && s.scope != nil && !s.scope.AllowsRoute(base) {
		return true
	}

	imageTarget := html
	if base != "" {
		imageTarget = base
	}

	if isImageURL(imageTarget) {
		seen := s.seenHTMLImagesPassive
		writer := s.RoutesImages.passive
		if isActive {
			seen = s.seenHTMLImagesActive
			writer = s.RoutesImages.active
		}
		if writer == nil {
			return true
		}
		if seen != nil && s.markSeen(seen, html) {
			return true
		}
		if isActive {
			_ = writer.WriteRaw(html)
			return true
		}
		_ = writer.WriteURL(html)
		return true
	}

	seen := s.seenHTMLPassive
	writer := s.RoutesHTML.passive
	if isActive {
		seen = s.seenHTMLActive
		writer = s.RoutesHTML.active
	}
	if writer == nil {
		return true
	}
	if seen != nil && s.markSeen(seen, html) {
		return true
	}
	if isActive {
		_ = writer.WriteRaw(html)
		return true
	}
	_ = writer.WriteURL(html)
	return true
}

func handleMaps(s *Sink, line string, isActive bool) bool {
	return handleCategorizedRoute(s, line, isActive, "maps:", s.RoutesMaps, s.seenRoutesMaps, true)
}

func handleJSONCategory(s *Sink, line string, isActive bool) bool {
	return handleCategorizedRoute(s, line, isActive, "json:", s.RoutesJSON, s.seenRoutesJSON, true)
}

func handleAPICategory(s *Sink, line string, isActive bool) bool {
	return handleCategorizedRoute(s, line, isActive, "api:", s.RoutesAPI, s.seenRoutesAPI, true)
}

func handleWASMCategory(s *Sink, line string, isActive bool) bool {
	return handleCategorizedRoute(s, line, isActive, "wasm:", s.RoutesWASM, s.seenRoutesWASM, true)
}

func handleSVGCategory(s *Sink, line string, isActive bool) bool {
	return handleCategorizedRoute(s, line, isActive, "svg:", s.RoutesSVG, s.seenRoutesSVG, true)
}

func handleCrawlCategory(s *Sink, line string, isActive bool) bool {
	return handleCategorizedRoute(s, line, isActive, "crawl:", s.RoutesCrawl, s.seenRoutesCrawl, true)
}

func handleMetaCategory(s *Sink, line string, isActive bool) bool {
	return handleCategorizedRoute(s, line, isActive, "meta-route:", s.RoutesMetaFindings, s.seenRoutesMeta, false)
}

func handleCategorizedRoute(s *Sink, line string, isActive bool, prefix string, writers writerPair, seen map[string]struct{}, normalizePassive bool) bool {
	value := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if value == "" {
		return true
	}

	if seen != nil {
		key := value
		if isActive {
			key = "active:" + key
		}
		if s.markSeen(seen, key) {
			return true
		}
	}

	target := writers.passive
	if isActive {
		target = writers.active
	}
	if target == nil {
		return true
	}

	if isActive || !normalizePassive {
		_ = target.WriteRaw(value)
		return true
	}

	_ = target.WriteURL(value)
	return true
}

func handleRoute(s *Sink, line string, isActive bool) bool {
	base := extractRouteBase(line)
	if base == "" {
		return false
	}
	if !(strings.Contains(base, "://") || strings.HasPrefix(base, "/") || strings.Contains(base, "/")) {
		return false
	}

	if s.scope != nil && !s.scope.AllowsRoute(base) {
		return true
	}

	if isActive {
		if !s.markSeen(s.seenRoutesPassive, base) {
			if s.Routes.passive != nil {
				_ = s.Routes.passive.WriteURL(base)
			}
		}
	}

	seen := s.seenRoutesPassive
	writer := s.Routes.passive
	if isActive {
		seen = s.seenRoutesActive
		writer = s.Routes.active
		if status, ok := parseActiveRouteStatus(line, base); ok {
			if status <= 0 || status >= 400 {
				return true
			}
		}
	}
	if writer == nil {
		return true
	}
	if s.markSeen(seen, line) {
		return true
	}
	if !isActive || shouldCategorizeActiveRoute(line, base) {
		s.writeRouteCategories(base, isActive)
	}
	_ = writer.WriteURL(line)
	return true
}

func handleCert(s *Sink, line string, isActive bool) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}

	if strings.HasPrefix(trimmed, "cert:") {
		s.writeCertLine(strings.TrimSpace(strings.TrimPrefix(trimmed, "cert:")), isActive)
		return true
	}

	return false
}

func handleDomain(s *Sink, line string, isActive bool) bool {
	key := netutil.NormalizeDomain(line)
	if key == "" {
		return false
	}

	if s.scope != nil && !s.scope.AllowsDomain(key) {
		return true
	}

	if isActive {
		if !s.markSeen(s.seenDomainsPassive, key) {
			if s.Domains.passive != nil {
				_ = s.Domains.passive.WriteDomain(key)
			}
		}
	}

	seen := s.seenDomainsPassive
	writer := s.Domains.passive
	if isActive {
		seen = s.seenDomainsActive
		writer = s.Domains.active
	}
	if writer == nil {
		return true
	}
	if s.markSeen(seen, key) {
		return true
	}
	_ = writer.WriteDomain(line)
	return true
}

func (s *Sink) Flush() {
	s.procMu.Lock()
	for len(s.lines) > 0 || s.processing > 0 {
		s.cond.Wait()
	}
	s.procMu.Unlock()
}

func (s *Sink) Close() error {
	close(s.lines)
	s.wg.Wait()
	if s.Domains.passive != nil {
		_ = s.Domains.passive.Close()
	}
	if s.Domains.active != nil {
		_ = s.Domains.active.Close()
	}
	if s.Routes.passive != nil {
		_ = s.Routes.passive.Close()
	}
	if s.Routes.active != nil {
		_ = s.Routes.active.Close()
	}
	if s.RoutesJS.passive != nil {
		_ = s.RoutesJS.passive.Close()
	}
	if s.RoutesJS.active != nil {
		_ = s.RoutesJS.active.Close()
	}
	if s.RoutesHTML.passive != nil {
		_ = s.RoutesHTML.passive.Close()
	}
	if s.RoutesHTML.active != nil {
		_ = s.RoutesHTML.active.Close()
	}
	if s.RDAP.passive != nil {
		_ = s.RDAP.passive.Close()
	}
	if s.RoutesImages.passive != nil {
		_ = s.RoutesImages.passive.Close()
	}
	if s.RoutesImages.active != nil {
		_ = s.RoutesImages.active.Close()
	}
	if s.RoutesMaps.passive != nil {
		_ = s.RoutesMaps.passive.Close()
	}
	if s.RoutesMaps.active != nil {
		_ = s.RoutesMaps.active.Close()
	}
	if s.RoutesJSON.passive != nil {
		_ = s.RoutesJSON.passive.Close()
	}
	if s.RoutesJSON.active != nil {
		_ = s.RoutesJSON.active.Close()
	}
	if s.RoutesAPI.passive != nil {
		_ = s.RoutesAPI.passive.Close()
	}
	if s.RoutesAPI.active != nil {
		_ = s.RoutesAPI.active.Close()
	}
	if s.RoutesWASM.passive != nil {
		_ = s.RoutesWASM.passive.Close()
	}
	if s.RoutesWASM.active != nil {
		_ = s.RoutesWASM.active.Close()
	}
	if s.RoutesSVG.passive != nil {
		_ = s.RoutesSVG.passive.Close()
	}
	if s.RoutesSVG.active != nil {
		_ = s.RoutesSVG.active.Close()
	}
	if s.RoutesCrawl.passive != nil {
		_ = s.RoutesCrawl.passive.Close()
	}
	if s.RoutesCrawl.active != nil {
		_ = s.RoutesCrawl.active.Close()
	}
	if s.RoutesMetaFindings.passive != nil {
		_ = s.RoutesMetaFindings.passive.Close()
	}
	if s.RoutesMetaFindings.active != nil {
		_ = s.RoutesMetaFindings.active.Close()
	}
	if s.Certs.passive != nil {
		_ = s.Certs.passive.Close()
	}
	if s.Certs.active != nil {
		_ = s.Certs.active.Close()
	}
	if s.Meta.passive != nil {
		_ = s.Meta.passive.Close()
	}
	if s.Meta.active != nil {
		_ = s.Meta.active.Close()
	}
	return nil
}

// Helper para ejecutar una fuente con contexto y volcar al sink
type SourceFunc func(ctx context.Context, target string, out chan<- string) error

func (s *Sink) markSeen(seen map[string]struct{}, key string) bool {
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	if _, ok := seen[key]; ok {
		return true
	}
	seen[key] = struct{}{}
	return false
}

func (s *Sink) writeLazyCategory(route string, isActive bool, writers writerPair, seen map[string]struct{}) {
	if seen == nil {
		return
	}
	if s.scope != nil && !s.scope.AllowsRoute(route) {
		return
	}
	key := route
	if isActive {
		key = "active:" + route
	}
	if s.markSeen(seen, key) {
		return
	}
	target := writers.passive
	if isActive {
		target = writers.active
	}
	if target == nil {
		return
	}
	if isActive {
		_ = target.WriteRaw(route)
		return
	}
	_ = target.WriteURL(route)
}

func (s *Sink) writeCertLine(line string, isActive bool) {
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
		if domain == "" || (s.scope != nil && !s.scope.AllowsDomain(domain)) {
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
			if s.scope != nil && !s.scope.AllowsDomain(domain) {
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
		if !s.markSeen(s.seenDomainsPassive, domain) {
			if s.Domains.passive != nil {
				_ = s.Domains.passive.WriteDomain(domain)
			}
		}
		if s.activeMode {
			if !s.markSeen(s.seenDomainsActive, domain) {
				if s.Domains.active != nil {
					_ = s.Domains.active.WriteDomain(domain)
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

	seen := s.seenCertsPassive
	target := s.Certs.passive
	if isActive {
		seen = s.seenCertsActive
		target = s.Certs.active
	}
	if seen != nil && s.markSeen(seen, key) {
		return
	}

	if target != nil {
		_ = target.WriteRaw(serialized)
	}
}

func extractRouteBase(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ""
	}
	if idx := strings.IndexAny(trimmed, " \t"); idx != -1 {
		trimmed = trimmed[:idx]
	}
	return strings.TrimSpace(trimmed)
}

func (s *Sink) writeRouteCategories(route string, isActive bool) {
	if route == "" {
		return
	}
	categories := routes.DetectCategories(route)
	if len(categories) == 0 {
		return
	}
	categoryTargets := map[routes.Category]struct {
		writers writerPair
		seen    map[string]struct{}
	}{
		routes.CategoryMaps: {
			writers: s.RoutesMaps,
			seen:    s.seenRoutesMaps,
		},
		routes.CategoryJSON: {
			writers: s.RoutesJSON,
			seen:    s.seenRoutesJSON,
		},
		routes.CategoryAPI: {
			writers: s.RoutesAPI,
			seen:    s.seenRoutesAPI,
		},
		routes.CategoryWASM: {
			writers: s.RoutesWASM,
			seen:    s.seenRoutesWASM,
		},
		routes.CategorySVG: {
			writers: s.RoutesSVG,
			seen:    s.seenRoutesSVG,
		},
		routes.CategoryCrawl: {
			writers: s.RoutesCrawl,
			seen:    s.seenRoutesCrawl,
		},
		routes.CategoryMeta: {
			writers: s.RoutesMetaFindings,
			seen:    s.seenRoutesMeta,
		},
	}
	for _, cat := range categories {
		if target, ok := categoryTargets[cat]; ok {
			s.writeLazyCategory(route, isActive, target.writers, target.seen)
		}
	}
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
