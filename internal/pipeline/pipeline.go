package pipeline

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

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

// Artifact representa un hallazgo generado por el pipeline y serializado en el
// manifiesto JSONL.
type Artifact struct {
	Type        string         `json:"type"`
	Types       []string       `json:"types,omitempty"`
	Value       string         `json:"value"`
	Active      bool           `json:"active"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	Tool        string         `json:"tool,omitempty"`
	Tools       []string       `json:"tools,omitempty"`
	Occurrences int            `json:"occurrences,omitempty"`
}

type artifactKey struct {
	Value  string
	Active bool
}

type artifactRecord struct {
	Artifact    Artifact
	Tools       map[string]struct{}
	Occurrences int
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
	Artifacts             *lazyWriter
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
	artifactMu            sync.Mutex
	artifactIndex         map[artifactKey]*artifactRecord
	artifactOrder         []artifactKey
	artifactsPath         string
	artifactsDirty        bool
}

func ensureOutputFile(base, subdir, name string) error {
	targetDir := base
	if subdir != "" {
		targetDir = filepath.Join(base, subdir)
	}
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}
	path := filepath.Join(targetDir, name)
	if info, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			f, createErr := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
			if createErr != nil {
				return createErr
			}
			return f.Close()
		}
		return err
	} else if !info.Mode().IsRegular() {
		return fmt.Errorf("%s exists and is not a regular file", path)
	}
	return nil
}

func NewSink(outdir string, active bool, target string, lineBuffer int) (*Sink, error) {
	if lineBuffer <= 0 {
		lineBuffer = defaultLineBuffer
	}
	newWriter := func(subdir, name string) (sinkWriter, error) {
		if err := ensureOutputFile(outdir, subdir, name); err != nil {
			return nil, err
		}
		return newLazyWriter(outdir, subdir, name), nil
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
	if err := ensureOutputFile(outdir, "", "artifacts.jsonl"); err != nil {
		return nil, err
	}

	artifactsPath := filepath.Join(outdir, "artifacts.jsonl")

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
		Artifacts:             newLazyWriter(outdir, "", "artifacts.jsonl"),
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
		artifactIndex:         make(map[artifactKey]*artifactRecord),
		artifactsPath:         artifactsPath,
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

const (
	toolMarker    = "\x00tool:"
	toolSeparator = "\x00"
)

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

type lineHandler func(*Sink, string, bool, string) bool

var prefixHandlers = []struct {
	prefix  string
	name    string
	handler lineHandler
}{
	{prefix: "dns:", name: "handleDNS", handler: handleDNS},
	{prefix: "meta:", name: "handleMeta", handler: handleMeta},
	{prefix: "gffinding:", name: "handleGFFinding", handler: handleGFFinding},
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
	tool, raw := unwrapTool(ln)
	l := strings.TrimSpace(raw)
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
			if s.timedHandle(entry.name, entry.handler, l, isActive, tool) {
				return
			}
		}
	}

	if s.timedHandle("handleRelation", handleRelation, l, isActive, tool) {
		return
	}
	if s.timedHandle("handleMeta", handleMeta, l, isActive, tool) {
		return
	}
	if s.timedHandle("handleRoute", handleRoute, l, isActive, tool) {
		return
	}
	if s.timedHandle("handleCert", handleCert, l, isActive, tool) {
		return
	}
	_ = s.timedHandle("handleDomain", handleDomain, l, isActive, tool)
}

func (s *Sink) timedHandle(name string, handler lineHandler, line string, isActive bool, tool string) bool {
	start := time.Now()
	handled := handler(s, line, isActive, tool)
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

func (s *Sink) recordArtifact(tool string, artifact Artifact) {
	if s == nil || s.Artifacts == nil {
		return
	}
	normalized, ok := normalizeArtifact(tool, artifact)
	if !ok {
		return
	}

	key := artifactKey{Value: normalized.Value, Active: normalized.Active}

	s.artifactMu.Lock()
	defer s.artifactMu.Unlock()

	rec, exists := s.artifactIndex[key]
	if !exists {
		rec = &artifactRecord{Artifact: normalized, Tools: make(map[string]struct{})}
		s.artifactIndex[key] = rec
		s.artifactOrder = append(s.artifactOrder, key)
	} else {
		mergeArtifactMetadata(&rec.Artifact, normalized.Metadata)
		mergeArtifactTypes(&rec.Artifact, normalized.Type, normalized.Types)
	}

	if normalized.Tool != "" {
		if rec.Artifact.Tool == "" {
			rec.Artifact.Tool = normalized.Tool
		}
		if rec.Tools == nil {
			rec.Tools = make(map[string]struct{})
		}
		rec.Tools[normalized.Tool] = struct{}{}
	}
	contextTool := strings.TrimSpace(tool)
	if contextTool != "" {
		if rec.Artifact.Tool == "" {
			rec.Artifact.Tool = contextTool
		}
		if rec.Tools == nil {
			rec.Tools = make(map[string]struct{})
		}
		rec.Tools[contextTool] = struct{}{}
	}
	rec.Occurrences++
	s.artifactsDirty = true
}

func normalizeArtifact(tool string, artifact Artifact) (Artifact, bool) {
	artifact.Type = strings.TrimSpace(artifact.Type)
	artifact.Value = strings.TrimSpace(artifact.Value)
	if artifact.Value == "" {
		return Artifact{}, false
	}

	typeSet := make(map[string]struct{})
	if artifact.Type != "" {
		typeSet[artifact.Type] = struct{}{}
	}
	for _, typ := range artifact.Types {
		typ = strings.TrimSpace(typ)
		if typ == "" {
			continue
		}
		typeSet[typ] = struct{}{}
	}
	if len(typeSet) == 0 {
		return Artifact{}, false
	}
	ordered := make([]string, 0, len(typeSet))
	for typ := range typeSet {
		ordered = append(ordered, typ)
	}
	sort.Strings(ordered)
	primary := artifact.Type
	if primary == "" {
		primary = ordered[0]
	} else if _, ok := typeSet[primary]; !ok {
		primary = ordered[0]
	}
	artifact.Type = primary
	extras := make([]string, 0, len(ordered))
	for _, typ := range ordered {
		if typ == primary {
			continue
		}
		extras = append(extras, typ)
	}
	if len(extras) == 0 {
		artifact.Types = nil
	} else {
		artifact.Types = extras
	}

	if artifact.Metadata != nil {
		cleaned := make(map[string]any)
		for key, value := range artifact.Metadata {
			key = strings.TrimSpace(key)
			if key == "" || value == nil {
				continue
			}
			cleaned[key] = value
		}
		if len(cleaned) == 0 {
			artifact.Metadata = nil
		} else {
			artifact.Metadata = cleaned
		}
	}
	artifact.Tool = strings.TrimSpace(artifact.Tool)
	if artifact.Tool == "" {
		artifact.Tool = strings.TrimSpace(tool)
	}
	artifact.Tools = nil
	artifact.Occurrences = 0
	return artifact, true
}

func mergeArtifactMetadata(dst *Artifact, metadata map[string]any) {
	if dst == nil || metadata == nil {
		return
	}
	if dst.Metadata == nil {
		dst.Metadata = make(map[string]any, len(metadata))
	}
	for key, value := range metadata {
		if key == "" || value == nil {
			continue
		}
		if _, exists := dst.Metadata[key]; !exists {
			dst.Metadata[key] = value
		}
	}
}

func mergeArtifactTypes(dst *Artifact, primary string, types []string) {
	if dst == nil {
		return
	}
	typeSet := make(map[string]struct{})
	currentPrimary := strings.TrimSpace(dst.Type)
	if currentPrimary != "" {
		typeSet[currentPrimary] = struct{}{}
	}
	for _, typ := range dst.Types {
		typ = strings.TrimSpace(typ)
		if typ == "" {
			continue
		}
		typeSet[typ] = struct{}{}
	}
	normalizedPrimary := strings.TrimSpace(primary)
	if normalizedPrimary != "" {
		typeSet[normalizedPrimary] = struct{}{}
	}
	for _, typ := range types {
		typ = strings.TrimSpace(typ)
		if typ == "" {
			continue
		}
		typeSet[typ] = struct{}{}
	}
	if len(typeSet) == 0 {
		dst.Type = ""
		dst.Types = nil
		return
	}
	ordered := make([]string, 0, len(typeSet))
	for typ := range typeSet {
		ordered = append(ordered, typ)
	}
	sort.Strings(ordered)
	if currentPrimary == "" {
		currentPrimary = ordered[0]
	} else if _, ok := typeSet[currentPrimary]; !ok {
		currentPrimary = ordered[0]
	}
	dst.Type = currentPrimary
	merged := make([]string, 0, len(ordered))
	for _, typ := range ordered {
		if typ == currentPrimary {
			continue
		}
		merged = append(merged, typ)
	}
	if len(merged) == 0 {
		dst.Types = nil
	} else {
		dst.Types = merged
	}
}

func (s *Sink) flushArtifacts() {
	if s == nil || s.Artifacts == nil {
		return
	}

	s.artifactMu.Lock()
	if !s.artifactsDirty && len(s.artifactOrder) == 0 {
		s.artifactMu.Unlock()
		return
	}

	records := make([]Artifact, 0, len(s.artifactOrder))
	for _, key := range s.artifactOrder {
		rec := s.artifactIndex[key]
		if rec == nil {
			continue
		}
		art := rec.Artifact
		if rec.Tools != nil {
			tools := make([]string, 0, len(rec.Tools))
			for tool := range rec.Tools {
				if tool == "" {
					continue
				}
				tools = append(tools, tool)
			}
			sort.Strings(tools)
			if len(tools) > 0 {
				art.Tools = tools
				if art.Tool == "" {
					art.Tool = tools[0]
				}
			}
		}
		if rec.Occurrences <= 0 {
			art.Occurrences = 1
		} else {
			art.Occurrences = rec.Occurrences
		}
		records = append(records, art)
	}
	s.artifactsDirty = false
	s.artifactMu.Unlock()

	if s.Artifacts != nil {
		_ = s.Artifacts.Close()
	}
	if s.artifactsPath == "" {
		return
	}
	f, err := os.OpenFile(s.artifactsPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return
	}
	writer := bufio.NewWriter(f)
	for _, art := range records {
		encoded, err := json.Marshal(art)
		if err != nil {
			continue
		}
		if _, err := writer.Write(encoded); err != nil {
			continue
		}
		_ = writer.WriteByte('\n')
	}
	_ = writer.Flush()
	_ = f.Close()
}

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

func handleMeta(s *Sink, line string, isActive bool, tool string) bool {
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
		normalized := normalizeMetaContent(content)
		if normalized == "" {
			return true
		}
		_ = target.WriteRaw(normalized)
		s.recordArtifact(tool, Artifact{
			Type:   "meta",
			Value:  normalized,
			Active: isActive,
			Tool:   inferToolFromMessage(normalized),
			Metadata: map[string]any{
				"raw": trimmed,
			},
		})
		return true
	}

	return false
}

func handleGFFinding(s *Sink, line string, isActive bool, tool string) bool {
	payload := strings.TrimSpace(strings.TrimPrefix(line, "gffinding:"))
	if payload == "" {
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
	context := strings.TrimSpace(data.Context)
	rules := normalizeGFRules(data.Rules)

	value := buildGFFindingValue(resource, data.Line, evidence)

	metadata := map[string]any{"evidence": evidence}
	if resource != "" {
		metadata["resource"] = resource
	}
	if data.Line > 0 {
		metadata["line"] = data.Line
	}
	if context != "" {
		metadata["context"] = context
	}
	if len(rules) > 0 {
		metadata["rules"] = rules
	}

	s.recordArtifact(tool, Artifact{
		Type:     "gfFinding",
		Types:    rules,
		Value:    value,
		Active:   isActive,
		Metadata: metadata,
	})
	return true
}

func handleRelation(s *Sink, line string, isActive bool, tool string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || !strings.Contains(trimmed, "-->") {
		return false
	}

	leftRaw, relationRaw, rightRaw := splitRelation(trimmed)
	if leftRaw == "" || relationRaw == "" || rightRaw == "" {
		return false
	}

	leftValue, leftKind := parseRelationNode(leftRaw)
	rightValue, rightKind := parseRelationNode(rightRaw)
	if leftValue == "" || rightValue == "" {
		return false
	}

	relation := strings.TrimSpace(relationRaw)
	recordType := normalizeRelationType(relation)

	record := dnsArtifact{Host: leftValue, Value: rightValue, Raw: trimmed}
	if recordType != "" {
		record.Type = recordType
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return false
	}

	metadata := map[string]any{"raw": trimmed, "relationship": relation}
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

	s.recordArtifact(tool, Artifact{
		Type:     "dns",
		Value:    string(payload),
		Active:   isActive,
		Metadata: metadata,
	})
	return true
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

var (
	ansiEscapeSequence = regexp.MustCompile("\\x1b\\[[0-9;]*[A-Za-z]")
	ansiColorCode      = regexp.MustCompile("\\[[0-9;]*m")
	ansiOSCSequence    = regexp.MustCompile("\\x1b\\][^\\x07]*\\x07")
)

func stripANSI(input string) string {
	withoutOSC := ansiOSCSequence.ReplaceAllString(input, "")
	withoutEsc := ansiEscapeSequence.ReplaceAllString(withoutOSC, "")
	withoutCodes := ansiColorCode.ReplaceAllString(withoutEsc, "")
	return strings.ReplaceAll(withoutCodes, "\x1b", "")
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

type dnsArtifact struct {
	Host  string   `json:"host,omitempty"`
	Type  string   `json:"type,omitempty"`
	Value string   `json:"value,omitempty"`
	Raw   string   `json:"raw,omitempty"`
	PTR   []string `json:"ptr,omitempty"`
}

func handleDNS(s *Sink, line string, isActive bool, tool string) bool {
	payload := strings.TrimSpace(strings.TrimPrefix(line, "dns:"))
	if payload == "" {
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

	s.recordArtifact(tool, Artifact{
		Type:     "dns",
		Value:    payload,
		Active:   isActive,
		Metadata: metadata,
	})
	return true
}

func handleRDAP(s *Sink, line string, isActive bool, tool string) bool {
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
	s.recordArtifact(tool, Artifact{
		Type:   "rdap",
		Value:  content,
		Active: false,
		Tool:   inferToolFromMessage(content),
	})
	return true
}

func handleJS(s *Sink, line string, isActive bool, tool string) bool {
	js := strings.TrimSpace(strings.TrimPrefix(line, "js:"))
	if js == "" {
		return true
	}
	base := extractRouteBase(js)
	if base != "" && s.scope != nil && !s.scope.AllowsRoute(base) {
		return true
	}
	value := base
	if value == "" {
		value = js
	}
	metadata := make(map[string]any)
	if strings.TrimSpace(js) != value {
		metadata["raw"] = js
	}
	buildExtras := func() []string {
		if base == "" {
			return nil
		}
		return []string{"route"}
	}
	if isActive {
		if status, ok := parseActiveRouteStatus(js, base); ok {
			metadata["status"] = status
			if status <= 0 || status >= 400 {
				s.recordArtifact(tool, Artifact{
					Type:     "js",
					Types:    buildExtras(),
					Value:    value,
					Active:   true,
					Metadata: metadata,
				})
				return true
			}
		}
		if s.RoutesJS.active != nil {
			_ = s.RoutesJS.active.WriteRaw(js)
		}
		s.recordArtifact(tool, Artifact{
			Type:     "js",
			Types:    buildExtras(),
			Value:    value,
			Active:   true,
			Metadata: metadata,
		})
		return true
	}
	if s.RoutesJS.passive != nil {
		_ = s.RoutesJS.passive.WriteURL(js)
		s.recordArtifact(tool, Artifact{
			Type:     "js",
			Types:    buildExtras(),
			Value:    value,
			Active:   false,
			Metadata: metadata,
		})
	}
	return true
}

func handleHTML(s *Sink, line string, isActive bool, tool string) bool {
	html := strings.TrimSpace(strings.TrimPrefix(line, "html:"))
	if html == "" {
		return true
	}

	base := html
	if isActive {
		base = extractRouteBase(html)
	}

	if base != "" && s.scope != nil && !s.scope.AllowsRoute(base) {
		return true
	}

	imageTarget := html
	if base != "" {
		imageTarget = base
	}

	value := base
	if value == "" {
		value = html
	}
	buildExtras := func() []string {
		if base == "" {
			return nil
		}
		return []string{"route"}
	}
	metadata := make(map[string]any)
	if strings.TrimSpace(html) != value {
		metadata["raw"] = html
	}
	if isActive {
		if status, ok := parseActiveRouteStatus(html, base); ok {
			metadata["status"] = status
			if status <= 0 || status >= 400 {
				artifactType := "html"
				if isImageURL(imageTarget) {
					artifactType = "image"
				}
				s.recordArtifact(tool, Artifact{
					Type:     artifactType,
					Types:    buildExtras(),
					Value:    value,
					Active:   true,
					Metadata: metadata,
				})
				return true
			}
		}
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
			s.recordArtifact(tool, Artifact{
				Type:     "image",
				Types:    buildExtras(),
				Value:    value,
				Active:   isActive,
				Metadata: metadata,
			})
			return true
		}
		if isActive {
			_ = writer.WriteRaw(html)
			s.recordArtifact(tool, Artifact{
				Type:     "image",
				Types:    buildExtras(),
				Value:    value,
				Active:   true,
				Metadata: metadata,
			})
			return true
		}
		_ = writer.WriteURL(html)
		s.recordArtifact(tool, Artifact{
			Type:     "image",
			Types:    buildExtras(),
			Value:    value,
			Active:   false,
			Metadata: metadata,
		})
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
		s.recordArtifact(tool, Artifact{
			Type:     "html",
			Types:    buildExtras(),
			Value:    value,
			Active:   isActive,
			Metadata: metadata,
		})
		return true
	}
	if isActive {
		_ = writer.WriteRaw(html)
		s.recordArtifact(tool, Artifact{
			Type:     "html",
			Types:    buildExtras(),
			Value:    value,
			Active:   true,
			Metadata: metadata,
		})
		return true
	}
	_ = writer.WriteURL(html)
	s.recordArtifact(tool, Artifact{
		Type:     "html",
		Types:    buildExtras(),
		Value:    value,
		Active:   false,
		Metadata: metadata,
	})
	return true
}

func handleMaps(s *Sink, line string, isActive bool, tool string) bool {
	return handleCategorizedRoute(s, line, isActive, tool, "maps:", s.RoutesMaps, s.seenRoutesMaps, true)
}

func handleJSONCategory(s *Sink, line string, isActive bool, tool string) bool {
	return handleCategorizedRoute(s, line, isActive, tool, "json:", s.RoutesJSON, s.seenRoutesJSON, true)
}

func handleAPICategory(s *Sink, line string, isActive bool, tool string) bool {
	return handleCategorizedRoute(s, line, isActive, tool, "api:", s.RoutesAPI, s.seenRoutesAPI, true)
}

func handleWASMCategory(s *Sink, line string, isActive bool, tool string) bool {
	return handleCategorizedRoute(s, line, isActive, tool, "wasm:", s.RoutesWASM, s.seenRoutesWASM, true)
}

func handleSVGCategory(s *Sink, line string, isActive bool, tool string) bool {
	return handleCategorizedRoute(s, line, isActive, tool, "svg:", s.RoutesSVG, s.seenRoutesSVG, true)
}

func handleCrawlCategory(s *Sink, line string, isActive bool, tool string) bool {
	return handleCategorizedRoute(s, line, isActive, tool, "crawl:", s.RoutesCrawl, s.seenRoutesCrawl, true)
}

func handleMetaCategory(s *Sink, line string, isActive bool, tool string) bool {
	return handleCategorizedRoute(s, line, isActive, tool, "meta-route:", s.RoutesMetaFindings, s.seenRoutesMeta, false)
}

func handleCategorizedRoute(s *Sink, line string, isActive bool, tool string, prefix string, writers writerPair, seen map[string]struct{}, normalizePassive bool) bool {
	value := strings.TrimSpace(strings.TrimPrefix(line, prefix))
	if value == "" {
		return true
	}

	artifactType := strings.TrimSuffix(prefix, ":")
	base := extractRouteBase(value)
	artifactValue := base
	if artifactValue == "" {
		artifactValue = value
	}
	buildExtras := func() []string {
		if base == "" {
			return nil
		}
		return []string{"route"}
	}
	metadata := make(map[string]any)
	if artifactValue != value {
		metadata["raw"] = value
	}
	if isActive {
		if status, ok := parseActiveRouteStatus(value, base); ok {
			metadata["status"] = status
			if status <= 0 || status >= 400 {
				s.recordArtifact(tool, Artifact{
					Type:     artifactType,
					Types:    buildExtras(),
					Value:    artifactValue,
					Active:   true,
					Metadata: metadata,
				})
				return true
			}
		}
	}

	if seen != nil {
		key := artifactValue
		if key == "" {
			key = value
		}
		if isActive {
			key = "active:" + key
		}
		if s.markSeen(seen, key) {
			s.recordArtifact(tool, Artifact{
				Type:     artifactType,
				Types:    buildExtras(),
				Value:    artifactValue,
				Active:   isActive,
				Metadata: metadata,
			})
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
		s.recordArtifact(tool, Artifact{
			Type:     artifactType,
			Types:    buildExtras(),
			Value:    artifactValue,
			Active:   isActive,
			Metadata: metadata,
		})
		return true
	}

	_ = target.WriteURL(value)
	s.recordArtifact(tool, Artifact{
		Type:     artifactType,
		Types:    buildExtras(),
		Value:    artifactValue,
		Active:   false,
		Metadata: metadata,
	})
	return true
}

func handleRoute(s *Sink, line string, isActive bool, tool string) bool {
	trimmed := strings.TrimSpace(line)
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

	metadata := make(map[string]any)
	if trimmed != base {
		metadata["raw"] = trimmed
	}

	if isActive {
		passiveKey := base
		if passiveKey == "" {
			passiveKey = strings.TrimSpace(line)
		}
		if passiveKey == "" {
			passiveKey = line
		}
		if !s.markSeen(s.seenRoutesPassive, passiveKey) {
			if s.Routes.passive != nil {
				_ = s.Routes.passive.WriteURL(base)
			}
		}
		if status, ok := parseActiveRouteStatus(trimmed, base); ok {
			metadata["status"] = status
			if status <= 0 || status >= 400 {
				s.recordArtifact(tool, Artifact{
					Type:     "route",
					Value:    base,
					Active:   true,
					Metadata: metadata,
				})
				return true
			}
		}
	}

	seen := s.seenRoutesPassive
	writer := s.Routes.passive
	if isActive {
		seen = s.seenRoutesActive
		writer = s.Routes.active
	}
	if writer == nil {
		return true
	}
	seenKey := base
	if seenKey == "" {
		seenKey = strings.TrimSpace(line)
	}
	if seenKey == "" {
		seenKey = line
	}
	if s.markSeen(seen, seenKey) {
		s.recordArtifact(tool, Artifact{
			Type:     "route",
			Value:    base,
			Active:   isActive,
			Metadata: metadata,
		})
		return true
	}
	if !isActive || shouldCategorizeActiveRoute(line, base) {
		s.writeRouteCategories(base, isActive, tool)
	}
	_ = writer.WriteURL(line)
	s.recordArtifact(tool, Artifact{
		Type:     "route",
		Value:    base,
		Active:   isActive,
		Metadata: metadata,
	})
	return true
}

func handleCert(s *Sink, line string, isActive bool, tool string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}

	if strings.HasPrefix(trimmed, "cert:") {
		s.writeCertLine(strings.TrimSpace(strings.TrimPrefix(trimmed, "cert:")), isActive, tool)
		return true
	}

	return false
}

func handleDomain(s *Sink, line string, isActive bool, tool string) bool {
	trimmed := strings.TrimSpace(line)
	key := netutil.NormalizeDomain(line)
	if key == "" {
		return false
	}

	if s.scope != nil && !s.scope.AllowsDomain(key) {
		return true
	}

	metadata := make(map[string]any)
	if trimmed != key {
		metadata["raw"] = trimmed
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
		s.recordArtifact(tool, Artifact{
			Type:     "domain",
			Value:    key,
			Active:   isActive,
			Metadata: metadata,
		})
		return true
	}
	_ = writer.WriteDomain(line)
	s.recordArtifact(tool, Artifact{
		Type:     "domain",
		Value:    key,
		Active:   isActive,
		Metadata: metadata,
	})
	return true
}

func (s *Sink) Flush() {
	s.procMu.Lock()
	for len(s.lines) > 0 || s.processing > 0 {
		s.cond.Wait()
	}
	s.procMu.Unlock()
	s.flushArtifacts()
}

func (s *Sink) Close() error {
	close(s.lines)
	s.wg.Wait()
	s.flushArtifacts()
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
	if s.Artifacts != nil {
		_ = s.Artifacts.Close()
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

func (s *Sink) writeLazyCategory(route string, isActive bool, tool string, writers writerPair, seen map[string]struct{}, artifactType string) {
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
		s.recordArtifact(tool, Artifact{
			Type:   artifactType,
			Value:  route,
			Active: isActive,
		})
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
		s.recordArtifact(tool, Artifact{
			Type:   artifactType,
			Value:  route,
			Active: true,
		})
		return
	}
	_ = target.WriteURL(route)
	s.recordArtifact(tool, Artifact{
		Type:   artifactType,
		Value:  route,
		Active: false,
	})
}

func (s *Sink) writeCertLine(line string, isActive bool, tool string) {
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
		meta := map[string]any{"names": names}
		if key != "" {
			meta["key"] = key
		}
		s.recordArtifact(tool, Artifact{
			Type:     "certificate",
			Value:    serialized,
			Active:   isActive,
			Tool:     filtered.Source,
			Metadata: meta,
		})
		return
	}

	if target != nil {
		_ = target.WriteRaw(serialized)
	}
	meta := map[string]any{
		"names": names,
	}
	if key != "" {
		meta["key"] = key
	}
	s.recordArtifact(tool, Artifact{
		Type:     "certificate",
		Value:    serialized,
		Active:   isActive,
		Tool:     filtered.Source,
		Metadata: meta,
	})
}

func extractRouteBase(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ""
	}
	if idx := strings.IndexAny(trimmed, " \t"); idx != -1 {
		trimmed = trimmed[:idx]
	}
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return ""
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	if u.Scheme == "" && u.Host == "" {
		return trimmed
	}

	if scheme := strings.ToLower(u.Scheme); scheme != "" {
		u.Scheme = scheme
	}

	if host := u.Hostname(); host != "" {
		hostname := strings.ToLower(host)
		port := u.Port()
		if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
			port = ""
		}
		normalizedHost := hostname
		if port != "" {
			normalizedHost = net.JoinHostPort(hostname, port)
		}
		if u.User != nil {
			normalizedHost = u.User.String() + "@" + normalizedHost
		}
		u.Host = normalizedHost
	}

	return strings.TrimSpace(u.String())
}

func (s *Sink) writeRouteCategories(route string, isActive bool, tool string) {
	if route == "" {
		return
	}
	categories := routes.DetectCategories(route)
	if len(categories) == 0 {
		return
	}
	categoryTargets := map[routes.Category]struct {
		writers      writerPair
		seen         map[string]struct{}
		artifactType string
	}{
		routes.CategoryMaps: {
			writers:      s.RoutesMaps,
			seen:         s.seenRoutesMaps,
			artifactType: "maps",
		},
		routes.CategoryJSON: {
			writers:      s.RoutesJSON,
			seen:         s.seenRoutesJSON,
			artifactType: "json",
		},
		routes.CategoryAPI: {
			writers:      s.RoutesAPI,
			seen:         s.seenRoutesAPI,
			artifactType: "api",
		},
		routes.CategoryWASM: {
			writers:      s.RoutesWASM,
			seen:         s.seenRoutesWASM,
			artifactType: "wasm",
		},
		routes.CategorySVG: {
			writers:      s.RoutesSVG,
			seen:         s.seenRoutesSVG,
			artifactType: "svg",
		},
		routes.CategoryCrawl: {
			writers:      s.RoutesCrawl,
			seen:         s.seenRoutesCrawl,
			artifactType: "crawl",
		},
		routes.CategoryMeta: {
			writers:      s.RoutesMetaFindings,
			seen:         s.seenRoutesMeta,
			artifactType: "meta-route",
		},
	}
	for _, cat := range categories {
		if target, ok := categoryTargets[cat]; ok {
			s.writeLazyCategory(route, isActive, tool, target.writers, target.seen, target.artifactType)
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
