package pipeline

import (
	"context"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"passive-rec/internal/certs"
	"passive-rec/internal/netutil"
	"passive-rec/internal/out"
)

type writerPair struct {
	passive *out.Writer
	active  *out.Writer
}

type lazyWriter struct {
	outdir  string
	subdir  string
	name    string
	mu      sync.Mutex
	writer  *out.Writer
	initErr error
}

func newLazyWriter(outdir, subdir, name string) *lazyWriter {
	return &lazyWriter{outdir: outdir, subdir: subdir, name: name}
}

func (lw *lazyWriter) ensure() (*out.Writer, error) {
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

func (lw *lazyWriter) WriteURL(u string) {
	if lw == nil {
		return
	}
	if u == "" {
		return
	}
	w, err := lw.ensure()
	if err != nil {
		return
	}
	_ = w.WriteURL(u)
}

func (lw *lazyWriter) WriteRaw(line string) {
	if lw == nil {
		return
	}
	if line == "" {
		return
	}
	w, err := lw.ensure()
	if err != nil {
		return
	}
	_ = w.WriteRaw(line)
}

func (lw *lazyWriter) Close() {
	if lw == nil {
		return
	}
	lw.mu.Lock()
	w := lw.writer
	lw.writer = nil
	lw.mu.Unlock()
	if w != nil {
		_ = w.Close()
	}
}

type Sink struct {
	Domains            writerPair
	Routes             writerPair
	RoutesJS           writerPair
	RoutesHTML         writerPair
	RoutesMaps         *lazyWriter
	RoutesJSON         *lazyWriter
	RoutesAPI          *lazyWriter
	RoutesWASM         *lazyWriter
	RoutesSVG          *lazyWriter
	RoutesCrawl        *lazyWriter
	RoutesMetaFindings *lazyWriter
	Certs              writerPair
	Meta               writerPair
	wg                 sync.WaitGroup
	lines              chan string
	seenMu             sync.Mutex
	seenDomainsPassive map[string]struct{}
	seenDomainsActive  map[string]struct{}
	seenRoutesPassive  map[string]struct{}
	seenRoutesActive   map[string]struct{}
	seenHTMLPassive    map[string]struct{}
	seenHTMLActive     map[string]struct{}
	seenRoutesMaps     map[string]struct{}
	seenRoutesJSON     map[string]struct{}
	seenRoutesAPI      map[string]struct{}
	seenRoutesWASM     map[string]struct{}
	seenRoutesSVG      map[string]struct{}
	seenRoutesCrawl    map[string]struct{}
	seenRoutesMeta     map[string]struct{}
	seenCertsPassive   map[string]struct{}
	procMu             sync.Mutex
	processing         int
	cond               *sync.Cond
	activeMode         bool
}

func NewSink(outdir string, active bool) (*Sink, error) {
	var opened []*out.Writer
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
	jsPassive, err := newWriter(filepath.Join("routes", "js"), "js.passive")
	if err != nil {
		return nil, err
	}
	jsActive, err := newWriter(filepath.Join("routes", "js"), "js.active")
	if err != nil {
		return nil, err
	}
	htmlActive, err := newWriter(filepath.Join("routes", "html"), "html.active")
	if err != nil {
		return nil, err
	}
	cPassive, err := newWriter("certs", "certs.passive")
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

	suffix := ".passive"
	if active {
		suffix = ".active"
	}

	s := &Sink{
		Domains:            writerPair{passive: dPassive, active: dActive},
		Routes:             writerPair{passive: rPassive, active: rActive},
		RoutesJS:           writerPair{passive: jsPassive, active: jsActive},
		RoutesHTML:         writerPair{active: htmlActive},
		RoutesMaps:         newLazyWriter(outdir, filepath.Join("routes", "maps"), "maps"+suffix),
		RoutesJSON:         newLazyWriter(outdir, filepath.Join("routes", "json"), "json"+suffix),
		RoutesAPI:          newLazyWriter(outdir, filepath.Join("routes", "api"), "api"+suffix),
		RoutesWASM:         newLazyWriter(outdir, filepath.Join("routes", "wasm"), "wasm"+suffix),
		RoutesSVG:          newLazyWriter(outdir, filepath.Join("routes", "svg"), "svg"+suffix),
		RoutesCrawl:        newLazyWriter(outdir, filepath.Join("routes", "crawl"), "crawl"+suffix),
		RoutesMetaFindings: newLazyWriter(outdir, filepath.Join("routes", "meta"), "meta"+suffix),
		Certs:              writerPair{passive: cPassive},
		Meta:               writerPair{passive: mPassive, active: mActive},
		lines:              make(chan string, 1024),
		seenDomainsPassive: make(map[string]struct{}),
		seenDomainsActive:  make(map[string]struct{}),
		seenRoutesPassive:  make(map[string]struct{}),
		seenRoutesActive:   make(map[string]struct{}),
		seenHTMLPassive:    make(map[string]struct{}),
		seenHTMLActive:     make(map[string]struct{}),
		seenRoutesMaps:     make(map[string]struct{}),
		seenRoutesJSON:     make(map[string]struct{}),
		seenRoutesAPI:      make(map[string]struct{}),
		seenRoutesWASM:     make(map[string]struct{}),
		seenRoutesSVG:      make(map[string]struct{}),
		seenRoutesCrawl:    make(map[string]struct{}),
		seenRoutesMeta:     make(map[string]struct{}),
		seenCertsPassive:   make(map[string]struct{}),
		activeMode:         active,
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
	handler lineHandler
}{
	{prefix: "meta:", handler: handleMeta},
	{prefix: "js:", handler: handleJS},
	{prefix: "html:", handler: handleHTML},
	{prefix: "cert:", handler: handleCert},
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
			if entry.handler(s, l, isActive) {
				return
			}
		}
	}

	if handleMeta(s, l, isActive) {
		return
	}
	if handleRoute(s, l, isActive) {
		return
	}
	if handleCert(s, l, isActive) {
		return
	}
	_ = handleDomain(s, l, isActive)
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

func handleJS(s *Sink, line string, isActive bool) bool {
	js := strings.TrimSpace(strings.TrimPrefix(line, "js:"))
	if js == "" {
		return true
	}
	if isActive {
		base := extractRouteBase(js)
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

func handleRoute(s *Sink, line string, isActive bool) bool {
	base := extractRouteBase(line)
	if base == "" {
		return false
	}
	if !(strings.Contains(base, "://") || strings.HasPrefix(base, "/") || strings.Contains(base, "/")) {
		return false
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
	_ = isActive // currently unused but kept for signature consistency

	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return true
	}

	if strings.HasPrefix(trimmed, "cert:") {
		s.writeCertLine(strings.TrimSpace(strings.TrimPrefix(trimmed, "cert:")))
		return true
	}

	return false
}

func handleDomain(s *Sink, line string, isActive bool) bool {
	key := netutil.NormalizeDomain(line)
	if key == "" {
		return false
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
	if s.RoutesMaps != nil {
		s.RoutesMaps.Close()
	}
	if s.RoutesJSON != nil {
		s.RoutesJSON.Close()
	}
	if s.RoutesAPI != nil {
		s.RoutesAPI.Close()
	}
	if s.RoutesWASM != nil {
		s.RoutesWASM.Close()
	}
	if s.RoutesSVG != nil {
		s.RoutesSVG.Close()
	}
	if s.RoutesCrawl != nil {
		s.RoutesCrawl.Close()
	}
	if s.RoutesMetaFindings != nil {
		s.RoutesMetaFindings.Close()
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

func (s *Sink) writeLazyCategory(route string, isActive bool, lw *lazyWriter, seen map[string]struct{}) {
	if lw == nil || seen == nil {
		return
	}
	if s.markSeen(seen, route) {
		return
	}
	if s.activeMode && isActive {
		lw.WriteRaw(route)
		return
	}
	lw.WriteURL(route)
}

func (s *Sink) writeCertLine(line string) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}

	record, err := certs.Parse(line)
	if err != nil {
		return
	}

	serialized, err := record.Marshal()
	if err != nil {
		return
	}

	key := record.Key()
	if key == "" {
		key = strings.ToLower(serialized)
	}
	if s.markSeen(s.seenCertsPassive, key) {
		return
	}

	if s.Certs.passive != nil {
		_ = s.Certs.passive.WriteRaw(serialized)
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

type routeCategory int

const (
	routeCategoryNone routeCategory = iota
	routeCategoryMaps
	routeCategoryJSON
	routeCategoryAPI
	routeCategoryWASM
	routeCategorySVG
	routeCategoryCrawl
	routeCategoryMeta
)

func (s *Sink) writeRouteCategories(route string, isActive bool) {
	if route == "" {
		return
	}
	if s.activeMode && !isActive {
		return
	}
	categories := detectRouteCategories(route)
	if len(categories) == 0 {
		return
	}
	categoryTargets := map[routeCategory]struct {
		writer *lazyWriter
		seen   map[string]struct{}
	}{
		routeCategoryMaps: {
			writer: s.RoutesMaps,
			seen:   s.seenRoutesMaps,
		},
		routeCategoryJSON: {
			writer: s.RoutesJSON,
			seen:   s.seenRoutesJSON,
		},
		routeCategoryAPI: {
			writer: s.RoutesAPI,
			seen:   s.seenRoutesAPI,
		},
		routeCategoryWASM: {
			writer: s.RoutesWASM,
			seen:   s.seenRoutesWASM,
		},
		routeCategorySVG: {
			writer: s.RoutesSVG,
			seen:   s.seenRoutesSVG,
		},
		routeCategoryCrawl: {
			writer: s.RoutesCrawl,
			seen:   s.seenRoutesCrawl,
		},
		routeCategoryMeta: {
			writer: s.RoutesMetaFindings,
			seen:   s.seenRoutesMeta,
		},
	}
	for _, cat := range categories {
		if target, ok := categoryTargets[cat]; ok {
			s.writeLazyCategory(route, isActive, target.writer, target.seen)
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

func detectRouteCategories(route string) []routeCategory {
	trimmed := strings.TrimSpace(route)
	if trimmed == "" {
		return nil
	}

	lowerFull := strings.ToLower(trimmed)
	pathComponent := trimmed
	if u, err := url.Parse(trimmed); err == nil {
		if u.Path != "" {
			pathComponent = u.Path
		}
		lowerFull = strings.ToLower(u.Path)
		if u.RawQuery != "" {
			lowerFull += "?" + strings.ToLower(u.RawQuery)
		}
	}

	if idx := strings.IndexAny(pathComponent, "?#"); idx != -1 {
		pathComponent = pathComponent[:idx]
	}
	pathComponent = strings.TrimSpace(pathComponent)
	lowerPath := strings.ToLower(pathComponent)

	base := strings.ToLower(filepath.Base(pathComponent))
	if base == "." || base == "/" {
		base = ""
	}
	ext := strings.ToLower(filepath.Ext(base))
	nameNoExt := strings.TrimSuffix(base, ext)

	appendCat := func(categories []routeCategory, cat routeCategory) []routeCategory {
		for _, existing := range categories {
			if existing == cat {
				return categories
			}
		}
		return append(categories, cat)
	}

	var categories []routeCategory

	switch ext {
	case ".map":
		categories = appendCat(categories, routeCategoryMaps)
	case ".wasm":
		categories = appendCat(categories, routeCategoryWASM)
	case ".svg":
		categories = appendCat(categories, routeCategorySVG)
	case ".jsonld":
		categories = appendCat(categories, routeCategoryJSON)
	case ".json":
		if isAPIDocument(lowerPath, base, nameNoExt, lowerFull) {
			categories = appendCat(categories, routeCategoryAPI)
		} else {
			categories = appendCat(categories, routeCategoryJSON)
		}
	case ".yaml", ".yml":
		if isAPIDocument(lowerPath, base, nameNoExt, lowerFull) {
			categories = appendCat(categories, routeCategoryAPI)
		}
	case ".xml":
		if isCrawlFile(base, nameNoExt) {
			categories = appendCat(categories, routeCategoryCrawl)
		}
	case ".txt":
		if base == "robots.txt" {
			categories = appendCat(categories, routeCategoryCrawl)
		}
	case ".gz":
		if strings.HasSuffix(base, "sitemap.xml.gz") || strings.HasSuffix(nameNoExt, "sitemap.xml") {
			categories = appendCat(categories, routeCategoryCrawl)
		}
	}

	if base == "robots.txt" {
		categories = appendCat(categories, routeCategoryCrawl)
	}
	if ext == "" && isCrawlPathWithoutExt(lowerPath) {
		categories = appendCat(categories, routeCategoryCrawl)
	}

	if shouldCategorizeMeta(base, nameNoExt, ext, lowerFull) {
		categories = appendCat(categories, routeCategoryMeta)
	}

	return categories
}

func isAPIDocument(lowerPath, base, nameNoExt, lowerFull string) bool {
	keywords := []string{"swagger", "openapi", "api-doc", "api_docs", "apispec", "api-spec", "api_spec", "api-definition", "api_definition"}
	for _, kw := range keywords {
		if strings.Contains(lowerPath, kw) {
			return true
		}
	}
	for _, kw := range keywords {
		if strings.Contains(base, kw) {
			return true
		}
	}
	if nameNoExt == "api" && (strings.Contains(lowerFull, "openapi") || strings.Contains(lowerFull, "swagger")) {
		return true
	}
	return false
}

func isCrawlFile(base, nameNoExt string) bool {
	if strings.Contains(nameNoExt, "sitemap") {
		return true
	}
	return false
}

func isCrawlPathWithoutExt(lowerPath string) bool {
	if strings.HasSuffix(lowerPath, "/robots") || strings.HasSuffix(lowerPath, "/robots/") {
		return true
	}
	return false
}

func shouldCategorizeMeta(base, nameNoExt, ext, lowerFull string) bool {
	if base == "" {
		return false
	}

	sensitiveExts := map[string]struct{}{
		".bak":    {},
		".old":    {},
		".swp":    {},
		".sql":    {},
		".db":     {},
		".sqlite": {},
		".env":    {},
		".ini":    {},
		".cfg":    {},
		".config": {},
		".conf":   {},
		".log":    {},
	}

	if _, ok := sensitiveExts[ext]; ok {
		return true
	}

	archiveExts := []string{".zip", ".rar", ".7z", ".tar", ".tgz", ".gz"}
	for _, archiveExt := range archiveExts {
		if strings.HasSuffix(base, archiveExt) {
			if strings.Contains(nameNoExt, "backup") || strings.Contains(nameNoExt, "config") || strings.Contains(nameNoExt, "secret") || strings.Contains(nameNoExt, "database") || strings.Contains(nameNoExt, "db") {
				return true
			}
		}
	}

	lowerBase := base
	keywords := []string{"backup", "secret", "token", "password", "passwd", "credential", "creds", "config", "database", "db", "id_rsa", ".env", ".git", ".svn", "ssh", "private"}
	for _, kw := range keywords {
		if strings.Contains(lowerBase, kw) {
			return true
		}
	}

	queryKeywords := []string{"token=", "secret=", "password=", "passwd=", "key=", "apikey=", "api_key=", "access_token=", "auth=", "credential"}
	for _, kw := range queryKeywords {
		if strings.Contains(lowerFull, kw) {
			return true
		}
	}

	return false
}
