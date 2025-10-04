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

	// meta: prefijo "meta: ..."
	if strings.HasPrefix(l, "meta: ") {
		target := s.Meta.passive
		if isActive {
			target = s.Meta.active
		}
		_ = target.WriteRaw(strings.TrimPrefix(l, "meta: "))
		return
	}

	if strings.HasPrefix(l, "js:") {
		js := strings.TrimSpace(strings.TrimPrefix(l, "js:"))
		if js == "" {
			return
		}
		if isActive {
			if s.RoutesJS.active != nil {
				_ = s.RoutesJS.active.WriteRaw(js)
			}
			if s.RoutesJS.passive != nil {
				_ = s.RoutesJS.passive.WriteURL(js)
			}
			return
		}
		if s.RoutesJS.passive != nil {
			_ = s.RoutesJS.passive.WriteURL(js)
		}
		return
	}

	if strings.HasPrefix(l, "html:") {
		html := strings.TrimSpace(strings.TrimPrefix(l, "html:"))
		if html == "" {
			return
		}
		seen := s.seenHTMLPassive
		writer := s.RoutesHTML.passive
		if isActive {
			seen = s.seenHTMLActive
			writer = s.RoutesHTML.active
		}
		if writer == nil {
			return
		}
		if seen != nil && s.markSeen(seen, html) {
			return
		}
		if isActive {
			_ = writer.WriteRaw(html)
			return
		}
		_ = writer.WriteURL(html)
		return
	}

	if strings.Contains(l, "-->") || strings.Contains(l, " (") {
		target := s.Meta.passive
		if isActive {
			target = s.Meta.active
		}
		_ = target.WriteRaw(l)
		return
	}

	if strings.HasPrefix(l, "cert:") {
		s.writeCertLine(strings.TrimSpace(l[len("cert:"):]))
		return
	}

	// Clasificación simple: URLs/rutas si contiene esquema o '/'
	base := extractRouteBase(l)
	if base != "" && (strings.Contains(base, "://") || strings.HasPrefix(base, "/") || strings.Contains(base, "/")) {
		// When the line includes metadata (e.g. httpx status/title), keep a
		// clean copy of the URL in routes.passive so users always get a
		// canonical list of discovered routes.
		if isActive {
			if !s.markSeen(s.seenRoutesPassive, base) {
				_ = s.Routes.passive.WriteURL(base)
			}
		}

		seen := s.seenRoutesPassive
		writer := s.Routes.passive
		if isActive {
			seen = s.seenRoutesActive
			writer = s.Routes.active
		}
		if s.markSeen(seen, l) {
			return
		}
		if !isActive || shouldCategorizeActiveRoute(l, base) {
			s.writeRouteCategories(base, isActive)
		}
		_ = writer.WriteURL(l)
		return
	}

	// crt.sh name_value puede venir con commas/nuevas líneas ya partidos aguas arriba.
	if strings.Contains(l, ",") || strings.Contains(l, "\n") {
		s.writeCertLine(l)
		return
	}

	// defecto: dominio
	key := netutil.NormalizeDomain(l)
	if key == "" {
		return
	}

	seen := s.seenDomainsPassive
	writer := s.Domains.passive
	if isActive {
		seen = s.seenDomainsActive
		writer = s.Domains.active
	}
	if s.markSeen(seen, key) {
		return
	}
	_ = writer.WriteDomain(l)
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
	for _, cat := range categories {
		switch cat {
		case routeCategoryMaps:
			if s.RoutesMaps != nil && !s.markSeen(s.seenRoutesMaps, route) {
				if s.activeMode && isActive {
					s.RoutesMaps.WriteRaw(route)
				} else {
					s.RoutesMaps.WriteURL(route)
				}
			}
		case routeCategoryJSON:
			if s.RoutesJSON != nil && !s.markSeen(s.seenRoutesJSON, route) {
				if s.activeMode && isActive {
					s.RoutesJSON.WriteRaw(route)
				} else {
					s.RoutesJSON.WriteURL(route)
				}
			}
		case routeCategoryAPI:
			if s.RoutesAPI != nil && !s.markSeen(s.seenRoutesAPI, route) {
				if s.activeMode && isActive {
					s.RoutesAPI.WriteRaw(route)
				} else {
					s.RoutesAPI.WriteURL(route)
				}
			}
		case routeCategoryWASM:
			if s.RoutesWASM != nil && !s.markSeen(s.seenRoutesWASM, route) {
				if s.activeMode && isActive {
					s.RoutesWASM.WriteRaw(route)
				} else {
					s.RoutesWASM.WriteURL(route)
				}
			}
		case routeCategorySVG:
			if s.RoutesSVG != nil && !s.markSeen(s.seenRoutesSVG, route) {
				if s.activeMode && isActive {
					s.RoutesSVG.WriteRaw(route)
				} else {
					s.RoutesSVG.WriteURL(route)
				}
			}
		case routeCategoryCrawl:
			if s.RoutesCrawl != nil && !s.markSeen(s.seenRoutesCrawl, route) {
				if s.activeMode && isActive {
					s.RoutesCrawl.WriteRaw(route)
				} else {
					s.RoutesCrawl.WriteURL(route)
				}
			}
		case routeCategoryMeta:
			if s.RoutesMetaFindings != nil && !s.markSeen(s.seenRoutesMeta, route) {
				if s.activeMode && isActive {
					s.RoutesMetaFindings.WriteRaw(route)
				} else {
					s.RoutesMetaFindings.WriteURL(route)
				}
			}
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
