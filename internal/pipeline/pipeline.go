package pipeline

import (
	"context"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"passive-rec/internal/certs"
	"passive-rec/internal/out"
)

type writerPair struct {
	passive *out.Writer
	active  *out.Writer
}

type Sink struct {
	Domains            writerPair
	Routes             writerPair
	RoutesJS           writerPair
	RoutesHTML         writerPair
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
	seenCertsPassive   map[string]struct{}
	procMu             sync.Mutex
	processing         int
	cond               *sync.Cond
}

func normalizeDomainKey(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return ""
	}

	if idx := strings.IndexAny(trimmed, " \t"); idx != -1 {
		trimmed = trimmed[:idx]
	}

	host := extractHost(trimmed)
	if host == "" {
		return ""
	}

	lower := strings.ToLower(host)
	if strings.HasPrefix(lower, "www.") {
		lower = lower[4:]
	}
	return lower
}

func extractHost(raw string) string {
	if raw == "" {
		return ""
	}

	candidate := raw
	var parsed *url.URL
	var err error

	if strings.Contains(candidate, "://") {
		parsed, err = url.Parse(candidate)
	} else {
		parsed, err = url.Parse("http://" + candidate)
	}
	if err == nil && parsed != nil {
		hostPort := parsed.Host
		hostname := parsed.Hostname()
		if hostname != "" && !(strings.Count(hostPort, ":") > 1 && !strings.Contains(hostPort, "[")) {
			return hostname
		}
		if hostPort != "" {
			candidate = hostPort
		}
	}

	if candidate == "" {
		return ""
	}

	if at := strings.LastIndex(candidate, "@"); at != -1 {
		candidate = candidate[at+1:]
	}

	if idx := strings.IndexAny(candidate, "/?#"); idx != -1 {
		candidate = candidate[:idx]
	}

	if candidate == "" {
		return ""
	}

	if host, _, err := net.SplitHostPort(candidate); err == nil {
		return host
	}

	if strings.HasPrefix(candidate, "[") && strings.HasSuffix(candidate, "]") {
		return strings.Trim(candidate, "[]")
	}

	return candidate
}

func NewSink(outdir string) (*Sink, error) {
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

	s := &Sink{
		Domains:            writerPair{passive: dPassive, active: dActive},
		Routes:             writerPair{passive: rPassive, active: rActive},
		RoutesJS:           writerPair{passive: jsPassive, active: jsActive},
		RoutesHTML:         writerPair{active: htmlActive},
		Certs:              writerPair{passive: cPassive},
		Meta:               writerPair{passive: mPassive, active: mActive},
		lines:              make(chan string, 1024),
		seenDomainsPassive: make(map[string]struct{}),
		seenDomainsActive:  make(map[string]struct{}),
		seenRoutesPassive:  make(map[string]struct{}),
		seenRoutesActive:   make(map[string]struct{}),
		seenHTMLPassive:    make(map[string]struct{}),
		seenHTMLActive:     make(map[string]struct{}),
		seenCertsPassive:   make(map[string]struct{}),
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
				_ = s.RoutesJS.active.WriteURL(js)
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
		_ = writer.WriteURL(l)
		return
	}

	// crt.sh name_value puede venir con commas/nuevas líneas ya partidos aguas arriba.
	if strings.Contains(l, ",") || strings.Contains(l, "\n") {
		s.writeCertLine(l)
		return
	}

	// defecto: dominio
	key := normalizeDomainKey(l)
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
