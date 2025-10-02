package pipeline

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"passive-rec/internal/out"
)

type writerPair struct {
	passive *out.Writer
	active  *out.Writer
}

type Sink struct {
	Domains            writerPair
	Routes             writerPair
	Certs              writerPair
	Meta               writerPair
	wg                 sync.WaitGroup
	lines              chan string
	seenMu             sync.Mutex
	seenDomainsPassive map[string]struct{}
	seenDomainsActive  map[string]struct{}
	seenRoutesPassive  map[string]struct{}
	seenRoutesActive   map[string]struct{}
	seenCertsPassive   map[string]struct{}
	seenCertsActive    map[string]struct{}
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

	if i := strings.Index(trimmed, "://"); i != -1 {
		trimmed = trimmed[i+3:]
	}
	if i := strings.IndexAny(trimmed, ":/"); i != -1 {
		trimmed = trimmed[:i]
	}

	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "www.") {
		lower = lower[4:]
	}
	return lower
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
		Domains:            writerPair{passive: dPassive, active: dActive},
		Routes:             writerPair{passive: rPassive, active: rActive},
		Certs:              writerPair{passive: cPassive, active: cActive},
		Meta:               writerPair{passive: mPassive, active: mActive},
		lines:              make(chan string, 1024),
		seenDomainsPassive: make(map[string]struct{}),
		seenDomainsActive:  make(map[string]struct{}),
		seenRoutesPassive:  make(map[string]struct{}),
		seenRoutesActive:   make(map[string]struct{}),
		seenCertsPassive:   make(map[string]struct{}),
		seenCertsActive:    make(map[string]struct{}),
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

	if strings.Contains(l, "-->") || strings.Contains(l, " (") {
		target := s.Meta.passive
		if isActive {
			target = s.Meta.active
		}
		_ = target.WriteRaw(l)
		return
	}

	if strings.HasPrefix(l, "cert:") {
		s.writeCertLine(strings.TrimSpace(l[len("cert:"):]), isActive)
		return
	}

	// Clasificación simple: URLs/rutas si contiene esquema o '/'
	if strings.Contains(l, "http://") || strings.Contains(l, "https://") || strings.Contains(l, "/") {
		// When the line includes metadata (e.g. httpx status/title), keep a
		// clean copy of the URL in routes.passive so users always get a
		// canonical list of discovered routes.
		if isActive {
			if base := extractRouteBase(l); base != "" {
				if !s.markSeen(s.seenRoutesPassive, base) {
					_ = s.Routes.passive.WriteURL(base)
				}
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
		s.writeCertLine(l, isActive)
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
	_ = s.Domains.passive.Close()
	_ = s.Domains.active.Close()
	_ = s.Routes.passive.Close()
	_ = s.Routes.active.Close()
	_ = s.Certs.passive.Close()
	_ = s.Certs.active.Close()
	_ = s.Meta.passive.Close()
	_ = s.Meta.active.Close()
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

func (s *Sink) writeCertLine(line string, isActive bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}

	parts := []string{line}
	if strings.ContainsAny(line, ",\n") {
		parts = strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == '\n' })
	}

	seen := s.seenCertsPassive
	writer := s.Certs.passive
	if isActive {
		seen = s.seenCertsActive
		writer = s.Certs.active
	}

	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		key := strings.ToLower(p)
		if s.markSeen(seen, key) {
			continue
		}
		_ = writer.WriteRaw(p)
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
