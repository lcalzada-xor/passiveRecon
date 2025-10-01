package pipeline

import (
	"context"
	"strings"
	"sync"

	"passive-rec/internal/out"
)

type Sink struct {
	Domains     *out.Writer
	Routes      *out.Writer
	Certs       *out.Writer
	Meta        *out.Writer
	wg          sync.WaitGroup
	lines       chan string
	seenMu      sync.Mutex
	seenDomains map[string]struct{}
	seenRoutes  map[string]struct{}
	seenCerts   map[string]struct{}
	procMu      sync.Mutex
	processing  int
	cond        *sync.Cond
}

func NewSink(outdir string) (*Sink, error) {
	var opened []*out.Writer
	newWriter := func(name string) (*out.Writer, error) {
		w, err := out.New(outdir, name)
		if err != nil {
			for _, ow := range opened {
				_ = ow.Close()
			}
			return nil, err
		}
		opened = append(opened, w)
		return w, nil
	}

	d, err := newWriter("domains.passive")
	if err != nil {
		return nil, err
	}
	r, err := newWriter("routes.passive")
	if err != nil {
		return nil, err
	}
	c, err := newWriter("certs.passive")
	if err != nil {
		return nil, err
	}
	m, err := newWriter("meta.passive")
	if err != nil {
		return nil, err
	}

	s := &Sink{
		Domains: d, Routes: r, Certs: c, Meta: m,
		lines:       make(chan string, 1024),
		seenDomains: make(map[string]struct{}),
		seenRoutes:  make(map[string]struct{}),
		seenCerts:   make(map[string]struct{}),
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

	// meta: prefijo "meta: ..."
	if strings.HasPrefix(l, "meta: ") {
		_ = s.Meta.WriteRaw(strings.TrimPrefix(l, "meta: "))
		return
	}

	if strings.Contains(l, "-->") || strings.Contains(l, " (") {
		_ = s.Meta.WriteRaw(l)
		return
	}

	// Clasificación simple: URLs/rutas si contiene esquema o '/'
	if strings.Contains(l, "http://") || strings.Contains(l, "https://") || strings.Contains(l, "/") {
		if s.markSeen(s.seenRoutes, l) {
			return
		}
		_ = s.Routes.WriteURL(l)
		return
	}

	// crt.sh name_value puede venir con commas/nuevas líneas ya partidos aguas arriba.
	if strings.Contains(l, ",") || strings.Contains(l, "\n") {
		parts := strings.FieldsFunc(l, func(r rune) bool { return r == ',' || r == '\n' })
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			key := strings.ToLower(p)
			if s.markSeen(s.seenCerts, key) {
				continue
			}
			_ = s.Certs.WriteRaw(p)
		}
		return
	}

	// defecto: dominio
	key := strings.ToLower(l)
	if s.markSeen(s.seenDomains, key) {
		return
	}
	_ = s.Domains.WriteDomain(l)
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
	_ = s.Domains.Close()
	_ = s.Routes.Close()
	_ = s.Certs.Close()
	_ = s.Meta.Close()
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
