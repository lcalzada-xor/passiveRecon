package pipeline

import (
	"context"
	"strings"
	"sync"

	"passive-rec/internal/out"
)

type Sink struct {
	Domains *out.Writer
	Routes  *out.Writer
	Certs   *out.Writer
	Meta    *out.Writer
	wg      sync.WaitGroup
	lines   chan string
}

func NewSink(outdir string) (*Sink, error) {
	d, err := out.New(outdir, "domains.passive")
	if err != nil { return nil, err }
	r, err := out.New(outdir, "routes.passive")
	if err != nil { return nil, err }
	c, err := out.New(outdir, "certs.passive")
	if err != nil { return nil, err }
	m, err := out.New(outdir, "meta.passive")
	if err != nil { return nil, err }

	s := &Sink{
		Domains: d, Routes: r, Certs: c, Meta: m,
		lines: make(chan string, 1024),
	}
	return s, nil
}

func (s *Sink) Start(workers int) {
	if workers < 1 { workers = 1 }
	for i := 0; i < workers; i++ {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			for ln := range s.lines {
				l := strings.TrimSpace(ln)
				if l == "" { continue }

				// meta: prefijo "meta: ..."
				if strings.HasPrefix(l, "meta: ") {
					_ = s.Meta.WriteRaw(strings.TrimPrefix(l, "meta: "))
					continue
				}

				// Clasificación simple: URLs/rutas si contiene esquema o '/'
				if strings.Contains(l, "http://") || strings.Contains(l, "https://") || strings.Contains(l, "/") {
					_ = s.Routes.WriteURL(l)
					continue
				}

				// crt.sh name_value puede venir con commas/nuevas líneas ya partidos aguas arriba.
				if strings.Contains(l, ",") || strings.Contains(l, "\n") {
					parts := strings.FieldsFunc(l, func(r rune) bool { return r == ',' || r == '\n' })
					for _, p := range parts {
						_ = s.Certs.WriteRaw(p)
					}
					continue
				}

				// defecto: dominio
				_ = s.Domains.WriteDomain(l)
			}
		}()
	}
}

func (s *Sink) In() chan<- string { return s.lines }

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
