package out

import (
	"bufio"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"passive-rec/internal/netutil"
)

type Writer struct {
	mu     sync.Mutex
	file   *os.File
	buf    *bufio.Writer
	seen   map[string]struct{}
	closed bool
}

func New(outdir, name string) (*Writer, error) {
	if err := os.MkdirAll(outdir, 0755); err != nil {
		return nil, err
	}
	p := filepath.Join(outdir, name)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, err
	}
	return &Writer{
		file: f,
		buf:  bufio.NewWriterSize(f, 64*1024),
		seen: make(map[string]struct{}),
	}, nil
}

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	var err error
	if w.buf != nil {
		if e := w.buf.Flush(); e != nil && err == nil {
			err = e
		}
	}
	if w.file != nil {
		if e := w.file.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// --- Normalizadores ---

func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	if d == "" {
		return ""
	}

	// Preservar "metadata" tras el primer espacio/tab si existe.
	var meta string
	if i := strings.IndexAny(d, " \t"); i != -1 {
		meta = strings.TrimSpace(d[i:])
		d = strings.TrimSpace(d[:i])
	}

	base := netutil.NormalizeDomain(d)
	if base == "" {
		return ""
	}

	if meta != "" {
		return base + " " + meta
	}
	return base
}

func normalizeURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}

	// Asegurar esquema si falta.
	if !strings.Contains(u, "://") {
		u = "http://" + u
	}

	// Si ya contiene whitespace, asumimos que trae metadata y lo devolvemos tal cual.
	if strings.ContainsAny(u, " \t") {
		return u
	}

	parsed, err := url.Parse(u)
	if err != nil {
		// Si la URL es inválida, devolvemos lo que tengamos (con esquema) para no perder info.
		return u
	}

	parsed.Scheme = strings.ToLower(parsed.Scheme)

	host := parsed.Hostname()
	port := parsed.Port()
	if host != "" {
		parsed.Host = strings.ToLower(host)
		if port != "" {
			parsed.Host += ":" + port
		}
	}

	return parsed.String()
}

// --- Escrituras ---

func (w *Writer) writeUnique(line string) error {
	if line == "" {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return os.ErrClosed
	}

	if _, ok := w.seen[line]; ok {
		return nil
	}
	w.seen[line] = struct{}{}

	// Escribir + newline
	if _, err := w.buf.WriteString(line); err != nil {
		return err
	}
        if err := w.buf.WriteByte('\n'); err != nil {
                return err
        }

        // Flush inmediatamente para que los datos estén disponibles incluso si el
        // consumidor lee el archivo antes de que Writer.Close sea llamado. Esto
        // también garantiza que las pruebas que inspeccionan el contenido sin
        // cerrar explícitamente el escritor vean los resultados.
        if err := w.buf.Flush(); err != nil {
                return err
        }
        return nil
}

func (w *Writer) WriteDomain(d string) error {
	return w.writeUnique(normalizeDomain(d))
}

func (w *Writer) WriteRaw(line string) error {
	return w.writeUnique(strings.TrimSpace(line))
}

func (w *Writer) WriteURL(u string) error {
	return w.writeUnique(normalizeURL(u))
}
