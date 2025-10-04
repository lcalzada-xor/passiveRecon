package out

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"passive-rec/internal/netutil"
)

type Writer struct {
	mu   sync.Mutex
	file *os.File
	seen map[string]bool
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
	return &Writer{file: f, seen: make(map[string]bool)}, nil
}

func (w *Writer) Close() error {
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(d)
	if d == "" {
		return ""
	}

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

	if !strings.Contains(u, "://") {
		u = "http://" + u
	}

	// If the string already contains whitespace, assume it carries metadata
	// (e.g. httpx status/title) and keep the original representation so the
	// additional information remains human-readable.
	if strings.ContainsAny(u, " \t") {
		return u
	}

	parsed, err := url.Parse(u)
	if err != nil {
		// Si la URL es inválida devolvemos la versión con esquema para evitar perder datos.
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

func (w *Writer) WriteDomain(d string) error {
	d = normalizeDomain(d)
	if d == "" {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.seen[d] {
		return nil
	}
	w.seen[d] = true
	_, err := w.file.WriteString(d + "\n")
	return err
}

func (w *Writer) WriteRaw(line string) error {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.seen[line] {
		return nil
	}
	w.seen[line] = true
	_, err := w.file.WriteString(line + "\n")
	return err
}

func (w *Writer) WriteURL(u string) error {
	u = normalizeURL(u)
	if u == "" {
		return nil
	}
	return w.WriteRaw(u)
}
