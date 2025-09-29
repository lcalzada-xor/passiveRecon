package out

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	if i := strings.Index(d, "://"); i != -1 {
		d = d[i+3:]
	}
	if i := strings.IndexAny(d, ":/"); i != -1 {
		d = d[:i]
	}
	d = strings.TrimPrefix(d, "www.")
	return strings.ToLower(d)
}

func normalizeURL(u string) string {
	u = strings.TrimSpace(u)
	if u == "" {
		return ""
	}
	if !(strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")) {
		u = "http://" + u
	}
	return u
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
