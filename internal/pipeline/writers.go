package pipeline

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"passive-rec/internal/out"
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

func (p writerPair) writer(active bool) sinkWriter {
	if active {
		return p.active
	}
	return p.passive
}

type CategoryWriters map[string]writerPair

func (cw CategoryWriters) add(name string, pair writerPair) {
	if cw != nil {
		cw[name] = pair
	}
}

func (cw CategoryWriters) pair(name string) writerPair {
	if cw == nil {
		return writerPair{}
	}
	return cw[name]
}

func (cw CategoryWriters) closeAll() error {
	if cw == nil {
		return nil
	}
	var firstErr error
	for _, pair := range cw {
		if pair.passive != nil {
			if err := pair.passive.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		if pair.active != nil {
			if err := pair.active.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

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

func (lw *lazyWriter) withWriter(action func(*out.Writer) error) error {
	if lw == nil {
		return nil
	}
	w, err := lw.ensure()
	if err != nil {
		return err
	}
	return action(w)
}

func (lw *lazyWriter) WriteURL(u string) error {
	if lw == nil || u == "" {
		return nil
	}
	return lw.withWriter(func(w *out.Writer) error {
		return w.WriteURL(u)
	})
}

func (lw *lazyWriter) WriteRaw(line string) error {
	if lw == nil || line == "" {
		return nil
	}
	return lw.withWriter(func(w *out.Writer) error {
		return w.WriteRaw(line)
	})
}

func (lw *lazyWriter) WriteDomain(domain string) error {
	if lw == nil || domain == "" {
		return nil
	}
	return lw.withWriter(func(w *out.Writer) error {
		return w.WriteDomain(domain)
	})
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

func makeLazyWriterPair(outdir, subdir, passiveName, activeName string) writerPair {
	newWriter := func(name string) sinkWriter {
		if name == "" {
			return nil
		}
		return newLazyWriter(outdir, subdir, name)
	}
	return writerPair{
		passive: newWriter(passiveName),
		active:  newWriter(activeName),
	}
}
