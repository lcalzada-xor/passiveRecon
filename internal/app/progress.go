package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"passive-rec/internal/runner"
)

type progressBar struct {
	mu           sync.Mutex
	total        int
	current      int
	width        int
	lastLineLen  int
	done         bool
	out          io.Writer
	lastRendered string
	missing      []string
}

func newProgressBar(total int, out io.Writer) *progressBar {
	if out == nil {
		out = os.Stderr
	}
	pb := &progressBar{total: total, width: 30, out: out}
	if total > 0 {
		pb.renderInitial()
	}
	return pb
}

func (p *progressBar) renderInitial() {
	p.mu.Lock()
	defer p.mu.Unlock()

	bar := strings.Repeat("░", p.width)
	line := fmt.Sprintf("[%s] 0/%d iniciando...", bar, p.total)
	fmt.Fprint(p.out, line)
	p.lastLineLen = len(line)
	p.lastRendered = line
}

func (p *progressBar) Wrap(tool string, fn func() error) func() error {
	if p == nil {
		return fn
	}
	return func() error {
		p.StepRunning(tool)
		err := fn()
		status := "ok"
		if err != nil {
			switch {
			case errors.Is(err, runner.ErrMissingBinary):
				status = "faltante"
			case errors.Is(err, context.DeadlineExceeded):
				status = "timeout"
			default:
				status = "error"
			}
		}
		p.StepDone(tool, status)
		return err
	}
}

func (p *progressBar) StepRunning(tool string) {
	if p == nil || p.total <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.done {
		return
	}

	p.renderLocked(tool, "ejecutando")
}

func (p *progressBar) StepDone(tool, status string) {
	if p == nil || p.total <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.done {
		return
	}

	p.current++
	if p.current > p.total {
		p.current = p.total
	}

	if status == "faltante" {
		toolName := strings.TrimSpace(tool)
		if toolName != "" {
			found := false
			for _, existing := range p.missing {
				if strings.EqualFold(existing, toolName) {
					found = true
					break
				}
			}
			if !found {
				p.missing = append(p.missing, toolName)
			}
		}
	}

	p.renderLocked(tool, status)
	if p.current == p.total {
		fmt.Fprintln(p.out)
		p.lastLineLen = 0
		p.done = true
		p.lastRendered = ""
	}
}

func (p *progressBar) renderLocked(tool, status string) {
	fill := 0
	if p.total > 0 {
		fill = (p.current * p.width) / p.total
		if fill > p.width {
			fill = p.width
		}
	}
	bar := strings.Repeat("█", fill) + strings.Repeat("░", p.width-fill)

	label := strings.TrimSpace(tool)
	if status != "" {
		if label != "" {
			label = fmt.Sprintf("%s (%s)", label, status)
		} else {
			label = status
		}
	}

	line := fmt.Sprintf("\r[%s] %d/%d %s", bar, p.current, p.total, label)
	padding := 0
	if len(line) < p.lastLineLen {
		padding = p.lastLineLen - len(line)
	}
	if padding > 0 {
		line += strings.Repeat(" ", padding)
	}
	fmt.Fprint(p.out, line)
	p.lastLineLen = len(line)
	p.lastRendered = line
}

func (p *progressBar) Writer() io.Writer {
	return &progressWriter{pb: p}
}

func (p *progressBar) MissingTools() []string {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.missing) == 0 {
		return nil
	}

	out := make([]string, len(p.missing))
	copy(out, p.missing)
	return out
}

type progressWriter struct {
	pb *progressBar
}

func (w *progressWriter) Write(data []byte) (int, error) {
	if w == nil || w.pb == nil {
		return os.Stderr.Write(data)
	}

	p := w.pb
	p.mu.Lock()
	defer p.mu.Unlock()

	out := p.out
	if out == nil {
		out = os.Stderr
	}

	if p.lastLineLen > 0 && !p.done {
		clear := "\r" + strings.Repeat(" ", p.lastLineLen) + "\r"
		if _, err := fmt.Fprint(out, clear); err != nil {
			return 0, err
		}
	}

	if _, err := out.Write(data); err != nil {
		return 0, err
	}

	if p.lastRendered != "" && !p.done {
		if _, err := fmt.Fprint(out, p.lastRendered); err != nil {
			return 0, err
		}
	}

	return len(data), nil
}
