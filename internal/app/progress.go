package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"passive-rec/internal/runner"
)

type progressBar struct {
	mu          sync.Mutex
	total       int
	current     int
	width       int
	lastLineLen int
	done        bool
}

func newProgressBar(total int) *progressBar {
	pb := &progressBar{total: total, width: 30}
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
	fmt.Fprint(os.Stderr, line)
	p.lastLineLen = len(line)
}

func (p *progressBar) Wrap(tool string, fn func() error) func() error {
	if p == nil {
		return fn
	}
	return func() error {
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

	p.renderLocked(tool, status)
	if p.current == p.total {
		fmt.Fprintln(os.Stderr)
		p.lastLineLen = 0
		p.done = true
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
	fmt.Fprint(os.Stderr, line)
	p.lastLineLen = len(line)
}
