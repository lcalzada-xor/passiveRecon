package logx

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Spinner gestiona un indicador de progreso animado
type Spinner struct {
	mu          sync.Mutex
	frames      []string
	frameIndex  int
	active      bool
	stopCh      chan struct{}
	stoppedCh   chan struct{}
	writer      io.Writer
	prefix      string
	isTTY       bool
	refreshRate time.Duration
	manager     *spinnerManager
}

// NewSpinner crea un nuevo spinner
func NewSpinner(prefix string) *Spinner {
	// Detectar si estamos en TTY
	isTTY := IsTerminal(os.Stderr)

	writer := GetOutputWriter()
	if writer == nil {
		writer = os.Stderr
	}

	return &Spinner{
		frames:      SpinnerFrames,
		frameIndex:  0,
		active:      false,
		stopCh:      make(chan struct{}),
		stoppedCh:   make(chan struct{}),
		writer:      writer,
		prefix:      prefix,
		isTTY:       isTTY,
		refreshRate: 100 * time.Millisecond,
		manager:     defaultSpinnerManager,
	}
}

// Start inicia la animación del spinner
func (s *Spinner) Start() {
	s.mu.Lock()
	if s.active {
		s.mu.Unlock()
		return
	}
	s.active = true
	s.mu.Unlock()

	// Si no es TTY, solo imprimir el primer frame y salir
	if !s.isTTY {
		s.mu.Lock()
		frame := SpinnerFrames[0]
		formatter := GetFormatter()
		frame = formatter.colored(colorBlue, frame)
		fmt.Fprintf(s.writer, "%s %s\n", frame, s.prefix)
		s.mu.Unlock()
		close(s.stoppedCh)
		return
	}

	if s.manager != nil {
		s.manager.addSpinner(s)
	}

	go func() {
		defer close(s.stoppedCh)

		ticker := time.NewTicker(s.refreshRate)
		defer ticker.Stop()

		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.mu.Lock()
				if !s.active {
					s.mu.Unlock()
					return
				}

				s.frameIndex = (s.frameIndex + 1) % len(s.frames)
				s.mu.Unlock()

				if s.manager != nil {
					s.manager.render()
				}
			}
		}
	}()
}

// Stop detiene el spinner y muestra el mensaje final
func (s *Spinner) Stop(finalMsg string) {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return
	}
	s.active = false
	s.mu.Unlock()

	// Señalar parada
	close(s.stopCh)

	// Esperar a que termine la goroutine
	<-s.stoppedCh

	s.mu.Lock()
	isTTY := s.isTTY
	s.mu.Unlock()

	if isTTY && s.manager != nil {
		s.manager.finishSpinner(s, finalMsg)
		return
	}

	if finalMsg != "" {
		fmt.Fprintf(s.writer, "%s\n", finalMsg)
	}
}

// StopSuccess detiene con mensaje de éxito
func (s *Spinner) StopSuccess(msg string) {
	formatter := GetFormatter()
	status := formatter.colored(colorGreen, "[✔]")
	s.Stop(fmt.Sprintf("%s %s", status, msg))
}

// StopError detiene con mensaje de error
func (s *Spinner) StopError(msg string) {
	formatter := GetFormatter()
	status := formatter.colored(colorRed, "[✗]")
	s.Stop(fmt.Sprintf("%s %s", status, msg))
}

// UpdatePrefix actualiza el texto del spinner sin detenerlo
func (s *Spinner) UpdatePrefix(prefix string) {
	s.mu.Lock()
	s.prefix = prefix
	s.mu.Unlock()
	if s.isTTY && s.manager != nil {
		s.manager.render()
	}
}

type spinnerManager struct {
	mu           sync.Mutex
	renderMu     sync.Mutex
	spinners     []*Spinner
	lastRendered int
}

var defaultSpinnerManager = &spinnerManager{}

func (m *spinnerManager) addSpinner(s *Spinner) {
	m.mu.Lock()
	m.spinners = append(m.spinners, s)
	m.mu.Unlock()
	m.render()
}

func (m *spinnerManager) finishSpinner(s *Spinner, finalMsg string) {
	m.mu.Lock()
	for i, candidate := range m.spinners {
		if candidate == s {
			m.spinners = append(m.spinners[:i], m.spinners[i+1:]...)
			break
		}
	}
	m.mu.Unlock()

	m.render()

	if finalMsg == "" {
		return
	}

	m.renderMu.Lock()
	defer m.renderMu.Unlock()

	writer := GetOutputWriter()
	if writer == nil {
		writer = os.Stderr
	}
	fmt.Fprintf(writer, "%s\n", finalMsg)
}

func (m *spinnerManager) render() {
	m.mu.Lock()
	spinners := make([]*Spinner, len(m.spinners))
	copy(spinners, m.spinners)
	prevLines := m.lastRendered
	m.lastRendered = len(spinners)
	m.mu.Unlock()

	writer := GetOutputWriter()
	if writer == nil {
		writer = os.Stderr
	}

	formatter := GetFormatter()

	var lines []string
	for _, sp := range spinners {
		sp.mu.Lock()
		frame := sp.frames[sp.frameIndex]
		prefix := sp.prefix
		sp.mu.Unlock()

		colored := formatter.colored(colorBlue, frame)
		lines = append(lines, fmt.Sprintf("%s %s", colored, prefix))
	}

	m.renderMu.Lock()
	defer m.renderMu.Unlock()

	m.renderLines(writer, lines, prevLines)
}

func (m *spinnerManager) renderLines(w io.Writer, lines []string, prevLines int) {
	if prevLines > 0 {
		for i := 0; i < prevLines; i++ {
			fmt.Fprint(w, "\033[F")
		}
	}

	for _, line := range lines {
		fmt.Fprint(w, "\r\033[2K")
		fmt.Fprint(w, line)
		fmt.Fprint(w, "\n")
	}

	if prevLines > len(lines) {
		remaining := prevLines - len(lines)
		for i := 0; i < remaining; i++ {
			fmt.Fprint(w, "\r\033[2K\n")
		}
	}

	if len(lines) == 0 {
		fmt.Fprint(w, "\r\033[2K")
	}
}
