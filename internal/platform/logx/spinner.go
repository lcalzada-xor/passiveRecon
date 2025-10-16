package logx

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// ANSI escape codes
const (
	ansiClearLine     = "\r\033[K"
	ansiHideCursor    = "\033[?25l"
	ansiShowCursor    = "\033[?25h"
	ansiSaveCursor    = "\0337"
	ansiRestoreCursor = "\0338"
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
	lastLine    string
	isTTY       bool
	refreshRate time.Duration
}

// NewSpinner crea un nuevo spinner
func NewSpinner(prefix string) *Spinner {
	// Detectar si estamos en TTY
	isTTY := IsTerminal(os.Stderr)

	return &Spinner{
		frames:      SpinnerFrames,
		frameIndex:  0,
		active:      false,
		stopCh:      make(chan struct{}),
		stoppedCh:   make(chan struct{}),
		writer:      os.Stderr,
		prefix:      prefix,
		isTTY:       isTTY,
		refreshRate: 100 * time.Millisecond,
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
		fmt.Fprintf(s.writer, "%s %s\n", SpinnerFrames[0], s.prefix)
		s.mu.Unlock()
		close(s.stoppedCh)
		return
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

				// Obtener formatter para aplicar colores
				formatter := GetFormatter()
				frame := formatter.colored(colorBlue, s.frames[s.frameIndex])

				// Limpiar línea y escribir nuevo frame
				line := fmt.Sprintf("\r%s %s", frame, s.prefix)
				fmt.Fprint(s.writer, line)
				s.lastLine = line

				// Siguiente frame
				s.frameIndex = (s.frameIndex + 1) % len(s.frames)
				s.mu.Unlock()
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

	// Escribir mensaje final
	s.mu.Lock()
	if s.isTTY {
		// Limpiar la línea y escribir mensaje final
		fmt.Fprintf(s.writer, "\r\033[K%s\n", finalMsg)
	} else {
		// En modo no-TTY, simplemente imprimir el mensaje en una nueva línea
		fmt.Fprintf(s.writer, "%s\n", finalMsg)
	}
	s.mu.Unlock()
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
	defer s.mu.Unlock()
	s.prefix = prefix
}
