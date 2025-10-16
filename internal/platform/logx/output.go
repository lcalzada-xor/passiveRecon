package logx

import (
	"io"
	"os"

	"golang.org/x/term"
)

// OutputConfig gestiona la configuración de salida
type OutputConfig struct {
	IsTTY       bool
	NoColor     bool
	Compact     bool
	Width       int
	ShowVerbose bool
}

// DetectOutput detecta características del terminal
func DetectOutput(w io.Writer) OutputConfig {
	isTTY := isTTY(w)

	return OutputConfig{
		IsTTY:       isTTY,
		NoColor:     !isTTY,
		Compact:     false,
		Width:       120,
		ShowVerbose: false,
	}
}

// isTTY detecta si el writer está conectado a un terminal
func isTTY(w io.Writer) bool {
	if f, ok := w.(*os.File); ok {
		return isTerminal(f.Fd())
	}
	return false
}

// isTerminal verifica si un file descriptor es un terminal
func isTerminal(fd uintptr) bool {
	// En Linux/Unix, podemos usar isatty
	return checkIfTerminal(fd)
}

// checkIfTerminal es la implementación real (depende del SO)
func checkIfTerminal(fd uintptr) bool {
	return term.IsTerminal(int(fd))
}

// IsTerminal verifica si el writer es un terminal (función exportada)
func IsTerminal(w io.Writer) bool {
	return isTTY(w)
}
