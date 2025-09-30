package logx

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type Level int

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

type levelInfo struct {
	label string
	color string
}

var (
	mu           sync.RWMutex
	verbosity              = 0
	output       io.Writer = os.Stderr
	colorEnabled           = true
	levels                 = map[Level]levelInfo{
		LevelError: {label: "[ERROR]", color: "\x1b[31m"},
		LevelWarn:  {label: "[WARN]", color: "\x1b[33m"},
		LevelInfo:  {label: "[INFO]", color: "\x1b[36m"},
		LevelDebug: {label: "[DEBUG]", color: "\x1b[35m"},
		LevelTrace: {label: "[TRACE]", color: "\x1b[90m"},
	}
)

// SetVerbosity configura el nivel máximo de detalle a imprimir (0=errores, 1=info, 2=debug, 3=trace).
func SetVerbosity(v int) {
	mu.Lock()
	verbosity = v
	mu.Unlock()
}

// SetOutput permite redirigir la salida del log. Si w es nil se usa stderr.
func SetOutput(w io.Writer) {
	mu.Lock()
	if w == nil {
		output = os.Stderr
	} else {
		output = w
	}
	mu.Unlock()
}

// EnableColors permite activar o desactivar colores ANSI en la salida.
func EnableColors(enabled bool) {
	mu.Lock()
	colorEnabled = enabled
	mu.Unlock()
}

// Errorf imprime siempre, independiente de la verbosidad configurada.
func Errorf(format string, a ...interface{}) { logf(LevelError, format, a...) }

// Warnf respeta verbosidad >=0 (por defecto visible salvo modo silencioso estricto).
func Warnf(format string, a ...interface{}) { logf(LevelWarn, format, a...) }

// Infof requiere verbosidad >=1.
func Infof(format string, a ...interface{}) { logf(LevelInfo, format, a...) }

// Debugf requiere verbosidad >=2.
func Debugf(format string, a ...interface{}) { logf(LevelDebug, format, a...) }

// Tracef requiere verbosidad >=3.
func Tracef(format string, a ...interface{}) { logf(LevelTrace, format, a...) }

// V mantiene compatibilidad con la API anterior.
// level>=1 equivale a Info, >=2 a Debug, >=3 a Trace. Valores <=0 se consideran advertencias.
func V(level int, format string, a ...interface{}) {
	switch {
	case level <= 0:
		Warnf(format, a...)
	case level == 1:
		Infof(format, a...)
	case level == 2:
		Debugf(format, a...)
	default:
		Tracef(format, a...)
	}
}

func logf(level Level, format string, a ...interface{}) {
	if !shouldLog(level) {
		return
	}
	msg := fmt.Sprintf(format, a...)
	stamp := time.Now().Format(time.RFC3339)
	label := formatLabel(level)

	mu.RLock()
	out := output
	mu.RUnlock()

	fmt.Fprintf(out, "%s %s %s\n", stamp, label, msg)
}

func shouldLog(level Level) bool {
	mu.RLock()
	v := verbosity
	mu.RUnlock()

	switch level {
	case LevelError:
		return true
	case LevelWarn:
		return v >= 0
	case LevelInfo:
		return v >= 1
	case LevelDebug:
		return v >= 2
	case LevelTrace:
		return v >= 3
	default:
		return false
	}
}

func formatLabel(level Level) string {
	info, ok := levels[level]
	if !ok {
		return "[LOG]"
	}
	mu.RLock()
	useColors := colorEnabled
	mu.RUnlock()
	if !useColors {
		return info.label
	}
	return fmt.Sprintf("%s%s\x1b[0m", info.color, info.label)
}
