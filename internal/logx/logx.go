package logx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

type Level uint8

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

var levelMeta = map[Level]levelInfo{
	LevelError: {label: "[ERROR]", color: "\x1b[31m"},
	LevelWarn:  {label: "[WARN]", color: "\x1b[33m"},
	LevelInfo:  {label: "[INFO]", color: "\x1b[36m"},
	LevelDebug: {label: "[DEBUG]", color: "\x1b[35m"},
	LevelTrace: {label: "[TRACE]", color: "\x1b[90m"},
}

// Config runtime segura con RWMutex
type Config struct {
	mu         sync.RWMutex
	level      Level
	out        io.Writer
	color      bool
	jsonMode   bool
	withCaller bool
	timeFormat string
	withTime   bool
	useUTC     bool
	prefix     string
}

var cfg = &Config{
	level:      LevelInfo,
	out:        os.Stderr,
	color:      true,
	jsonMode:   false,
	withCaller: false,
	timeFormat: time.RFC3339,
	withTime:   true,
	useUTC:     false,
	prefix:     "",
}

// SetVerbosity mantiene compat con tu API anterior: 0=errores, 1=info, 2=debug, 3=trace
func SetVerbosity(v int) {
	switch {
	case v <= 0:
		SetLevel(LevelError)
	case v == 1:
		SetLevel(LevelInfo)
	case v == 2:
		SetLevel(LevelDebug)
	default:
		SetLevel(LevelTrace)
	}
}

// SetLevel cambia el nivel mínimo visible
func SetLevel(l Level) {
	cfg.mu.Lock()
	cfg.level = l
	cfg.mu.Unlock()
}

// ParseLevel permite setear por string: "error", "warn", "info", "debug", "trace"
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "error", "err":
		return LevelError, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "info":
		return LevelInfo, nil
	case "debug":
		return LevelDebug, nil
	case "trace":
		return LevelTrace, nil
	default:
		return 0, fmt.Errorf("logx: nivel desconocido %q", s)
	}
}

// SetOutput redirige la salida (nil usa stderr)
func SetOutput(w io.Writer) {
	cfg.mu.Lock()
	if w == nil {
		cfg.out = os.Stderr
	} else {
		cfg.out = w
	}
	cfg.mu.Unlock()
}

// AddOutput envía el log a otro writer además del actual
func AddOutput(w io.Writer) {
	if w == nil {
		return
	}
	cfg.mu.Lock()
	cfg.out = io.MultiWriter(cfg.out, w)
	cfg.mu.Unlock()
}

// EnableColors activa o desactiva colores ANSI
func EnableColors(enabled bool) {
	cfg.mu.Lock()
	cfg.color = enabled
	cfg.mu.Unlock()
}

// SetJSON habilita salida JSON estructurada
func SetJSON(enabled bool) {
	cfg.mu.Lock()
	cfg.jsonMode = enabled
	cfg.mu.Unlock()
}

// SetCaller muestra archivo:línea
func SetCaller(enabled bool) {
	cfg.mu.Lock()
	cfg.withCaller = enabled
	cfg.mu.Unlock()
}

// SetTimeFormat cambia el formato de tiempo (ej: time.DateTime)
func SetTimeFormat(tf string) {
	cfg.mu.Lock()
	cfg.timeFormat = tf
	cfg.mu.Unlock()
}

// SetTimestamps muestra u oculta timestamp
func SetTimestamps(enabled bool) {
	cfg.mu.Lock()
	cfg.withTime = enabled
	cfg.mu.Unlock()
}

// SetUTC fuerza timestamps en UTC
func SetUTC(enabled bool) {
	cfg.mu.Lock()
	cfg.useUTC = enabled
	cfg.mu.Unlock()
}

// SetPrefix añade un prefijo al comienzo del mensaje
func SetPrefix(p string) {
	cfg.mu.Lock()
	cfg.prefix = p
	cfg.mu.Unlock()
}

// Atajos de nivel
func Errorf(format string, a ...interface{}) { logf(LevelError, format, a...) }
func Warnf(format string, a ...interface{})  { logf(LevelWarn, format, a...) }
func Infof(format string, a ...interface{})  { logf(LevelInfo, format, a...) }
func Debugf(format string, a ...interface{}) { logf(LevelDebug, format, a...) }
func Tracef(format string, a ...interface{}) { logf(LevelTrace, format, a...) }

// Compat con API anterior V
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

func logf(lvl Level, format string, a ...interface{}) {
	// snapshot de config con RLock mínimo
	cfg.mu.RLock()
	min := cfg.level
	if lvl > min && lvl != LevelError { // Error siempre imprime
		cfg.mu.RUnlock()
		return
	}
	out := cfg.out
	color := cfg.color
	jsonMode := cfg.jsonMode
	withCaller := cfg.withCaller
	tf := cfg.timeFormat
	withTime := cfg.withTime
	useUTC := cfg.useUTC
	prefix := cfg.prefix
	cfg.mu.RUnlock()

	now := time.Now()
	if useUTC {
		now = now.UTC()
	}

	msg := fmt.Sprintf(format, a...)

	if jsonMode {
		payload := map[string]any{
			"level": levelMeta[lvl].label[1 : len(levelMeta[lvl].label)-1], // sin corchetes
			"msg":   msg,
		}
		if withTime {
			payload["time"] = now.Format(tf)
		}
		if prefix != "" {
			payload["prefix"] = prefix
		}
		if withCaller {
			if file, line, ok := caller(3); ok {
				payload["file"] = file
				payload["line"] = line
			}
		}
		enc := json.NewEncoder(out)
		_ = enc.Encode(payload)
		return
	}

	var b bytes.Buffer
	if withTime {
		b.WriteString(now.Format(tf))
		b.WriteByte(' ')
	}
	if prefix != "" {
		b.WriteString(prefix)
		b.WriteByte(' ')
	}
	label := labelFor(lvl, color)
	b.WriteString(label)
	b.WriteByte(' ')
	if withCaller {
		if file, line, ok := caller(3); ok {
			fmt.Fprintf(&b, "(%s:%d) ", file, line)
		}
	}
	b.WriteString(msg)
	b.WriteByte('\n')
	_, _ = out.Write(b.Bytes())
}

func labelFor(lvl Level, withColor bool) string {
	info, ok := levelMeta[lvl]
	if !ok {
		return "[LOG]"
	}
	if !withColor {
		return info.label
	}
	return info.color + info.label + "\x1b[0m"
}

func caller(skip int) (file string, line int, ok bool) {
	// runtime.Caller devuelve ruta completa; nos quedamos con el tail
	_, f, ln, ok := runtime.Caller(skip)
	if !ok {
		return "", 0, false
	}
	// tail
	for i := len(f) - 1; i >= 0; i-- {
		if f[i] == '/' || f[i] == '\\' {
			f = f[i+1:]
			break
		}
	}
	return f, ln, true
}
