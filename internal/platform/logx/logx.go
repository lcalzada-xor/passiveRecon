package logx

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/rs/zerolog"
)

// Level representa el nivel de logging (compatible con API anterior)
type Level uint8

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
	LevelTrace
)

// Fields representa pares clave-valor para structured logging
type Fields map[string]any

// Config gestiona la configuración global del logger
type Config struct {
	mu         sync.RWMutex
	logger     zerolog.Logger
	formatter  *LogFormatter
	level      Level
	outputCfg  OutputConfig
	groupTrack *GroupTracker
}

var cfg = &Config{
	logger: zerolog.New(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: "15:04:05",
		NoColor:    false,
	}).With().Timestamp().Logger(),
	formatter: NewLogFormatter(true),
	level:     LevelInfo,
	outputCfg: DetectOutput(os.Stderr),
}

var sampleRates = map[string]int{
	"httpx": 25,
	"dnsx":  25,
}

var sampleState = struct {
	sync.Mutex
	counters map[string]int64
}{counters: make(map[string]int64)}

// SetVerbosity configura el nivel según la API antigua: 0=info, 1=info, 2=debug, 3=trace
func SetVerbosity(v int) {
	switch {
	case v <= 0:
		SetLevel(LevelInfo)
	case v == 1:
		SetLevel(LevelInfo)
	case v == 2:
		SetLevel(LevelDebug)
	default:
		SetLevel(LevelTrace)
	}
}

// SetLevel cambia el nivel mínimo de logging
func SetLevel(l Level) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()
	cfg.level = l

	// Mapear a niveles de zerolog
	var zlevel zerolog.Level
	switch l {
	case LevelError:
		zlevel = zerolog.ErrorLevel
	case LevelWarn:
		zlevel = zerolog.WarnLevel
	case LevelInfo:
		zlevel = zerolog.InfoLevel
	case LevelDebug:
		zlevel = zerolog.DebugLevel
	case LevelTrace:
		zlevel = zerolog.TraceLevel
	default:
		zlevel = zerolog.InfoLevel
	}

	zerolog.SetGlobalLevel(zlevel)
}

// ParseLevel convierte string a Level
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

// SetOutput redirige la salida del logger
func SetOutput(w io.Writer) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	if w == nil {
		w = os.Stderr
	}

	// Recrear logger con nuevo writer
	cfg.logger = zerolog.New(zerolog.ConsoleWriter{
		Out:        w,
		TimeFormat: "15:04:05",
		NoColor:    false,
	}).With().Timestamp().Logger()
}

// AddOutput no soportado directamente en zerolog, usar MultiLevelWriter en caller
func AddOutput(w io.Writer) {
	if w == nil {
		return
	}
	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	// Usar MultiLevelWriter de zerolog
	multi := zerolog.MultiLevelWriter(
		zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: "15:04:05",
			NoColor:    false,
		},
		w,
	)

	cfg.logger = zerolog.New(multi).With().Timestamp().Logger()
	SetLevel(cfg.level)
}

// EnableColors activa/desactiva colores ANSI
func EnableColors(enabled bool) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	// Recrear console writer con opción de color
	cfg.logger = zerolog.New(zerolog.ConsoleWriter{
		Out:        os.Stderr,
		TimeFormat: "15:04:05",
		NoColor:    !enabled,
	}).With().Timestamp().Logger()

	// Actualizar formatter
	cfg.formatter.EnableColors(enabled)
	cfg.outputCfg.NoColor = !enabled
}

// SetJSON habilita output JSON estructurado
func SetJSON(enabled bool) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	if enabled {
		cfg.logger = zerolog.New(os.Stderr).With().Timestamp().Logger()
	} else {
		cfg.logger = zerolog.New(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: "15:04:05",
			NoColor:    false,
		}).With().Timestamp().Logger()
	}
}

// SetCaller habilita mostrar archivo:línea
func SetCaller(enabled bool) {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	if enabled {
		cfg.logger = cfg.logger.With().Caller().Logger()
	}
}

// SetTimeFormat cambia formato de timestamp (no-op en zerolog, usa formato fijo)
func SetTimeFormat(tf string) {
	// No-op: zerolog usa su propio formato
}

// SetTimestamps habilita/deshabilita timestamps
func SetTimestamps(enabled bool) {
	// zerolog siempre incluye timestamps en modo With().Timestamp()
	// Para deshabilitar habría que recrear sin .Timestamp()
	if !enabled {
		cfg.mu.Lock()
		defer cfg.mu.Unlock()
		cfg.logger = zerolog.New(zerolog.ConsoleWriter{
			Out:        os.Stderr,
			TimeFormat: "15:04:05",
			NoColor:    false,
		})
	}
}

// SetUTC fuerza timestamps en UTC
func SetUTC(enabled bool) {
	// zerolog por defecto usa time.Now(), no hay override simple
	// Esta es una no-op para mantener compatibilidad de API
}

// SetPrefix añade un prefijo (implementado como field constante)
func SetPrefix(p string) {
	if p != "" {
		cfg.mu.Lock()
		defer cfg.mu.Unlock()
		cfg.logger = cfg.logger.With().Str("prefix", p).Logger()
	}
}

// Atajos de nivel - API compatible con logx original
func Errorf(format string, a ...interface{}) {
	cfg.mu.RLock()
	logger := cfg.logger
	cfg.mu.RUnlock()
	logger.Error().Msgf(format, a...)
}

func Warnf(format string, a ...interface{}) {
	cfg.mu.RLock()
	logger := cfg.logger
	cfg.mu.RUnlock()
	logger.Warn().Msgf(format, a...)
}

func Infof(format string, a ...interface{}) {
	cfg.mu.RLock()
	logger := cfg.logger
	cfg.mu.RUnlock()
	logger.Info().Msgf(format, a...)
}

func Debugf(format string, a ...interface{}) {
	cfg.mu.RLock()
	logger := cfg.logger
	cfg.mu.RUnlock()
	logger.Debug().Msgf(format, a...)
}

func Tracef(format string, a ...interface{}) {
	cfg.mu.RLock()
	logger := cfg.logger
	cfg.mu.RUnlock()
	logger.Trace().Msgf(format, a...)
}

// Funciones con fields estructurados
func Error(msg string, fields Fields) {
	if shouldSampleFields(LevelError, fields) {
		return
	}
	cfg.mu.RLock()
	logger := cfg.logger
	cfg.mu.RUnlock()

	event := logger.Error()
	for k, v := range fields {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

func Warn(msg string, fields Fields) {
	if shouldSampleFields(LevelWarn, fields) {
		return
	}
	cfg.mu.RLock()
	logger := cfg.logger
	cfg.mu.RUnlock()

	event := logger.Warn()
	for k, v := range fields {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

func Info(msg string, fields Fields) {
	if shouldSampleFields(LevelInfo, fields) {
		return
	}
	cfg.mu.RLock()
	logger := cfg.logger
	cfg.mu.RUnlock()

	event := logger.Info()
	for k, v := range fields {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

func Debug(msg string, fields Fields) {
	if shouldSampleFields(LevelDebug, fields) {
		return
	}
	cfg.mu.RLock()
	logger := cfg.logger
	cfg.mu.RUnlock()

	event := logger.Debug()
	for k, v := range fields {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

func Trace(msg string, fields Fields) {
	if shouldSampleFields(LevelTrace, fields) {
		return
	}
	cfg.mu.RLock()
	logger := cfg.logger
	cfg.mu.RUnlock()

	event := logger.Trace()
	for k, v := range fields {
		event = event.Interface(k, v)
	}
	event.Msg(msg)
}

// V mantiene compatibilidad con API anterior de verbosity
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

// shouldSampleFields implementa sampling para reducir noise en logs debug
func shouldSampleFields(lvl Level, fields Fields) bool {
	if lvl < LevelDebug || len(fields) == 0 {
		return false
	}
	toolRaw, ok := fields["tool"]
	if !ok {
		return false
	}
	tool, ok := toolRaw.(string)
	if !ok {
		return false
	}
	tool = strings.ToLower(strings.TrimSpace(tool))
	if tool == "" {
		return false
	}
	rate, ok := sampleRates[tool]
	if !ok || rate <= 1 {
		return false
	}
	sampleState.Lock()
	defer sampleState.Unlock()
	count := sampleState.counters[tool] + 1
	sampleState.counters[tool] = count
	if count%int64(rate) != 1 {
		return true
	}
	return false
}

// logFields es un helper para mantener compatibilidad con helpers.go
func logFields(lvl Level, msg string, fields Fields) {
	switch lvl {
	case LevelError:
		Error(msg, fields)
	case LevelWarn:
		Warn(msg, fields)
	case LevelInfo:
		Info(msg, fields)
	case LevelDebug:
		Debug(msg, fields)
	case LevelTrace:
		Trace(msg, fields)
	}
}

// GetFormatter retorna el formatter global (para uso en otros módulos)
func GetFormatter() *LogFormatter {
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()
	return cfg.formatter
}

// GetLevel retorna el nivel actual de logging
func GetLevel() Level {
	cfg.mu.RLock()
	defer cfg.mu.RUnlock()
	return cfg.level
}

// GetGroupTracker retorna el rastreador de grupos
func GetGroupTracker() *GroupTracker {
	cfg.mu.Lock()
	defer cfg.mu.Unlock()

	if cfg.groupTrack == nil {
		cfg.groupTrack = NewGroupTracker(cfg.formatter)
	}
	return cfg.groupTrack
}

// ConfigureCliFlags configura los flags de CLI
type CliFlags struct {
	NoColor   bool
	Compact   bool
	Verbosity string
	Width     int
}

// ApplyCliFlags aplica configuración desde flags de CLI
func ApplyCliFlags(flags CliFlags) {
	if flags.NoColor {
		EnableColors(false)
	}

	cfg.mu.Lock()
	if flags.Compact {
		cfg.formatter.compact = true
		cfg.outputCfg.Compact = true
	}

	if flags.Width > 0 {
		cfg.formatter.width = flags.Width
		cfg.outputCfg.Width = flags.Width
	}
	cfg.mu.Unlock()

	// Mapear verbosity (sin lock para evitar deadlock)
	switch flags.Verbosity {
	case "trace":
		SetLevel(LevelTrace)
	case "debug":
		SetLevel(LevelDebug)
	case "info":
		SetLevel(LevelInfo)
	case "warn":
		SetLevel(LevelWarn)
	case "error":
		SetLevel(LevelError)
	}
}
