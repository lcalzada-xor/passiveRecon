package logx

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// ANSI color codes
const (
	colorReset   = "\033[0m"
	colorBold    = "\033[1m"
	colorDim     = "\033[2m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorGray    = "\033[37m"
	colorBgRed   = "\033[41m"
	colorBgGreen = "\033[42m"
)

// LogFormatter gestiona el formato mejorado de logs
type LogFormatter struct {
	colorEnabled bool
	timeFormat   string
}

// NewLogFormatter crea un nuevo formatter
func NewLogFormatter(colorEnabled bool) *LogFormatter {
	return &LogFormatter{
		colorEnabled: colorEnabled,
		timeFormat:   "15:04:05",
	}
}

// Format formatea un log entry con estructura mejorada
func (f *LogFormatter) Format(level, message string, fields map[string]interface{}) string {
	var (
		prefix   string
		levColor string
		icon     string
	)

	// Configurar prefijo, color e icono según nivel
	switch level {
	case "ERR", "error":
		levColor = colorRed
		icon = "✗"
		prefix = f.colored(colorBold+colorRed, "[ERROR]")
	case "WRN", "warn":
		levColor = colorYellow
		icon = "⚠"
		prefix = f.colored(colorBold+colorYellow, "[WARN]")
	case "INF", "info":
		levColor = colorGreen
		icon = "✓"
		prefix = f.colored(colorBold+colorGreen, "[INFO]")
	case "DBG", "debug":
		levColor = colorBlue
		icon = "→"
		prefix = f.colored(colorBold+colorBlue, "[DEBUG]")
	case "TRC", "trace":
		levColor = colorGray
		icon = "•"
		prefix = f.colored(colorDim+colorGray, "[TRACE]")
	default:
		levColor = colorGray
		icon = "•"
		prefix = f.colored(colorGray, "[LOG]")
	}

	now := time.Now().Format(f.timeFormat)
	timestamp := f.colored(colorDim+colorGray, fmt.Sprintf("[%s]", now))

	// Construir línea principal
	mainLine := fmt.Sprintf("%s %s %s %s", timestamp, prefix, icon, message)

	// Si no hay fields, retornar solo el mensaje
	if len(fields) == 0 {
		return mainLine
	}

	// Formattear fields
	details := f.formatFields(fields, levColor)
	if details == "" {
		return mainLine
	}

	return mainLine + "\n" + details
}

// formatFields formatea los fields de manera estructurada y legible
func (f *LogFormatter) formatFields(fields map[string]interface{}, color string) string {
	if len(fields) == 0 {
		return ""
	}

	var lines []string

	// Mostrar main fields en una línea si hay pocos
	mainFields := f.extractMainFields(fields)

	if len(mainFields) > 0 {
		var parts []string
		for key, val := range mainFields {
			parts = append(parts, f.formatField(key, val))
		}
		if len(parts) > 0 {
			indented := f.indent(strings.Join(parts, " | "))
			lines = append(lines, indented)
		}
	}

	// Mostrar fields secundarios en líneas adicionales
	secondaryFields := f.extractSecondaryFields(fields)
	for key, val := range secondaryFields {
		line := fmt.Sprintf("%s: %v", f.colored(colorCyan, key), val)
		indented := f.indent(line)
		lines = append(lines, indented)
	}

	return strings.Join(lines, "\n")
}

// extractMainFields extrae los fields más importantes a mostrar
func (f *LogFormatter) extractMainFields(fields map[string]interface{}) map[string]interface{} {
	important := map[string]bool{
		"target":      true,
		"tool":        true,
		"status":      true,
		"duration_ms": true,
		"outputs":     true,
		"errors":      true,
		"timeout_sec": true,
		"workers":     true,
		"scope":       true,
		"active":      true,
		"report":      true,
		"concurrencia": true,
		"steps":       true,
		"reason":      true,
	}

	result := make(map[string]interface{})
	for k, v := range fields {
		if important[k] || strings.HasPrefix(k, "duration") {
			result[k] = v
		}
	}
	return result
}

// extractSecondaryFields extrae los fields secundarios
func (f *LogFormatter) extractSecondaryFields(fields map[string]interface{}) map[string]interface{} {
	important := map[string]bool{
		"target":      true,
		"tool":        true,
		"status":      true,
		"duration_ms": true,
		"outputs":     true,
		"errors":      true,
		"timeout_sec": true,
		"workers":     true,
		"scope":       true,
		"active":      true,
		"report":      true,
		"concurrencia": true,
		"steps":       true,
		"reason":      true,
	}

	result := make(map[string]interface{})
	for k, v := range fields {
		if !important[k] && !strings.HasPrefix(k, "duration") {
			result[k] = v
		}
	}
	return result
}

// formatField formatea un campo individual
func (f *LogFormatter) formatField(key string, val interface{}) string {
	return fmt.Sprintf("%s: %v", f.colored(colorCyan, key), val)
}

// indent añade indentación a una línea
func (f *LogFormatter) indent(line string) string {
	return "    " + line
}

// colored aplica color a un string si está habilitado
func (f *LogFormatter) colored(codes, text string) string {
	if !f.colorEnabled {
		return text
	}
	return codes + text + colorReset
}

// formatSummary formatea un resumen de ejecución
func (f *LogFormatter) FormatSummary(title string, stats map[string]interface{}) string {
	sep := f.colored(colorGreen, "═")
	line := strings.Repeat(sep, 50)

	output := fmt.Sprintf("\n%s\n", line)
	output += fmt.Sprintf("  %s\n", f.colored(colorBold+colorGreen, title))
	output += fmt.Sprintf("%s\n", line)

	for key, val := range stats {
		output += fmt.Sprintf("  %s: %v\n", f.colored(colorCyan, key), val)
	}

	return output
}

// WriteLog escribe un log formateado a un writer
func (f *LogFormatter) WriteLog(w io.Writer, level, message string, fields map[string]interface{}) {
	formatted := f.Format(level, message, fields)
	fmt.Fprintln(w, formatted)
}

// EnableColors establece si deben mostrarse colores
func (f *LogFormatter) EnableColors(enabled bool) {
	f.colorEnabled = enabled
}

// SetTimeFormat cambia el formato de timestamp
func (f *LogFormatter) SetTimeFormat(format string) {
	f.timeFormat = format
}

// ProgressBar crea una barra de progreso simple
func (f *LogFormatter) ProgressBar(current, total int) string {
	if total == 0 {
		return ""
	}

	percent := float64(current) / float64(total)
	filled := int(percent * 20)
	empty := 20 - filled

	bar := fmt.Sprintf("[%s%s] %d/%d",
		strings.Repeat("█", filled),
		strings.Repeat("░", empty),
		current,
		total,
	)

	if percent >= 1.0 {
		return f.colored(colorGreen, bar)
	} else if percent >= 0.5 {
		return f.colored(colorYellow, bar)
	}
	return bar
}
