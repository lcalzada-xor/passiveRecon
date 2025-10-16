package logx

import (
	"fmt"
	"io"
	"strings"
	"time"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[37m"
)

// LogFormatter gestiona el formato mejorado de logs
type LogFormatter struct {
	colorEnabled bool
	timeFormat   string
	compact      bool
	width        int
	dedupCache   map[string]int
}

// NewLogFormatter crea un nuevo formatter
func NewLogFormatter(colorEnabled bool) *LogFormatter {
	return &LogFormatter{
		colorEnabled: colorEnabled,
		timeFormat:   "15:04:05",
		compact:      false,
		width:        120,
		dedupCache:   make(map[string]int),
	}
}

// Format formatea un log entry con estructura mejorada
func (f *LogFormatter) Format(level, message string, fields map[string]interface{}) string {
	var (
		badge string
		icon  string
	)

	// Configurar badge e icono según nivel
	switch level {
	case "ERR", "error":
		icon = "⛔"
		badge = f.colored(colorBold+colorRed, "ERR")
	case "WRN", "warn":
		icon = "⚠"
		badge = f.colored(colorBold+colorYellow, "WRN")
	case "INF", "info":
		icon = "✅"
		badge = f.colored(colorBold+colorGreen, "INF")
	case "DBG", "debug":
		icon = "⚙"
		badge = f.colored(colorBold+colorBlue, "DBG")
	case "TRC", "trace":
		icon = "🔍"
		badge = f.colored(colorDim+colorGray, "TRC")
	default:
		icon = "•"
		badge = f.colored(colorGray, "LOG")
	}

	now := time.Now().Format(f.timeFormat)
	timestamp := f.colored(colorDim+colorGray, now)

	// Construir línea principal con badge e icono
	mainLine := fmt.Sprintf("%s %s %s %s", timestamp, badge, icon, message)

	// Si no hay fields, retornar solo el mensaje
	if len(fields) == 0 {
		return mainLine
	}

	// Formattear fields
	details := f.formatFields(fields)
	if details == "" {
		return mainLine
	}

	return mainLine + "\n" + details
}

// formatFields formatea los fields de manera estructurada y legible
func (f *LogFormatter) formatFields(fields map[string]interface{}) string {
	if len(fields) == 0 {
		return ""
	}

	var parts []string

	// Mostrar todos los fields en una línea compacta
	mainFields := f.extractMainFields(fields)
	secondaryFields := f.extractSecondaryFields(fields)

	for key, val := range mainFields {
		parts = append(parts, f.formatField(key, val))
	}
	for key, val := range secondaryFields {
		parts = append(parts, f.formatField(key, val))
	}

	if len(parts) == 0 {
		return ""
	}

	// Mostrar en una o dos líneas máximo
	if len(parts) <= 3 {
		return f.indent(strings.Join(parts, " "))
	}

	// Si hay muchos fields, repartir en líneas
	line1 := strings.Join(parts[:len(parts)/2], " ")
	line2 := strings.Join(parts[len(parts)/2:], " ")
	return f.indent(line1) + "\n" + f.indent(line2)
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
	return "  " + line
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
	sep := f.colored(colorGreen, "─")
	line := strings.Repeat(sep, 40)

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
	filled := int(percent * 15)
	empty := 15 - filled

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

// FormatPhaseHeader formatea un encabezado de fase con caja
// Ejemplo: ── FASE: subdomain-sources (concurrency=4) ── 00:01:27
func (f *LogFormatter) FormatPhaseHeader(phase string, metadata map[string]interface{}, elapsed time.Duration) string {
	var metaStr string
	if len(metadata) > 0 {
		var parts []string
		for k, v := range metadata {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
		metaStr = fmt.Sprintf("(%s) ", strings.Join(parts, " "))
	}

	elapsedStr := FormatDuration(elapsed)
	sep := f.colored(colorGreen, "─")
	phaseName := f.colored(colorBold+colorGreen, phase)

	header := fmt.Sprintf("%s FASE: %s %s%s %s", sep, phaseName, metaStr, sep, elapsedStr)
	return header
}

// FormatCommandStart formatea el inicio de un comando
// Ejemplo: ▶ subfinder   -d uvesa.es                 (deadline ~2m)
func (f *LogFormatter) FormatCommandStart(cmdID, cmd, args string, deadline string) string {
	arrow := f.colored(colorBlue, "▶")
	cmdText := f.colored(colorBold+colorCyan, cmd)
	idText := f.colored(colorDim+colorGray, cmdID)

	// Alinear campos
	line := fmt.Sprintf("%s %s %-10s %s", arrow, idText, cmdText, args)
	if deadline != "" {
		line += fmt.Sprintf(" %s", f.colored(colorDim+colorGray, fmt.Sprintf("(deadline %s)", deadline)))
	}

	return line
}

// FormatCommandFinish formatea el fin de un comando
// Ejemplo: ✔ subfinder   done in 18.9s   exit=0  out=3 lines
func (f *LogFormatter) FormatCommandFinish(cmdID, cmd string, exitCode int, duration time.Duration, output int) string {
	checkmark := f.colored(colorGreen, "✔")
	cmdText := f.colored(colorBold+colorCyan, cmd)
	idText := f.colored(colorDim+colorGray, cmdID)
	durationStr := FormatDuration(duration)

	var parts []string
	parts = append(parts, fmt.Sprintf("done in %s", durationStr))
	if exitCode == 0 {
		parts = append(parts, f.colored(colorGreen, fmt.Sprintf("exit=%d", exitCode)))
	} else {
		parts = append(parts, f.colored(colorRed, fmt.Sprintf("exit=%d", exitCode)))
	}
	if output > 0 {
		parts = append(parts, fmt.Sprintf("out=%d", output))
	}

	line := fmt.Sprintf("%s %s %-10s %s", checkmark, idText, cmdText, strings.Join(parts, "  "))
	return line
}

// FormatCommandError formatea un error de comando
// Ejemplo: ✗ cmd#A1 subfinder   error: connection timeout
func (f *LogFormatter) FormatCommandError(cmdID, cmd, errMsg string) string {
	cross := f.colored(colorRed, "✗")
	cmdText := f.colored(colorBold+colorCyan, cmd)
	idText := f.colored(colorDim+colorGray, cmdID)
	errText := f.colored(colorRed, errMsg)

	return fmt.Sprintf("%s %s %-10s error: %s", cross, idText, cmdText, errText)
}
