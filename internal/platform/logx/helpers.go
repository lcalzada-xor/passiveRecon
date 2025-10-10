package logx

import (
	"fmt"
	"time"
)

// LogTool logs con el campo "tool" pre-agregado para facilitar filtrado.
func LogTool(level Level, tool, msg string, extraFields ...Fields) {
	fields := Fields{"tool": tool}
	for _, extra := range extraFields {
		for k, v := range extra {
			fields[k] = v
		}
	}
	logFields(level, msg, fields)
}

// ToolErrorf es un atajo para loggear errores de herramientas.
func ToolErrorf(tool, format string, a ...interface{}) {
	LogTool(LevelError, tool, Sprintf(format, a...))
}

// ToolWarnf es un atajo para loggear warnings de herramientas.
func ToolWarnf(tool, format string, a ...interface{}) {
	LogTool(LevelWarn, tool, Sprintf(format, a...))
}

// ToolInfof es un atajo para loggear info de herramientas.
func ToolInfof(tool, format string, a ...interface{}) {
	LogTool(LevelInfo, tool, Sprintf(format, a...))
}

// ToolDebugf es un atajo para loggear debug de herramientas.
func ToolDebugf(tool, format string, a ...interface{}) {
	LogTool(LevelDebug, tool, Sprintf(format, a...))
}

// ToolTracef es un atajo para loggear trace de herramientas.
func ToolTracef(tool, format string, a ...interface{}) {
	LogTool(LevelTrace, tool, Sprintf(format, a...))
}

// TimedOperation logs el inicio y fin de una operación con su duración.
type TimedOperation struct {
	tool      string
	operation string
	start     time.Time
	fields    Fields
}

// StartOperation inicia el tracking de una operación.
func StartOperation(tool, operation string, fields ...Fields) *TimedOperation {
	op := &TimedOperation{
		tool:      tool,
		operation: operation,
		start:     time.Now(),
		fields:    Fields{},
	}

	for _, f := range fields {
		for k, v := range f {
			op.fields[k] = v
		}
	}

	msg := operation + " started"
	LogTool(LevelDebug, tool, msg, op.fields)

	return op
}

// Complete marca la operación como completada y loggea la duración.
func (op *TimedOperation) Complete() {
	duration := time.Since(op.start)
	op.fields["duration_ms"] = duration.Milliseconds()
	op.fields["duration"] = duration.String()

	msg := op.operation + " completed"
	LogTool(LevelInfo, op.tool, msg, op.fields)
}

// Fail marca la operación como fallida y loggea el error.
func (op *TimedOperation) Fail(err error) {
	duration := time.Since(op.start)
	op.fields["duration_ms"] = duration.Milliseconds()
	op.fields["duration"] = duration.String()
	op.fields["error"] = err.Error()

	msg := op.operation + " failed"
	LogTool(LevelError, op.tool, msg, op.fields)
}

// AddField añade un campo adicional a la operación.
func (op *TimedOperation) AddField(key string, value interface{}) {
	if op.fields == nil {
		op.fields = Fields{}
	}
	op.fields[key] = value
}

// Sprintf es un helper para formatear strings (evita tener que importar fmt).
func Sprintf(format string, a ...interface{}) string {
	return fmt.Sprintf(format, a...)
}

// LogMetrics loggea métricas con estructura consistente.
func LogMetrics(tool string, metrics map[string]interface{}) {
	fields := Fields{"type": "metrics"}
	for k, v := range metrics {
		fields[k] = v
	}
	LogTool(LevelInfo, tool, "metrics", fields)
}

// LogProgress loggea progreso de una operación (útil para operaciones largas).
func LogProgress(tool string, current, total int64, extra ...Fields) {
	percent := float64(current) / float64(total) * 100
	fields := Fields{
		"current": current,
		"total":   total,
		"percent": Sprintf("%.1f%%", percent),
	}
	for _, e := range extra {
		for k, v := range e {
			fields[k] = v
		}
	}
	LogTool(LevelInfo, tool, "progress", fields)
}

// LogBinary loggea información sobre un binario encontrado o faltante.
func LogBinary(tool, binary, status string, extra ...Fields) {
	fields := Fields{
		"binary": binary,
		"status": status,
	}
	for _, e := range extra {
		for k, v := range e {
			fields[k] = v
		}
	}

	level := LevelInfo
	if status == "missing" {
		level = LevelError
	}

	LogTool(level, tool, Sprintf("binary %s: %s", binary, status), fields)
}

// LogValidation loggea resultados de validación.
func LogValidation(tool string, valid, total int, warnings int) {
	fields := Fields{
		"valid":       valid,
		"total":       total,
		"invalid":     total - valid,
		"warnings":    warnings,
		"valid_pct":   Sprintf("%.1f%%", float64(valid)/float64(total)*100),
		"invalid_pct": Sprintf("%.1f%%", float64(total-valid)/float64(total)*100),
	}

	level := LevelInfo
	if valid < total/2 {
		level = LevelWarn
	}

	LogTool(level, tool, "validation results", fields)
}
