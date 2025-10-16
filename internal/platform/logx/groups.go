package logx

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// GroupTracker rastrea información de grupos
type GroupTracker struct {
	mu       sync.Mutex
	groups   map[string]*GroupInfo
	nextID   int
	dedup    *MessageDeduplicator
	formatter *LogFormatter
}

// GroupInfo almacena información de un grupo
type GroupInfo struct {
	ID        string
	Name      string
	StartTime time.Time
	Tools     int
	Artifacts int64
	Status    string
}

// NewGroupTracker crea un nuevo rastreador de grupos
func NewGroupTracker(formatter *LogFormatter) *GroupTracker {
	return &GroupTracker{
		groups:    make(map[string]*GroupInfo),
		nextID:    1,
		dedup:     NewMessageDeduplicator(),
		formatter: formatter,
	}
}

// StartGroup inicia un nuevo grupo
func (gt *GroupTracker) StartGroup(name string, metadata map[string]interface{}) string {
	gt.mu.Lock()
	defer gt.mu.Unlock()

	id := fmt.Sprintf("grp#G%d", gt.nextID)
	gt.nextID++

	group := &GroupInfo{
		ID:        id,
		Name:      name,
		StartTime: time.Now(),
		Tools:     0,
		Artifacts: 0,
		Status:    "running",
	}

	gt.groups[id] = group

	// Loggear cabecera
	elapsed := time.Since(group.StartTime)
	header := gt.formatter.FormatPhaseHeader(name, metadata, elapsed)
	Infof(header)

	return id
}

// EndGroup termina un grupo y loggea el resumen
func (gt *GroupTracker) EndGroup(groupID string) {
	gt.mu.Lock()
	group, exists := gt.groups[groupID]
	gt.mu.Unlock()

	if !exists {
		return
	}

	elapsed := time.Since(group.StartTime)
	group.Status = "completed"

	// Loggear resumen
	summary := fmt.Sprintf(
		"group=%s tools=%d artifacts=%d elapsed=%s",
		group.Name,
		group.Tools,
		group.Artifacts,
		FormatDuration(elapsed),
	)
	Infof(summary)
}

// RegisterTool registra una herramienta en un grupo
func (gt *GroupTracker) RegisterTool(groupID string) string {
	gt.mu.Lock()
	defer gt.mu.Unlock()

	group, exists := gt.groups[groupID]
	if !exists {
		return ""
	}

	cmdID := fmt.Sprintf("cmd#C%d", gt.nextID)
	gt.nextID++
	group.Tools++

	return cmdID
}

// AddArtifacts suma artefactos a un grupo
func (gt *GroupTracker) AddArtifacts(groupID string, count int64) {
	gt.mu.Lock()
	defer gt.mu.Unlock()

	group, exists := gt.groups[groupID]
	if exists {
		group.Artifacts += count
	}
}

// CheckMessageDedupe verifica si un mensaje debe ser deduplicado
func (gt *GroupTracker) CheckMessageDedupe(message string) (string, bool) {
	shouldLog, count := gt.dedup.ShouldLog(message)
	if count > 1 && !shouldLog {
		return FormatDedupedMessage(message, count), false
	}
	return message, shouldLog
}

// FormatStderr formatea salida de stderr con plegado opcional
func FormatStderrOutput(stderr string, maxLines int) string {
	lines := strings.Split(strings.TrimSpace(stderr), "\n")
	if len(lines) <= maxLines {
		return stderr
	}

	preview := strings.Join(lines[:maxLines], "\n")
	return fmt.Sprintf("%s\n... and %d more lines (use -v trace to expand)", preview, len(lines)-maxLines)
}
