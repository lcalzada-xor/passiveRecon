package app

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"passive-rec/internal/platform/logx"
)

const (
	// checkpointFilename es el nombre del archivo de checkpoint
	checkpointFilename = ".checkpoint.json"

	// defaultCheckpointInterval es el intervalo por defecto entre checkpoints
	defaultCheckpointInterval = 30 * time.Second

	// checkpointVersion es la versión del formato de checkpoint
	checkpointVersion = "1.0"
)

// Checkpoint representa el estado de una ejecución que puede ser resumida.
type Checkpoint struct {
	Version       string            `json:"version"`
	RunHash       string            `json:"run_hash"`
	Target        string            `json:"target"`
	StartedAt     time.Time         `json:"started_at"`
	LastUpdate    time.Time         `json:"last_update"`
	CompletedTools []string         `json:"completed_tools"`
	ToolProgress  map[string]int64  `json:"tool_progress"` // Tool -> outputs count
	ArtifactCount int64             `json:"artifact_count"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// CheckpointManager gestiona la persistencia y recuperación de checkpoints.
type CheckpointManager struct {
	mu               sync.RWMutex
	checkpoint       *Checkpoint
	path             string
	interval         time.Duration
	lastSave         time.Time
	autoSaveEnabled  bool
	stopAutoSave     chan struct{}
	autoSaveStopped  chan struct{}
}

// NewCheckpointManager crea un nuevo manager de checkpoints.
func NewCheckpointManager(outdir string, runHash string, target string, interval time.Duration) *CheckpointManager {
	if interval <= 0 {
		interval = defaultCheckpointInterval
	}

	path := filepath.Join(outdir, checkpointFilename)

	return &CheckpointManager{
		checkpoint: &Checkpoint{
			Version:       checkpointVersion,
			RunHash:       runHash,
			Target:        target,
			StartedAt:     time.Now(),
			LastUpdate:    time.Now(),
			CompletedTools: []string{},
			ToolProgress:  make(map[string]int64),
			Metadata:      make(map[string]string),
		},
		path:            path,
		interval:        interval,
		stopAutoSave:    make(chan struct{}),
		autoSaveStopped: make(chan struct{}),
	}
}

// Load intenta cargar un checkpoint existente desde disco.
func (m *CheckpointManager) Load() (*Checkpoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	data, err := os.ReadFile(m.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No checkpoint, es normal
		}
		return nil, fmt.Errorf("failed to read checkpoint: %w", err)
	}

	var checkpoint Checkpoint
	if err := json.Unmarshal(data, &checkpoint); err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint: %w", err)
	}

	// Validar versión
	if checkpoint.Version != checkpointVersion {
		logx.Warn("Checkpoint version mismatch", logx.Fields{
			"expected": checkpointVersion,
			"got": checkpoint.Version,
		})
	}

	m.checkpoint = &checkpoint
	return &checkpoint, nil
}

// Save persiste el checkpoint actual a disco.
func (m *CheckpointManager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Actualizar timestamp
	m.checkpoint.LastUpdate = time.Now()

	data, err := json.MarshalIndent(m.checkpoint, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal checkpoint: %w", err)
	}

	// Escribir atómicamente (write + rename)
	tmpPath := m.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write checkpoint: %w", err)
	}

	if err := os.Rename(tmpPath, m.path); err != nil {
		os.Remove(tmpPath) // Cleanup
		return fmt.Errorf("failed to rename checkpoint: %w", err)
	}

	m.lastSave = time.Now()
	return nil
}

// StartAutoSave inicia el guardado automático periódico.
func (m *CheckpointManager) StartAutoSave() {
	m.mu.Lock()
	if m.autoSaveEnabled {
		m.mu.Unlock()
		return
	}
	m.autoSaveEnabled = true
	m.mu.Unlock()

	go func() {
		ticker := time.NewTicker(m.interval)
		defer ticker.Stop()
		defer close(m.autoSaveStopped)

		for {
			select {
			case <-ticker.C:
				if err := m.Save(); err != nil {
					logx.Warn("Checkpoint auto-save falló", logx.Fields{"error": err.Error()})
				} else {
					logx.Debug("Checkpoint guardado", logx.Fields{
						"tools": len(m.GetCompletedTools()),
						"artifacts": m.GetArtifactCount(),
					})
				}
			case <-m.stopAutoSave:
				// Guardar una última vez antes de salir
				if err := m.Save(); err != nil {
					logx.Warn("Checkpoint final save falló", logx.Fields{"error": err.Error()})
				}
				return
			}
		}
	}()

	logx.Debug("Checkpoint auto-save iniciado", logx.Fields{"interval": m.interval.String()})
}

// StopAutoSave detiene el guardado automático.
func (m *CheckpointManager) StopAutoSave() {
	m.mu.Lock()
	if !m.autoSaveEnabled {
		m.mu.Unlock()
		return
	}
	m.autoSaveEnabled = false
	m.mu.Unlock()

	close(m.stopAutoSave)
	<-m.autoSaveStopped // Wait for goroutine to finish
}

// MarkToolCompleted marca una tool como completada.
func (m *CheckpointManager) MarkToolCompleted(tool string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Verificar si ya está en la lista
	for _, t := range m.checkpoint.CompletedTools {
		if t == tool {
			return
		}
	}

	m.checkpoint.CompletedTools = append(m.checkpoint.CompletedTools, tool)
	m.checkpoint.LastUpdate = time.Now()
}

// RecordToolProgress registra progreso de una tool.
func (m *CheckpointManager) RecordToolProgress(tool string, outputCount int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.checkpoint.ToolProgress[tool] = outputCount
	m.checkpoint.LastUpdate = time.Now()
}

// UpdateArtifactCount actualiza el contador de artifacts.
func (m *CheckpointManager) UpdateArtifactCount(count int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.checkpoint.ArtifactCount = count
	m.checkpoint.LastUpdate = time.Now()
}

// SetMetadata establece un valor de metadata.
func (m *CheckpointManager) SetMetadata(key, value string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.checkpoint.Metadata[key] = value
	m.checkpoint.LastUpdate = time.Now()
}

// GetCompletedTools retorna las tools completadas.
func (m *CheckpointManager) GetCompletedTools() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Retornar copia para evitar race conditions
	tools := make([]string, len(m.checkpoint.CompletedTools))
	copy(tools, m.checkpoint.CompletedTools)
	return tools
}

// GetArtifactCount retorna el contador de artifacts.
func (m *CheckpointManager) GetArtifactCount() int64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.checkpoint.ArtifactCount
}

// GetCheckpoint retorna una copia del checkpoint actual.
func (m *CheckpointManager) GetCheckpoint() *Checkpoint {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Deep copy
	cp := *m.checkpoint
	cp.CompletedTools = make([]string, len(m.checkpoint.CompletedTools))
	copy(cp.CompletedTools, m.checkpoint.CompletedTools)

	cp.ToolProgress = make(map[string]int64)
	for k, v := range m.checkpoint.ToolProgress {
		cp.ToolProgress[k] = v
	}

	cp.Metadata = make(map[string]string)
	for k, v := range m.checkpoint.Metadata {
		cp.Metadata[k] = v
	}

	return &cp
}

// IsToolCompleted verifica si una tool ya fue completada.
func (m *CheckpointManager) IsToolCompleted(tool string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, t := range m.checkpoint.CompletedTools {
		if t == tool {
			return true
		}
	}
	return false
}

// Remove elimina el checkpoint del disco.
func (m *CheckpointManager) Remove() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := os.Remove(m.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove checkpoint: %w", err)
	}
	return nil
}

// GetElapsedTime retorna el tiempo transcurrido desde el inicio.
func (m *CheckpointManager) GetElapsedTime() time.Duration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return time.Since(m.checkpoint.StartedAt)
}

// GetProgress retorna información de progreso formateada.
func (m *CheckpointManager) GetProgress() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	elapsed := time.Since(m.checkpoint.StartedAt)
	completed := len(m.checkpoint.CompletedTools)

	return fmt.Sprintf("elapsed: %s | completed: %d tools | artifacts: %d",
		elapsed.Round(time.Second),
		completed,
		m.checkpoint.ArtifactCount,
	)
}
