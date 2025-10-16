package logx

import (
	"sync"
)

// MessageDeduplicator gestiona la deduplicación de mensajes repetidos
type MessageDeduplicator struct {
	mu       sync.Mutex
	messages map[string]*MessageCount
}

// MessageCount almacena conteo de mensaje repetido
type MessageCount struct {
	Count      int
	FirstSeen  bool
	LastLogged bool
}

// NewMessageDeduplicator crea un nuevo deduplicador
func NewMessageDeduplicator() *MessageDeduplicator {
	return &MessageDeduplicator{
		messages: make(map[string]*MessageCount),
	}
}

// ShouldLog decide si un mensaje debe ser registrado o deduplicado
// Retorna (shouldLog, count) donde count es el número de repeticiones
func (d *MessageDeduplicator) ShouldLog(key string) (bool, int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	msg, exists := d.messages[key]
	if !exists {
		d.messages[key] = &MessageCount{Count: 1, FirstSeen: true, LastLogged: true}
		return true, 1
	}

	msg.Count++

	// Log cada 10 repeticiones para reducir spam
	shouldLog := msg.Count == 1 || msg.Count%10 == 0

	return shouldLog, msg.Count
}

// FormatDedupedMessage formatea un mensaje deduplicado
// Ejemplo: "message (repeated x12)"
func FormatDedupedMessage(message string, count int) string {
	if count <= 1 {
		return message
	}
	return message + Sprintf(" (repeated x%d)", count)
}

// Reset limpia el cache de deduplicación (para resetear entre fases)
func (d *MessageDeduplicator) Reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.messages = make(map[string]*MessageCount)
}

// GetStats retorna estadísticas de deduplicación
func (d *MessageDeduplicator) GetStats() map[string]int {
	d.mu.Lock()
	defer d.mu.Unlock()

	stats := make(map[string]int)
	for k, v := range d.messages {
		if v.Count > 1 {
			stats[k] = v.Count
		}
	}
	return stats
}
