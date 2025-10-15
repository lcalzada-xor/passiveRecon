package pipeline

import (
	"sync/atomic"
	"time"

	"passive-rec/internal/adapters/artifacts"
)

const (
	// maxShardMemory es el límite de memoria aproximado por shard antes de flush incremental (en bytes)
	// Con 16 shards, esto permite ~160MB en memoria antes de flush forzado
	maxShardMemory = 10 * 1024 * 1024 // 10MB por shard

	// avgArtifactSize es el tamaño promedio estimado de un artifact en memoria (bytes)
	// Usado para estimar cuándo hacer flush incremental
	avgArtifactSize = 500 // ~500 bytes por artifact (conservador)

	// incrementalFlushThreshold es el número de artifacts que dispara un flush incremental
	incrementalFlushThreshold = maxShardMemory / avgArtifactSize // ~20,000 artifacts
)

// optimizedJSONLStore extiende jsonlStore con flush incremental basado en memoria.
type optimizedJSONLStore struct {
	*jsonlStore
	artifactCount atomic.Int64 // Contador atómico de artifacts en memoria
}

// newOptimizedJSONLStore crea un store optimizado con flush incremental.
func newOptimizedJSONLStore(path string, target string) *optimizedJSONLStore {
	return &optimizedJSONLStore{
		jsonlStore: newJSONLStore(path, target),
	}
}

// Record sobrescribe el método base para agregar tracking de memoria.
func (s *optimizedJSONLStore) Record(tool string, artifact artifacts.Artifact) {
	if s == nil {
		return
	}

	// Llamar al método base
	s.jsonlStore.Record(tool, artifact)

	// Incrementar contador de artifacts
	count := s.artifactCount.Add(1)

	// Flush incremental si excedemos el threshold
	if count >= incrementalFlushThreshold {
		// Non-blocking flush attempt
		go func() {
			_ = s.tryIncrementalFlush()
		}()
	}
}

// tryIncrementalFlush intenta hacer un flush incremental si las condiciones son apropiadas.
func (s *optimizedJSONLStore) tryIncrementalFlush() error {
	if s == nil {
		return nil
	}

	s.mu.Lock()

	// Verificar si realmente necesitamos flush
	if !s.dirty || len(s.order) < incrementalFlushThreshold/2 {
		s.mu.Unlock()
		return nil
	}

	// Verificar intervalo de tiempo (evitar flush muy frecuente)
	if !s.lastFlush.IsZero() && time.Since(s.lastFlush) < flushInterval {
		s.mu.Unlock()
		return nil
	}

	s.mu.Unlock()

	// Hacer flush y resetear contador
	err := s.Flush()
	if err == nil {
		s.artifactCount.Store(0)
	}

	return err
}

// Close sobrescribe para asegurar flush final.
func (s *optimizedJSONLStore) Close() error {
	if err := s.jsonlStore.Close(); err != nil {
		return err
	}
	s.artifactCount.Store(0)
	return nil
}

// optimizedShardedStore extiende shardedStore con shards optimizados.
type optimizedShardedStore struct {
	shards []*optimizedJSONLStore
	count  uint32
}

// newOptimizedShardedStore crea un sharded store con flush incremental.
func newOptimizedShardedStore(path string, target string, shardCount int) *optimizedShardedStore {
	if shardCount <= 0 {
		shardCount = defaultShardCount
	}
	shards := make([]*optimizedJSONLStore, shardCount)
	for i := 0; i < shardCount; i++ {
		shards[i] = newOptimizedJSONLStore(path, target)
	}
	return &optimizedShardedStore{
		shards: shards,
		count:  uint32(shardCount),
	}
}

// getShard selecciona el shard apropiado usando FNV hash.
func (s *optimizedShardedStore) getShard(key artifacts.Key) *optimizedJSONLStore {
	// Reusar la lógica de hash del shardedStore
	store := &shardedStore{
		shards: make([]*jsonlStore, len(s.shards)),
		count:  s.count,
	}
	for i, shard := range s.shards {
		store.shards[i] = shard.jsonlStore
	}

	baseShard := store.getShard(key)

	// Encontrar el shard optimizado correspondiente
	for _, shard := range s.shards {
		if shard.jsonlStore == baseShard {
			return shard
		}
	}

	return s.shards[0] // Fallback (no debería ocurrir)
}

// Record delega al shard apropiado.
func (s *optimizedShardedStore) Record(tool string, artifact artifacts.Artifact) {
	if s == nil {
		return
	}

	// Normalizar primero para obtener la key
	normalized, ok := artifacts.Normalize(tool, artifact)
	if !ok {
		return
	}
	key := artifacts.KeyFor(normalized)

	// Delegar al shard apropiado (con flush incremental automático)
	shard := s.getShard(key)
	shard.Record(tool, artifact)
}

// Flush recolecta y escribe todos los artifacts.
func (s *optimizedShardedStore) Flush() error {
	if s == nil {
		return nil
	}

	// Convertir a shardedStore base para reusar lógica
	baseStore := &shardedStore{
		shards: make([]*jsonlStore, len(s.shards)),
		count:  s.count,
	}
	for i, shard := range s.shards {
		baseStore.shards[i] = shard.jsonlStore
	}

	err := baseStore.Flush()

	// Resetear contadores si flush exitoso
	if err == nil {
		for _, shard := range s.shards {
			shard.artifactCount.Store(0)
		}
	}

	return err
}

// Close fuerza flush final y cierra todos los shards.
func (s *optimizedShardedStore) Close() error {
	if s == nil {
		return nil
	}

	// Resetear lastFlush para forzar flush en todos los shards
	for i := uint32(0); i < s.count; i++ {
		s.shards[i].mu.Lock()
		s.shards[i].lastFlush = time.Time{}
		s.shards[i].mu.Unlock()
	}

	// Hacer flush final
	if err := s.Flush(); err != nil {
		return err
	}

	// Cerrar todos los shards
	for _, shard := range s.shards {
		if err := shard.Close(); err != nil {
			return err
		}
	}

	return nil
}

// NewOptimizedStoreV2 crea un ArtifactStore con flush incremental y async recording.
// Esta versión incluye:
// - Flush incremental basado en memoria (evita OOM en scans grandes)
// - Sharding para paralelismo
// - Async recording para alto throughput
func NewOptimizedStoreV2(path string, target string) ArtifactStore {
	sharded := newOptimizedShardedStore(path, target, defaultShardCount)
	return newAsyncStore(sharded)
}
