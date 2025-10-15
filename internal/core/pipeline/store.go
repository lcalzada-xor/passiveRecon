package pipeline

import (
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"passive-rec/internal/adapters/artifacts"
)

const (
	// defaultShardCount es el número de shards para distribuir la carga.
	// Debe ser potencia de 2 para optimizar el hashing.
	defaultShardCount = 16

	// flushInterval es el intervalo mínimo entre flushes automáticos.
	// Reduce I/O ops sin sacrificar durabilidad en caso de crash.
	flushInterval = 5 * time.Second

	// asyncRecordBufferSize es el tamaño del canal para async recording.
	// Debe ser >= workers * lineBufferPerWorker para evitar backpressure.
	asyncRecordBufferSize = 8192
)

type ArtifactStore interface {
	Record(tool string, artifact artifacts.Artifact)
	Flush() error
	Close() error
}

type artifactRecord struct {
	Artifact    artifacts.Artifact
	Tools       map[string]struct{}
	Occurrences int
}

func (rec *artifactRecord) addTool(tool string) {
	if rec == nil {
		return
	}
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return
	}
	if rec.Artifact.Tool == "" {
		rec.Artifact.Tool = tool
	}
	if rec.Tools == nil {
		rec.Tools = make(map[string]struct{})
	}
	rec.Tools[tool] = struct{}{}
}

type jsonlStore struct {
	mu        sync.Mutex
	path      string
	index     map[artifacts.Key]*artifactRecord
	order     []artifacts.Key
	dirty     bool
	target    string    // Target domain/IP para header v2
	lastFlush time.Time // Último flush exitoso para batch flush inteligente
}

func newJSONLStore(path string, target string) *jsonlStore {
	return &jsonlStore{
		path:   path,
		target: target,
		index:  make(map[artifacts.Key]*artifactRecord),
	}
}

func (s *jsonlStore) Record(tool string, artifact artifacts.Artifact) {
	if s == nil {
		return
	}
	normalized, ok := artifacts.Normalize(tool, artifact)
	if !ok {
		return
	}
	key := artifacts.KeyFor(normalized)
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, exists := s.index[key]
	if !exists {
		rec = &artifactRecord{Artifact: normalized, Tools: make(map[string]struct{})}
		s.index[key] = rec
		s.order = append(s.order, key)
	} else {
		artifacts.MergeMetadata(&rec.Artifact, normalized.Metadata)
		artifacts.MergeTypes(&rec.Artifact, normalized.Type, normalized.Types)
		rec.Artifact.Up = rec.Artifact.Up && normalized.Up

		// Preservar FirstSeen original, actualizar LastSeen
		if rec.Artifact.FirstSeen == "" {
			rec.Artifact.FirstSeen = normalized.FirstSeen
		}
		rec.Artifact.LastSeen = normalized.LastSeen

		// Actualizar versión si la nueva es diferente
		if normalized.Version != "" {
			rec.Artifact.Version = normalized.Version
		}
	}
	rec.addTool(normalized.Tool)
	rec.addTool(tool)
	rec.Occurrences++
	s.dirty = true
}

func (s *jsonlStore) Flush() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	if !s.dirty && len(s.order) == 0 {
		s.mu.Unlock()
		return nil
	}

	// Batch flush inteligente: solo flush si ha pasado suficiente tiempo o si es crítico
	if !s.lastFlush.IsZero() && time.Since(s.lastFlush) < flushInterval {
		// No ha pasado suficiente tiempo, skip flush (mejora performance)
		s.mu.Unlock()
		return nil
	}

	records := make([]artifacts.Artifact, 0, len(s.order))
	for _, key := range s.order {
		rec := s.index[key]
		if rec == nil {
			continue
		}
		art := rec.Artifact
		if rec.Tools != nil {
			tools := make([]string, 0, len(rec.Tools))
			for tool := range rec.Tools {
				if tool == "" {
					continue
				}
				tools = append(tools, tool)
			}
			sort.Strings(tools)
			if len(tools) > 0 {
				art.Tools = tools
				if art.Tool == "" {
					art.Tool = tools[0]
				}
			}
		}
		if rec.Occurrences <= 0 {
			art.Occurrences = 1
		} else {
			art.Occurrences = rec.Occurrences
		}
		records = append(records, art)
	}
	s.dirty = false
	path := s.path
	target := s.target
	s.mu.Unlock()

	// Escribir en formato v2.0 (único formato)
	if path == "" {
		return nil
	}
	writer := artifacts.NewWriterV2(path, target)
	err := writer.WriteArtifacts(records)

	if err == nil {
		// Solo actualizar lastFlush si la escritura fue exitosa
		s.mu.Lock()
		s.lastFlush = time.Now()
		s.mu.Unlock()
	}

	return err
}

// forceFlush realiza un flush inmediato ignorando el intervalo de tiempo.
// Se usa en Close() y cuando el caller necesita garantizar persistencia.
func (s *jsonlStore) forceFlush() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	// Resetear lastFlush para forzar el flush
	s.lastFlush = time.Time{}
	s.mu.Unlock()
	return s.Flush()
}

func (s *jsonlStore) Close() error {
	// Usar forceFlush para garantizar que todos los datos se escriben
	if err := s.forceFlush(); err != nil {
		return err
	}
	return nil
}

// ============================================================================
// Sharded ArtifactStore - Optimización 1.1 (CRITICAL)
// ============================================================================

// shardedStore distribuye artifacts across multiple jsonlStore instances
// para reducir contención de mutex y permitir procesamiento paralelo.
type shardedStore struct {
	shards []*jsonlStore
	count  uint32
}

func newShardedStore(path string, target string, shardCount int) *shardedStore {
	if shardCount <= 0 {
		shardCount = defaultShardCount
	}
	shards := make([]*jsonlStore, shardCount)
	for i := 0; i < shardCount; i++ {
		shards[i] = newJSONLStore(path, target)
	}
	return &shardedStore{
		shards: shards,
		count:  uint32(shardCount),
	}
}

// getShard selecciona el shard apropiado usando FNV hash.
func (s *shardedStore) getShard(key artifacts.Key) *jsonlStore {
	h := fnv.New32a()
	h.Write([]byte(key.Type))
	if key.Subtype != "" {
		h.Write([]byte(":"))
		h.Write([]byte(key.Subtype))
	}
	h.Write([]byte(key.Value))
	if key.Active {
		h.Write([]byte("active"))
	}
	return s.shards[h.Sum32()%s.count]
}

func (s *shardedStore) Record(tool string, artifact artifacts.Artifact) {
	if s == nil {
		return
	}
	// Normalizar primero para obtener la key
	normalized, ok := artifacts.Normalize(tool, artifact)
	if !ok {
		return
	}
	key := artifacts.KeyFor(normalized)

	// Delegar al shard apropiado
	shard := s.getShard(key)
	shard.Record(tool, artifact)
}

func (s *shardedStore) Flush() error {
	if s == nil {
		return nil
	}

	// Recolectar todos los artifacts de todos los shards
	allRecords := make([]artifacts.Artifact, 0)
	var mu sync.Mutex

	// Recolectar de cada shard en paralelo
	var wg sync.WaitGroup
	errors := make([]error, s.count)

	for i := uint32(0); i < s.count; i++ {
		wg.Add(1)
		go func(idx uint32) {
			defer wg.Done()
			shard := s.shards[idx]
			shard.mu.Lock()

			// Verificar si hay algo que escribir
			if !shard.dirty && len(shard.order) == 0 {
				shard.mu.Unlock()
				return
			}

			// Batch flush inteligente
			if !shard.lastFlush.IsZero() && time.Since(shard.lastFlush) < flushInterval {
				shard.mu.Unlock()
				return
			}

			// Recolectar records del shard
			records := make([]artifacts.Artifact, 0, len(shard.order))
			for _, key := range shard.order {
				rec := shard.index[key]
				if rec == nil {
					continue
				}
				art := rec.Artifact
				if rec.Tools != nil {
					tools := make([]string, 0, len(rec.Tools))
					for tool := range rec.Tools {
						if tool == "" {
							continue
						}
						tools = append(tools, tool)
					}
					sort.Strings(tools)
					if len(tools) > 0 {
						art.Tools = tools
						if art.Tool == "" {
							art.Tool = tools[0]
						}
					}
				}
				if rec.Occurrences <= 0 {
					art.Occurrences = 1
				} else {
					art.Occurrences = rec.Occurrences
				}
				records = append(records, art)
			}

			shard.dirty = false
			shard.mu.Unlock()

			// Agregar a la colección global
			mu.Lock()
			allRecords = append(allRecords, records...)
			mu.Unlock()
		}(i)
	}

	wg.Wait()

	// Verificar errores en la recolección
	for _, err := range errors {
		if err != nil {
			return err
		}
	}

	// Si no hay records, no hacer nada
	if len(allRecords) == 0 {
		return nil
	}

	// Escribir todos los records en un solo archivo
	// Tomar path y target del primer shard
	path := s.shards[0].path
	target := s.shards[0].target

	if path == "" {
		return nil
	}

	writer := artifacts.NewWriterV2(path, target)
	err := writer.WriteArtifacts(allRecords)

	if err == nil {
		// Actualizar lastFlush en todos los shards
		now := time.Now()
		for i := uint32(0); i < s.count; i++ {
			s.shards[i].mu.Lock()
			s.shards[i].lastFlush = now
			s.shards[i].mu.Unlock()
		}
	}

	return err
}

func (s *shardedStore) Close() error {
	if s == nil {
		return nil
	}

	// Resetear lastFlush en todos los shards para forzar flush
	for i := uint32(0); i < s.count; i++ {
		s.shards[i].mu.Lock()
		s.shards[i].lastFlush = time.Time{}
		s.shards[i].mu.Unlock()
	}

	// Hacer un flush final que consolidará todos los shards
	return s.Flush()
}

// ============================================================================
// Async ArtifactStore - Optimización 1.2 (HIGH)
// ============================================================================

type artifactMessage struct {
	tool     string
	artifact artifacts.Artifact
}

// asyncStore envuelve un ArtifactStore y procesa Records de forma asíncrona.
type asyncStore struct {
	inner     ArtifactStore
	queue     chan artifactMessage
	done      chan struct{}
	wg        sync.WaitGroup
	closed    bool
	mu        sync.Mutex
	queueSize int32 // Contador atómico de mensajes en cola
}

func newAsyncStore(inner ArtifactStore) *asyncStore {
	store := &asyncStore{
		inner: inner,
		queue: make(chan artifactMessage, asyncRecordBufferSize),
		done:  make(chan struct{}),
	}

	// Iniciar worker que procesa los records
	store.wg.Add(1)
	go store.worker()

	return store
}

func (s *asyncStore) worker() {
	defer s.wg.Done()

	for {
		select {
		case msg := <-s.queue:
			s.inner.Record(msg.tool, msg.artifact)
			atomic.AddInt32(&s.queueSize, -1)
		case <-s.done:
			// Procesar mensajes restantes antes de salir
			for {
				select {
				case msg := <-s.queue:
					s.inner.Record(msg.tool, msg.artifact)
					atomic.AddInt32(&s.queueSize, -1)
				default:
					return
				}
			}
		}
	}
}

func (s *asyncStore) Record(tool string, artifact artifacts.Artifact) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()

	// Incrementar contador antes de intentar enviar
	atomic.AddInt32(&s.queueSize, 1)

	// Non-blocking send con fallback a procesamiento síncrono
	select {
	case s.queue <- artifactMessage{tool: tool, artifact: artifact}:
		// Enqueued successfully
	default:
		// Queue llena, procesar síncronamente para evitar bloqueo
		atomic.AddInt32(&s.queueSize, -1) // Decrementar ya que no se encoló
		s.inner.Record(tool, artifact)
	}
}

func (s *asyncStore) Flush() error {
	// Esperar a que la cola se vacíe
	for atomic.LoadInt32(&s.queueSize) > 0 {
		time.Sleep(time.Millisecond)
	}

	// Hacer flush del store interno
	return s.inner.Flush()
}

func (s *asyncStore) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	// Señalar al worker que termine
	close(s.done)

	// Esperar a que el worker procese todo
	s.wg.Wait()

	// Hacer un flush del inner store para garantizar que todo se escribió
	if err := s.inner.Flush(); err != nil {
		return err
	}

	// Cerrar el store interno
	return s.inner.Close()
}

// NewOptimizedStore crea un ArtifactStore optimizado con sharding y async recording.
func NewOptimizedStore(path string, target string) ArtifactStore {
	sharded := newShardedStore(path, target, defaultShardCount)
	return newAsyncStore(sharded)
}
