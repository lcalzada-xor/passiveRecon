package pipeline

import (
	"hash/fnv"
	"math"
	"sync"
)

// BloomFilter is a space-efficient probabilistic data structure for testing
// set membership. It may return false positives (saying an item was seen when
// it wasn't) but never false negatives (if it says not seen, it truly wasn't).
// This makes it suitable for deduplication when some duplicates are acceptable
// but memory efficiency is critical.
type BloomFilter struct {
	bits      []uint64
	numHashes int
	size      uint64
	mu        sync.RWMutex
}

const (
	// bloomFilterFalsePositiveRate is the target false positive probability.
	// A rate of 0.01 means approximately 1% of lookups may incorrectly report
	// an item as already seen.
	bloomFilterFalsePositiveRate = 0.01

	// bloomFilterEstimatedItems is the expected number of unique items.
	// This can be tuned based on the size of your reconnaissance target.
	bloomFilterEstimatedItems = 1000000 // 1 million items
)

// NewBloomFilter creates a bloom filter optimized for the expected number of items
// and desired false positive rate.
func NewBloomFilter(expectedItems int, falsePositiveRate float64) *BloomFilter {
	if expectedItems <= 0 {
		expectedItems = bloomFilterEstimatedItems
	}
	if falsePositiveRate <= 0 || falsePositiveRate >= 1 {
		falsePositiveRate = bloomFilterFalsePositiveRate
	}

	// Calculate optimal bit array size: m = -(n * ln(p)) / (ln(2)^2)
	m := -float64(expectedItems) * math.Log(falsePositiveRate) / (math.Ln2 * math.Ln2)
	size := uint64(math.Ceil(m))

	// Calculate optimal number of hash functions: k = (m/n) * ln(2)
	k := int(math.Ceil((float64(size) / float64(expectedItems)) * math.Ln2))
	if k < 1 {
		k = 1
	}

	// Allocate bit array (packed into uint64 words)
	numWords := (size + 63) / 64
	return &BloomFilter{
		bits:      make([]uint64, numWords),
		numHashes: k,
		size:      size,
	}
}

// Add inserts an item into the bloom filter.
func (bf *BloomFilter) Add(item string) {
	if bf == nil {
		return
	}
	bf.mu.Lock()
	defer bf.mu.Unlock()

	h1, h2 := bf.hash(item)
	for i := 0; i < bf.numHashes; i++ {
		// Double hashing: h(i) = h1 + i*h2
		pos := (h1 + uint64(i)*h2) % bf.size
		wordIdx := pos / 64
		bitIdx := pos % 64
		bf.bits[wordIdx] |= 1 << bitIdx
	}
}

// Contains checks if an item might be in the set.
// Returns true if the item was probably added, false if definitely not added.
func (bf *BloomFilter) Contains(item string) bool {
	if bf == nil {
		return false
	}
	bf.mu.RLock()
	defer bf.mu.RUnlock()

	h1, h2 := bf.hash(item)
	for i := 0; i < bf.numHashes; i++ {
		pos := (h1 + uint64(i)*h2) % bf.size
		wordIdx := pos / 64
		bitIdx := pos % 64
		if bf.bits[wordIdx]&(1<<bitIdx) == 0 {
			return false
		}
	}
	return true
}

// hash computes two independent hash values using FNV-1a.
func (bf *BloomFilter) hash(item string) (uint64, uint64) {
	h := fnv.New64a()
	h.Write([]byte(item))
	h1 := h.Sum64()

	// Second hash from first hash (simple perturbation)
	h.Reset()
	h.Write([]byte(item + "\x00"))
	h2 := h.Sum64()

	return h1, h2
}

// BloomDedupe is a memory-efficient deduplication strategy using a bloom filter.
// It trades perfect accuracy for significant memory savings, making it suitable
// for very large reconnaissance scans where occasional duplicates are acceptable.
type BloomDedupe struct {
	filter *BloomFilter
}

// NewBloomDedupe creates a deduplicator backed by a bloom filter.
func NewBloomDedupe() *BloomDedupe {
	return &BloomDedupe{
		filter: NewBloomFilter(bloomFilterEstimatedItems, bloomFilterFalsePositiveRate),
	}
}

// NewBloomDedupeWithParams creates a bloom filter dedupe with custom parameters.
func NewBloomDedupeWithParams(expectedItems int, falsePositiveRate float64) *BloomDedupe {
	return &BloomDedupe{
		filter: NewBloomFilter(expectedItems, falsePositiveRate),
	}
}

// Seen checks if an item was probably seen before.
func (bd *BloomDedupe) Seen(key string) bool {
	if bd == nil || bd.filter == nil {
		return false
	}
	return bd.filter.Contains(key)
}

// MarkSeen marks an item as seen.
func (bd *BloomDedupe) MarkSeen(key string) {
	if bd == nil || bd.filter == nil {
		return
	}
	bd.filter.Add(key)
}

// SeenAndMark checks if an item was seen and marks it atomically.
// Returns true if the item was probably already seen.
func (bd *BloomDedupe) SeenAndMark(key string) bool {
	if bd == nil || bd.filter == nil {
		return false
	}
	wasSeen := bd.filter.Contains(key)
	if !wasSeen {
		bd.filter.Add(key)
	}
	return wasSeen
}
