package pipeline

import (
	"fmt"
	"testing"
)

func TestBloomFilterBasic(t *testing.T) {
	t.Parallel()

	bf := NewBloomFilter(1000, 0.01)

	// Test items not in set
	if bf.Contains("foo") {
		t.Fatal("empty bloom filter should not contain 'foo'")
	}
	if bf.Contains("bar") {
		t.Fatal("empty bloom filter should not contain 'bar'")
	}

	// Add items
	bf.Add("foo")
	bf.Add("bar")

	// Test items in set
	if !bf.Contains("foo") {
		t.Fatal("bloom filter should contain 'foo' after adding it")
	}
	if !bf.Contains("bar") {
		t.Fatal("bloom filter should contain 'bar' after adding it")
	}

	// Test item not in set
	if bf.Contains("baz") {
		// This could be a false positive, which is acceptable
		t.Logf("false positive for 'baz' (acceptable with bloom filters)")
	}
}

func TestBloomDedupeSeenAndMark(t *testing.T) {
	t.Parallel()

	bd := NewBloomDedupe()

	// First time seeing item
	if bd.SeenAndMark("example.com") {
		t.Fatal("SeenAndMark should return false for first occurrence")
	}

	// Second time seeing same item
	if !bd.SeenAndMark("example.com") {
		t.Fatal("SeenAndMark should return true for second occurrence")
	}

	// Different item
	if bd.SeenAndMark("different.com") {
		t.Fatal("SeenAndMark should return false for different item")
	}
}

func TestBloomDedupeSeparateSeenAndMark(t *testing.T) {
	t.Parallel()

	bd := NewBloomDedupe()

	// Check before marking
	if bd.Seen("test.com") {
		t.Fatal("Seen should return false before marking")
	}

	// Mark as seen
	bd.MarkSeen("test.com")

	// Check after marking
	if !bd.Seen("test.com") {
		t.Fatal("Seen should return true after marking")
	}
}

func TestBloomFilterFalsePositiveRate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping false positive rate test in short mode")
	}

	expectedItems := 10000
	targetFPR := 0.01
	bf := NewBloomFilter(expectedItems, targetFPR)

	// Add expected number of items
	for i := 0; i < expectedItems; i++ {
		bf.Add(fmt.Sprintf("item-%d", i))
	}

	// Test with items not added
	falsePositives := 0
	testSize := 10000
	for i := expectedItems; i < expectedItems+testSize; i++ {
		if bf.Contains(fmt.Sprintf("item-%d", i)) {
			falsePositives++
		}
	}

	actualFPR := float64(falsePositives) / float64(testSize)
	t.Logf("False positive rate: %.4f (target: %.4f)", actualFPR, targetFPR)

	// Allow some variance (2x target rate is still acceptable for a probabilistic structure)
	if actualFPR > targetFPR*2 {
		t.Errorf("false positive rate %.4f exceeds 2x target %.4f", actualFPR, targetFPR)
	}
}

func TestBloomFilterConcurrency(t *testing.T) {
	t.Parallel()

	bd := NewBloomDedupe()
	done := make(chan bool)

	// Multiple goroutines adding items
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				bd.MarkSeen(fmt.Sprintf("item-%d-%d", id, j))
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify some items were added
	if !bd.Seen("item-0-0") {
		t.Fatal("expected item to be present after concurrent adds")
	}
	if !bd.Seen("item-9-99") {
		t.Fatal("expected item to be present after concurrent adds")
	}
}

func BenchmarkBloomFilterAdd(b *testing.B) {
	bf := NewBloomFilter(1000000, 0.01)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Add(fmt.Sprintf("item-%d", i))
	}
}

func BenchmarkBloomFilterContains(b *testing.B) {
	bf := NewBloomFilter(1000000, 0.01)
	for i := 0; i < 100000; i++ {
		bf.Add(fmt.Sprintf("item-%d", i))
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.Contains(fmt.Sprintf("item-%d", i%100000))
	}
}

func BenchmarkBloomDedupeSeenAndMark(b *testing.B) {
	bd := NewBloomDedupe()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bd.SeenAndMark(fmt.Sprintf("item-%d", i))
	}
}

// Comparison benchmarks
func BenchmarkMapDedupe(b *testing.B) {
	m := make(map[string]struct{})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key := fmt.Sprintf("item-%d", i)
		if _, ok := m[key]; !ok {
			m[key] = struct{}{}
		}
	}
}
