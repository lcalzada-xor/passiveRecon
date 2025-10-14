package artifacts

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Datos de prueba realistas
func generateTestArtifacts(count int) []Artifact {
	artifacts := make([]Artifact, count)
	baseTime := time.Date(2025, 10, 13, 19, 29, 44, 0, time.UTC)

	for i := 0; i < count; i++ {
		artifacts[i] = Artifact{
			Type:      "route",
			Value:     "/api/v1/users/123",
			Active:    true,
			Up:        true,
			Tool:      "linkfinderevo",
			Tools:     []string{"linkfinderevo", "httpx"},
			Occurrences: 3,
			FirstSeen: baseTime.Format(time.RFC3339),
			LastSeen:  baseTime.Add(time.Second * 60).Format(time.RFC3339),
			Version:   "1.0",
			Metadata: map[string]any{
				"source": "crawl",
				"raw":    []string{"/api/v1/users/123 [200]", "/api/v1/users/123 [GET]"},
			},
		}

		// Añadir variedad
		if i%3 == 0 {
			artifacts[i].Type = "domain"
			artifacts[i].Value = "example.com"
			artifacts[i].Metadata = map[string]any{"source": "certificate"}
		} else if i%3 == 1 {
			artifacts[i].Type = "certificate"
			artifacts[i].Value = `{"source":"crt.sh","common_name":"example.com","dns_names":["example.com"],"issuer":"C=US, O=Google Trust Services, CN=WR3","not_before":"2025-09-14T16:05:09","not_after":"2025-12-13T16:54:40","serial_number":"18b68e9a192e38741260c04470b05367"}`
			artifacts[i].Metadata = map[string]any{
				"key":   "18b68e9a192e38741260c04470b05367|c=us, o=google trust services, cn=wr3",
				"names": []string{"example.com"},
			}
		}
	}

	return artifacts
}

// Benchmark: Escritura V1
func BenchmarkWriteV1(b *testing.B) {
	tmpDir := b.TempDir()
	artifacts := generateTestArtifacts(1000)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		path := filepath.Join(tmpDir, "bench_v1.jsonl")
		f, _ := os.Create(path)
		writer := bufio.NewWriter(f)

		for _, art := range artifacts {
			data, _ := json.Marshal(art)
			writer.Write(data)
			writer.WriteByte('\n')
		}

		writer.Flush()
		f.Close()
		os.Remove(path)
	}
}

// Benchmark: Escritura V2
func BenchmarkWriteV2(b *testing.B) {
	tmpDir := b.TempDir()
	artifacts := generateTestArtifacts(1000)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		path := filepath.Join(tmpDir, "bench_v2.jsonl")
		writer := NewWriterV2(path, "example.com")
		writer.WriteArtifacts(artifacts)
		os.Remove(path)
	}
}

// Benchmark: Lectura V1
func BenchmarkReadV1(b *testing.B) {
	tmpDir := b.TempDir()
	path := filepath.Join(tmpDir, "bench_v1.jsonl")

	// Crear archivo de prueba
	artifacts := generateTestArtifacts(1000)
	f, _ := os.Create(path)
	writer := bufio.NewWriter(f)
	for _, art := range artifacts {
		data, _ := json.Marshal(art)
		writer.Write(data)
		writer.WriteByte('\n')
	}
	writer.Flush()
	f.Close()

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		file, _ := os.Open(path)
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

		count := 0
		for scanner.Scan() {
			var art Artifact
			json.Unmarshal(scanner.Bytes(), &art)
			count++
		}

		file.Close()
	}
}

// Benchmark: Lectura V2
func BenchmarkReadV2(b *testing.B) {
	tmpDir := b.TempDir()
	path := filepath.Join(tmpDir, "bench_v2.jsonl")

	// Crear archivo de prueba
	artifacts := generateTestArtifacts(1000)
	writer := NewWriterV2(path, "example.com")
	writer.WriteArtifacts(artifacts)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		file, _ := os.Open(path)
		reader, _ := NewReaderV2(file)

		count := 0
		for {
			_, err := reader.ReadArtifact()
			if err != nil {
				break
			}
			count++
		}

		file.Close()
	}
}

// Benchmark: Conversión V1 -> V2
func BenchmarkToV2(b *testing.B) {
	baseTime := time.Now().UTC()
	artifact := Artifact{
		Type:        "route",
		Value:       "/api/v1/users/123",
		Active:      true,
		Up:          true,
		Tool:        "linkfinderevo",
		Occurrences: 3,
		FirstSeen:   baseTime.Format(time.RFC3339),
		LastSeen:    baseTime.Add(time.Second * 60).Format(time.RFC3339),
		Version:     "1.0",
		Metadata: map[string]any{
			"source": "crawl",
			"raw":    []string{"/api/v1/users/123 [200]"},
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ToV2(artifact, baseTime)
	}
}

// Benchmark: Conversión V2 -> V1
func BenchmarkToV1(b *testing.B) {
	baseTime := time.Now().UTC()
	v2artifact := ArtifactV2{
		T:  "route",
		V:  "/api/v1/users/123",
		St: StateActiveUp,
		Tl: "linkfinderevo",
		N:  3,
		Ts: []int64{0, 60000},
		M: map[string]any{
			"source": "crawl",
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_ = ToV1(v2artifact, baseTime)
	}
}

// Benchmark: Serialización JSON V1
func BenchmarkJSONMarshalV1(b *testing.B) {
	artifact := Artifact{
		Type:        "route",
		Value:       "/api/v1/users/123",
		Active:      true,
		Up:          true,
		Tool:        "linkfinderevo",
		Tools:       []string{"linkfinderevo", "httpx"},
		Occurrences: 3,
		FirstSeen:   "2025-10-13T19:29:44Z",
		LastSeen:    "2025-10-13T19:30:44Z",
		Version:     "1.0",
		Metadata: map[string]any{
			"source": "crawl",
			"raw":    []string{"/api/v1/users/123 [200]"},
		},
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(artifact)
	}
}

// Benchmark: Serialización JSON V2
func BenchmarkJSONMarshalV2(b *testing.B) {
	baseTime := time.Now().UTC()
	artifact := Artifact{
		Type:        "route",
		Value:       "/api/v1/users/123",
		Active:      true,
		Up:          true,
		Tool:        "linkfinderevo",
		Occurrences: 3,
		FirstSeen:   baseTime.Format(time.RFC3339),
		LastSeen:    baseTime.Add(time.Second * 60).Format(time.RFC3339),
		Metadata: map[string]any{
			"source": "crawl",
		},
	}

	v2artifact := ToV2(artifact, baseTime)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(v2artifact)
	}
}

// Test de comparación de tamaño de archivo
func TestFileSizeComparison(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping file size comparison in short mode")
	}

	tmpDir := t.TempDir()
	artifacts := generateTestArtifacts(1000)

	// Escribir V1
	v1Path := filepath.Join(tmpDir, "compare_v1.jsonl")
	v1File, _ := os.Create(v1Path)
	v1Writer := bufio.NewWriter(v1File)
	for _, art := range artifacts {
		data, _ := json.Marshal(art)
		v1Writer.Write(data)
		v1Writer.WriteByte('\n')
	}
	v1Writer.Flush()
	v1File.Close()

	// Escribir V2
	v2Path := filepath.Join(tmpDir, "compare_v2.jsonl")
	v2Writer := NewWriterV2(v2Path, "example.com")
	v2Writer.WriteArtifacts(artifacts)

	// Comparar tamaños
	v1Info, _ := os.Stat(v1Path)
	v2Info, _ := os.Stat(v2Path)

	v1Size := v1Info.Size()
	v2Size := v2Info.Size()

	reduction := float64(v1Size-v2Size) / float64(v1Size) * 100

	t.Logf("V1 file size: %d bytes", v1Size)
	t.Logf("V2 file size: %d bytes", v2Size)
	t.Logf("Size reduction: %.2f%%", reduction)

	if v2Size >= v1Size {
		t.Errorf("V2 should be smaller than V1, but V2=%d >= V1=%d", v2Size, v1Size)
	}

	// Esperar al menos 20% de reducción
	if reduction < 20.0 {
		t.Logf("Warning: Size reduction (%.2f%%) is less than expected (20%%)", reduction)
	}
}

// Test de comparación de velocidad
func TestSpeedComparison(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping speed comparison in short mode")
	}

	tmpDir := t.TempDir()
	artifacts := generateTestArtifacts(5000)

	// Medir V1
	v1Start := time.Now()
	v1Path := filepath.Join(tmpDir, "speed_v1.jsonl")
	v1File, _ := os.Create(v1Path)
	v1Writer := bufio.NewWriter(v1File)
	for _, art := range artifacts {
		data, _ := json.Marshal(art)
		v1Writer.Write(data)
		v1Writer.WriteByte('\n')
	}
	v1Writer.Flush()
	v1File.Close()
	v1Duration := time.Since(v1Start)

	// Medir V2
	v2Start := time.Now()
	v2Path := filepath.Join(tmpDir, "speed_v2.jsonl")
	v2Writer := NewWriterV2(v2Path, "example.com")
	v2Writer.WriteArtifacts(artifacts)
	v2Duration := time.Since(v2Start)

	t.Logf("V1 write time: %v", v1Duration)
	t.Logf("V2 write time: %v", v2Duration)
	t.Logf("V2 speedup: %.2fx", float64(v1Duration)/float64(v2Duration))
}
