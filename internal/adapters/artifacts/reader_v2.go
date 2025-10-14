package artifacts

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// ReaderV2 lee artifacts en formato v2.0.
type ReaderV2 struct {
	scanner  *bufio.Scanner
	baseTime time.Time
	header   *HeaderV2
}

// NewReaderV2 crea un nuevo reader para formato v2.0.
// Espera que la primera línea sea un header v2 válido.
func NewReaderV2(file *os.File) (*ReaderV2, error) {
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	// Leer header v2 (primera línea)
	if !scanner.Scan() {
		return nil, fmt.Errorf("archivo vacío o error al leer header")
	}

	line := strings.TrimSpace(scanner.Text())
	if line == "" {
		return nil, fmt.Errorf("header v2 vacío")
	}

	var header HeaderV2
	if err := json.Unmarshal([]byte(line), &header); err != nil {
		return nil, fmt.Errorf("header v2 inválido: %w", err)
	}

	if header.Schema != SchemaV2 {
		return nil, fmt.Errorf("schema inválido: esperado %s, encontrado %s", SchemaV2, header.Schema)
	}

	reader := &ReaderV2{
		scanner:  scanner,
		baseTime: time.Unix(header.Created, 0).UTC(),
		header:   &header,
	}

	return reader, nil
}

// GetHeader retorna el header v2.
func (r *ReaderV2) GetHeader() *HeaderV2 {
	return r.header
}

// ReadArtifact lee el siguiente artifact del archivo en formato v2.0.
// Convierte el artifact a la estructura interna Artifact.
func (r *ReaderV2) ReadArtifact() (Artifact, error) {
	if !r.scanner.Scan() {
		if err := r.scanner.Err(); err != nil {
			return Artifact{}, err
		}
		return Artifact{}, fmt.Errorf("EOF")
	}

	line := strings.TrimSpace(r.scanner.Text())
	if line == "" {
		return r.ReadArtifact() // Skip empty lines
	}

	// Parsear como v2 y convertir a formato interno
	var v2 ArtifactV2
	if err := json.Unmarshal([]byte(line), &v2); err != nil {
		return Artifact{}, fmt.Errorf("unmarshal v2 artifact: %w", err)
	}

	return ToV1(v2, r.baseTime), nil
}

// ReadAll lee todos los artifacts del archivo.
func (r *ReaderV2) ReadAll() ([]Artifact, error) {
	artifacts := []Artifact{}

	for {
		art, err := r.ReadArtifact()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}
		artifacts = append(artifacts, art)
	}

	return artifacts, nil
}
