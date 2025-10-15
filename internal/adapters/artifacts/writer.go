package artifacts

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"time"
)

// WriterV2 escribe artifacts en formato v2.0 (compacto).
type WriterV2 struct {
	path          string
	baseTime      time.Time
	headerWritten bool
	target        string
	tools         []string
}

// NewWriterV2 crea un nuevo writer para formato v2.
func NewWriterV2(path, target string) *WriterV2 {
	return &WriterV2{
		path:     path,
		baseTime: time.Now().UTC(),
		target:   target,
		tools:    []string{},
	}
}

// WriteHeader escribe el header v2 al inicio del archivo.
func (w *WriterV2) WriteHeader(file io.Writer) error {
	if w.headerWritten {
		return nil
	}

	header := NewHeaderV2(w.target, w.tools)
	header.Created = w.baseTime.Unix()

	data, err := json.Marshal(header)
	if err != nil {
		return err
	}

	writer := bufio.NewWriter(file)
	if _, err := writer.Write(data); err != nil {
		return err
	}
	if err := writer.WriteByte('\n'); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}

	w.headerWritten = true
	return nil
}

// WriteArtifact escribe un artifact individual en formato v2.
func (w *WriterV2) WriteArtifact(file io.Writer, artifact Artifact) error {
	v2 := ToV2(artifact, w.baseTime)

	data, err := json.Marshal(v2)
	if err != nil {
		return err
	}

	writer := bufio.NewWriter(file)
	if _, err := writer.Write(data); err != nil {
		return err
	}
	if err := writer.WriteByte('\n'); err != nil {
		return err
	}

	return writer.Flush()
}

// WriteArtifacts escribe múltiples artifacts en formato v2.
func (w *WriterV2) WriteArtifacts(artifacts []Artifact) error {
	if w.path == "" {
		return nil
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)

	// Escribir header
	if err := w.WriteHeader(writer); err != nil {
		return err
	}

	// Escribir artifacts
	for _, art := range artifacts {
		v2 := ToV2(art, w.baseTime)

		data, err := json.Marshal(v2)
		if err != nil {
			continue
		}

		if _, err := writer.Write(data); err != nil {
			continue
		}
		_ = writer.WriteByte('\n')
	}

	if err := writer.Flush(); err != nil {
		return err
	}

	return nil
}

// AddTool agrega una tool al catálogo del header.
func (w *WriterV2) AddTool(tool string) {
	for _, t := range w.tools {
		if t == tool {
			return
		}
	}
	w.tools = append(w.tools, tool)
}

// SetBaseTime establece el tiempo base para timestamps relativos.
func (w *WriterV2) SetBaseTime(t time.Time) {
	w.baseTime = t
}

// GetBaseTime retorna el tiempo base usado para timestamps relativos.
func (w *WriterV2) GetBaseTime() time.Time {
	return w.baseTime
}
