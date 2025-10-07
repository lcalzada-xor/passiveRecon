package artifacts

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"passive-rec/internal/pipeline"
)

// ActiveState defines the activity filter applied when collecting artifacts.
type ActiveState int

const (
	// AnyState incluye artefactos tanto activos como pasivos.
	AnyState ActiveState = iota
	// ActiveOnly restringe a artefactos marcados como activos.
	ActiveOnly
	// PassiveOnly restringe a artefactos marcados como pasivos.
	PassiveOnly
)

func (s ActiveState) matches(active bool) bool {
	switch s {
	case ActiveOnly:
		return active
	case PassiveOnly:
		return !active
	default:
		return true
	}
}

// CollectValuesByType lee artifacts.jsonl desde el directorio proporcionado y
// devuelve los valores agrupados por tipo para los selectores solicitados. El
// mapa selectors debe utilizar el tipo de artefacto como clave y el estado de
// actividad deseado como valor. Si el archivo no existe se retorna el error de
// sistema correspondiente.
func CollectValuesByType(outdir string, selectors map[string]ActiveState) (map[string][]string, error) {
	path := filepath.Join(outdir, "artifacts.jsonl")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := bufio.NewScanner(file)
	buf.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	result := make(map[string][]string, len(selectors))
	for buf.Scan() {
		line := strings.TrimSpace(buf.Text())
		if line == "" {
			continue
		}

		var artifact pipeline.Artifact
		if err := json.Unmarshal([]byte(line), &artifact); err != nil {
			return nil, fmt.Errorf("unmarshal artifact: %w", err)
		}

		state, ok := selectors[artifact.Type]
		if !ok {
			continue
		}
		if !state.matches(artifact.Active) {
			continue
		}

		value := strings.TrimSpace(artifact.Value)
		if value == "" && artifact.Metadata != nil {
			if raw, ok := artifact.Metadata["raw"].(string); ok {
				value = strings.TrimSpace(raw)
			}
		}
		if value == "" {
			continue
		}

		result[artifact.Type] = append(result[artifact.Type], value)
	}
	if err := buf.Err(); err != nil {
		return nil, fmt.Errorf("scan artifacts: %w", err)
	}

	// Garantiza que los tipos solicitados estén presentes en el resultado
	// aunque no existan entradas correspondientes.
	for typ := range selectors {
		if _, ok := result[typ]; !ok {
			result[typ] = nil
		}
	}

	return result, nil
}

// CollectValues es un envoltorio de conveniencia para solicitar un único tipo
// de artefacto.
func CollectValues(outdir, typ string, state ActiveState) ([]string, error) {
	values, err := CollectValuesByType(outdir, map[string]ActiveState{typ: state})
	if err != nil {
		return nil, err
	}
	return values[typ], nil
}

// Exists devuelve true si artifacts.jsonl se encuentra en el directorio
// especificado.
func Exists(outdir string) (bool, error) {
	path := filepath.Join(outdir, "artifacts.jsonl")
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}
