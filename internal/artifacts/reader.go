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
	artifactsByType, err := CollectArtifactsByType(outdir, selectors)
	if err != nil {
		return nil, err
	}

	result := make(map[string][]string, len(selectors))
	for typ := range selectors {
		result[typ] = nil
	}

	for typ, artifacts := range artifactsByType {
		if len(artifacts) == 0 {
			continue
		}
		values := make([]string, 0, len(artifacts))
		for _, artifact := range artifacts {
			value := strings.TrimSpace(artifact.Value)
			if value == "" {
				continue
			}
			values = append(values, value)
		}
		if len(values) > 0 {
			result[typ] = values
		}
	}

	return result, nil
}

// CollectArtifactsByType lee artifacts.jsonl desde el directorio proporcionado y
// devuelve los artefactos agrupados por tipo aplicando el filtro de actividad
// indicado por selectors.
func CollectArtifactsByType(outdir string, selectors map[string]ActiveState) (map[string][]pipeline.Artifact, error) {
	path := filepath.Join(outdir, "artifacts.jsonl")
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	buf := bufio.NewScanner(file)
	buf.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	result := make(map[string][]pipeline.Artifact, len(selectors))
	for buf.Scan() {
		line := strings.TrimSpace(buf.Text())
		if line == "" {
			continue
		}

		var artifact pipeline.Artifact
		if err := json.Unmarshal([]byte(line), &artifact); err != nil {
			return nil, fmt.Errorf("unmarshal artifact: %w", err)
		}

		artifact.Value = strings.TrimSpace(artifact.Value)
		if artifact.Value == "" {
			continue
		}

		typeSet := make(map[string]struct{})
		orderedTypes := make([]string, 0, len(artifact.Types)+1)
		if primary := strings.TrimSpace(artifact.Type); primary != "" {
			if _, exists := typeSet[primary]; !exists {
				typeSet[primary] = struct{}{}
				orderedTypes = append(orderedTypes, primary)
			}
		}
		for _, typ := range artifact.Types {
			typ = strings.TrimSpace(typ)
			if typ == "" {
				continue
			}
			if _, exists := typeSet[typ]; exists {
				continue
			}
			typeSet[typ] = struct{}{}
			orderedTypes = append(orderedTypes, typ)
		}
		for _, typ := range orderedTypes {
			typ = strings.TrimSpace(typ)
			if typ == "" {
				continue
			}
			state, ok := selectors[typ]
			if !ok {
				continue
			}
			if !state.matches(artifact.Active) {
				continue
			}
			artifactCopy := artifact
			artifactCopy.Type = typ
			extras := make([]string, 0, len(orderedTypes))
			for _, candidate := range orderedTypes {
				candidate = strings.TrimSpace(candidate)
				if candidate == "" || candidate == typ {
					continue
				}
				extras = append(extras, candidate)
			}
			if len(extras) == 0 {
				artifactCopy.Types = nil
			} else {
				artifactCopy.Types = extras
			}
			result[typ] = append(result[typ], artifactCopy)
		}
	}
	if err := buf.Err(); err != nil {
		return nil, fmt.Errorf("scan artifacts: %w", err)
	}

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
