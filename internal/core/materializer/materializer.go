package materializer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/platform/out"
)

type writeMode int

const (
	writeModeNone writeMode = iota
	writeModeDomain
	writeModeURL
	writeModeRaw
)

type fileSpec struct {
	subdir               string
	passiveName          string
	activeName           string
	passiveMode          writeMode
	activeMode           writeMode
	passiveUseRaw        bool
	activeUseRaw         bool
	passiveIncludeActive bool
}

var typeSpecs = map[string]fileSpec{
	"domain": {
		subdir:               "domains",
		passiveName:          "domains.passive",
		activeName:           "domains.active",
		passiveMode:          writeModeDomain,
		activeMode:           writeModeDomain,
		passiveUseRaw:        true,
		activeUseRaw:         true,
		passiveIncludeActive: true,
	},
	"route": {
		subdir:               "routes",
		passiveName:          "routes.passive",
		activeName:           "routes.active",
		passiveMode:          writeModeURL,
		activeMode:           writeModeURL,
		passiveUseRaw:        false,
		activeUseRaw:         true,
		passiveIncludeActive: true,
	},
	"js": {
		subdir:        filepath.Join("routes", "js"),
		passiveName:   "js.passive",
		activeName:    "js.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeRaw,
		passiveUseRaw: true,
		activeUseRaw:  true,
	},
	"html": {
		subdir:        filepath.Join("routes", "html"),
		passiveName:   "html.passive",
		activeName:    "html.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeRaw,
		passiveUseRaw: true,
		activeUseRaw:  true,
	},
	"image": {
		subdir:       filepath.Join("routes", "images"),
		activeName:   "images.active",
		activeMode:   writeModeRaw,
		activeUseRaw: true,
	},
	"maps": {
		subdir:        filepath.Join("routes", "maps"),
		passiveName:   "maps.passive",
		activeName:    "maps.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeURL,
		passiveUseRaw: false,
		activeUseRaw:  false,
	},
	"json": {
		subdir:        filepath.Join("routes", "json"),
		passiveName:   "json.passive",
		activeName:    "json.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeURL,
		passiveUseRaw: false,
		activeUseRaw:  false,
	},
	"api": {
		subdir:        filepath.Join("routes", "api"),
		passiveName:   "api.passive",
		activeName:    "api.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeURL,
		passiveUseRaw: false,
		activeUseRaw:  false,
	},
	"wasm": {
		subdir:        filepath.Join("routes", "wasm"),
		passiveName:   "wasm.passive",
		activeName:    "wasm.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeURL,
		passiveUseRaw: false,
		activeUseRaw:  false,
	},
	"svg": {
		subdir:        filepath.Join("routes", "svg"),
		passiveName:   "svg.passive",
		activeName:    "svg.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeURL,
		passiveUseRaw: false,
		activeUseRaw:  false,
	},
	"crawl": {
		subdir:        filepath.Join("routes", "crawl"),
		passiveName:   "crawl.passive",
		activeName:    "crawl.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeURL,
		passiveUseRaw: false,
		activeUseRaw:  false,
	},
	"meta-route": {
		subdir:        filepath.Join("routes", "meta"),
		passiveName:   "meta.passive",
		activeName:    "meta.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeURL,
		passiveUseRaw: false,
		activeUseRaw:  false,
	},
	"css": {
		subdir:        filepath.Join("routes", "css"),
		passiveName:   "css.passive",
		activeName:    "css.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeURL,
		passiveUseRaw: false,
		activeUseRaw:  false,
	},
	"font": {
		subdir:        filepath.Join("routes", "fonts"),
		passiveName:   "fonts.passive",
		activeName:    "fonts.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeURL,
		passiveUseRaw: false,
		activeUseRaw:  false,
	},
	"video": {
		subdir:        filepath.Join("routes", "video"),
		passiveName:   "video.passive",
		activeName:    "video.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeURL,
		passiveUseRaw: false,
		activeUseRaw:  false,
	},
	"doc": {
		subdir:        filepath.Join("routes", "docs"),
		passiveName:   "docs.passive",
		activeName:    "docs.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeURL,
		passiveUseRaw: false,
		activeUseRaw:  false,
	},
	"archive": {
		subdir:        filepath.Join("routes", "archives"),
		passiveName:   "archives.passive",
		activeName:    "archives.active",
		passiveMode:   writeModeURL,
		activeMode:    writeModeURL,
		passiveUseRaw: false,
		activeUseRaw:  false,
	},
	"certificate": {
		subdir:      "certs",
		passiveName: "certs.passive",
		activeName:  "certs.active",
		passiveMode: writeModeRaw,
		activeMode:  writeModeRaw,
	},
	"meta": {
		passiveName: "meta.passive",
		activeName:  "meta.active",
		passiveMode: writeModeRaw,
		activeMode:  writeModeRaw,
	},
	"rdap": {
		subdir:      "rdap",
		passiveName: "rdap.passive",
		passiveMode: writeModeRaw,
	},
}

// Materialize reconstruye los artefactos en ficheros .active/.passive a partir de
// artifacts.jsonl. Si el manifiesto no existe, se devuelve un error.
func Materialize(outdir string) error {
	if strings.TrimSpace(outdir) == "" {
		return errors.New("materializer: outdir vacío")
	}

	exists, err := artifacts.Exists(outdir)
	if err != nil {
		return err
	}
	if !exists {
		return errors.New("materializer: artifacts.jsonl no encontrado")
	}

	manifestPath := filepath.Join(outdir, "artifacts.jsonl")
	file, err := os.Open(manifestPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Usar ReaderV2 que soporta auto-detección de formato v1/v2
	reader, err := artifacts.NewReaderV2(file)
	if err != nil {
		return fmt.Errorf("crear reader: %w", err)
	}

	type writerPair struct {
		passive *fileWriter
		active  *fileWriter
	}

	writersByType := make(map[string]*writerPair, len(typeSpecs))
	var allWriters []*fileWriter
	defer func() {
		for _, w := range allWriters {
			_ = w.close()
		}
	}()

	getWriters := func(typ string, spec fileSpec) *writerPair {
		if pair, ok := writersByType[typ]; ok {
			return pair
		}
		pair := &writerPair{}
		if spec.passiveName != "" && spec.passiveMode != writeModeNone {
			pair.passive = newFileWriter(outdir, spec.subdir, spec.passiveName, spec.passiveMode)
			allWriters = append(allWriters, pair.passive)
		}
		if spec.activeName != "" && spec.activeMode != writeModeNone {
			pair.active = newFileWriter(outdir, spec.subdir, spec.activeName, spec.activeMode)
			allWriters = append(allWriters, pair.active)
		}
		writersByType[typ] = pair
		return pair
	}

	for {
		art, err := reader.ReadArtifact()
		if err != nil {
			// EOF es esperado al finalizar el archivo
			if err.Error() == "EOF" {
				break
			}
			return fmt.Errorf("leer artifact: %w", err)
		}

		art.Type = strings.TrimSpace(art.Type)
		art.Value = strings.TrimSpace(art.Value)
		if art.Type == "" || art.Value == "" {
			continue
		}

		for _, typ := range artifactTypes(art) {
			spec, ok := typeSpecs[typ]
			if !ok {
				continue
			}
			if typ == "route" && art.Type != "route" {
				continue
			}
			pair := getWriters(typ, spec)
			if pair.passive != nil && (!art.Active || spec.passiveIncludeActive) {
				if err := pair.passive.write(renderValue(art, spec.passiveUseRaw)); err != nil {
					return err
				}
			}
			if pair.active != nil && art.Active && art.Up {
				if err := pair.active.write(renderValue(art, spec.activeUseRaw)); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func artifactTypes(art artifacts.Artifact) []string {
	seen := make(map[string]struct{})
	var ordered []string
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, exists := seen[value]; exists {
			return
		}
		seen[value] = struct{}{}
		ordered = append(ordered, value)
	}

	add(art.Type)
	for _, extra := range art.Types {
		add(extra)
	}
	return ordered
}

type fileWriter struct {
	outdir string
	subdir string
	name   string
	mode   writeMode
	writer *out.Writer
}

func newFileWriter(outdir, subdir, name string, mode writeMode) *fileWriter {
	if name == "" || mode == writeModeNone {
		return nil
	}
	return &fileWriter{outdir: outdir, subdir: subdir, name: name, mode: mode}
}

func (w *fileWriter) ensure() error {
	if w == nil || w.writer != nil {
		return nil
	}
	targetDir := w.outdir
	if w.subdir != "" {
		targetDir = filepath.Join(targetDir, w.subdir)
	}
	writer, err := out.New(targetDir, w.name)
	if err != nil {
		return err
	}
	w.writer = writer
	return nil
}

func (w *fileWriter) write(value string) error {
	if w == nil || value == "" {
		return nil
	}
	if err := w.ensure(); err != nil {
		return err
	}
	switch w.mode {
	case writeModeDomain:
		return w.writer.WriteDomain(value)
	case writeModeURL:
		return w.writer.WriteURL(value)
	case writeModeRaw:
		return w.writer.WriteRaw(value)
	default:
		return nil
	}
}

func (w *fileWriter) close() error {
	if w == nil || w.writer == nil {
		return nil
	}
	err := w.writer.Close()
	w.writer = nil
	return err
}

func renderValue(art artifacts.Artifact, useRaw bool) string {
	if useRaw {
		if raw := extractRaw(art.Metadata); raw != "" {
			return raw
		}
	}
	return strings.TrimSpace(art.Value)
}

func extractRaw(metadata map[string]any) string {
	if metadata == nil {
		return ""
	}
	raw, ok := metadata["raw"]
	if !ok {
		return ""
	}
	switch v := raw.(type) {
	case string:
		return strings.TrimSpace(v)
	default:
		return ""
	}
}
