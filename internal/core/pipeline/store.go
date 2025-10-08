package pipeline

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"

	"passive-rec/internal/adapters/artifacts"
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
	mu    sync.Mutex
	path  string
	index map[artifacts.Key]*artifactRecord
	order []artifacts.Key
	dirty bool
}

func newJSONLStore(path string) *jsonlStore {
	return &jsonlStore{
		path:  path,
		index: make(map[artifacts.Key]*artifactRecord),
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
	s.mu.Unlock()
	if s.path == "" {
		return nil
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(f)
	for _, art := range records {
		encoded, err := json.Marshal(art)
		if err != nil {
			continue
		}
		if _, err := writer.Write(encoded); err != nil {
			continue
		}
		_ = writer.WriteByte('\n')
	}
	if err := writer.Flush(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (s *jsonlStore) Close() error {
	if err := s.Flush(); err != nil {
		return err
	}
	return nil
}
