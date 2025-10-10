package linkfinderevo

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"passive-rec/internal/adapters/routes"
)

const (
	defaultFilePerm  = 0o644
	defaultDirPerm   = 0o755
	globalFindings   = "findings"
	gfPrefix         = "gf"
	undetectedActive = "undetected.active"
)

type emissionResult struct {
	Routes     []string
	JS         []string
	HTML       []string
	Images     []string
	Categories map[routes.Category][]string
	Undetected []string
}

func writeOutputs(outdir string, agg *aggregate, gfAgg *gfAggregate, out chan<- string) error {
	findingsDir := filepath.Join(outdir, "routes", "linkFindings")
	if err := os.MkdirAll(findingsDir, defaultDirPerm); err != nil {
		return fmt.Errorf("mkdir findings dir: %w", err)
	}

	reports := agg.reports()
	if len(reports) == 0 {
		cleanupOutputs(findingsDir)
		return nil
	}

	nowUTC := time.Now().UTC()
	meta := metadata{
		GeneratedAt:    nowUTC.Format(time.RFC3339),
		TotalResources: len(reports),
		TotalEndpoints: agg.endpointCount(),
	}

	p := payload{Meta: meta, Resources: reports}

	if err := writeJSON(filepath.Join(findingsDir, globalFindings+".json"), p); err != nil {
		return fmt.Errorf("write global json: %w", err)
	}
	if err := writeRaw(filepath.Join(findingsDir, globalFindings+".raw"), p); err != nil {
		return fmt.Errorf("write global raw: %w", err)
	}
	if err := writeHTML(filepath.Join(findingsDir, globalFindings+".html"), p); err != nil {
		return fmt.Errorf("write global html: %w", err)
	}

	emission, err := emitFindings(reports, out)
	if err != nil {
		return fmt.Errorf("emit findings: %w", err)
	}

	if err := writeUndetected(filepath.Join(findingsDir, undetectedActive), emission.Undetected); err != nil {
		return fmt.Errorf("write undetected: %w", err)
	}

	if err := persistActiveOutputs(outdir, emission); err != nil {
		return fmt.Errorf("persist active outputs: %w", err)
	}

	if err := emitGFFindings(gfAgg, out); err != nil {
		return fmt.Errorf("emit gf findings: %w", err)
	}

	return nil
}

func persistArtifacts(findingsDir, label, rawPath, htmlPath, jsonPath string) error {
	outputs := []struct {
		src  string
		dest string
	}{
		{src: rawPath, dest: filepath.Join(findingsDir, fmt.Sprintf("%s.%s.raw", globalFindings, label))},
		{src: htmlPath, dest: filepath.Join(findingsDir, fmt.Sprintf("%s.%s.html", globalFindings, label))},
		{src: jsonPath, dest: filepath.Join(findingsDir, fmt.Sprintf("%s.%s.json", globalFindings, label))},
	}
	for _, o := range outputs {
		if err := copyArtifact(o.src, o.dest); err != nil {
			return fmt.Errorf("copy %s -> %s: %w", o.src, o.dest, err)
		}
	}
	return nil
}

func persistGFArtifacts(findingsDir, label, srcDir string) error {
	outputs := []struct {
		name string
		dest string
	}{
		{name: "gf.txt", dest: filepath.Join(findingsDir, fmt.Sprintf("%s.%s.txt", gfPrefix, label))},
		{name: "gf.json", dest: filepath.Join(findingsDir, fmt.Sprintf("%s.%s.json", gfPrefix, label))},
	}
	for _, o := range outputs {
		src := filepath.Join(srcDir, o.name)
		if err := copyArtifact(src, o.dest); err != nil {
			return fmt.Errorf("copy gf %s -> %s: %w", src, o.dest, err)
		}
	}
	return nil
}

func copyArtifact(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove stale dest: %w", err)
			}
			return nil
		}
		return fmt.Errorf("read artifact: %w", err)
	}

	if len(bytes.TrimSpace(data)) == 0 {
		if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove empty dest: %w", err)
		}
		return nil
	}

	if err := os.WriteFile(dest, data, defaultFilePerm); err != nil {
		return fmt.Errorf("write dest: %w", err)
	}
	return nil
}

func writeJSON(path string, p payload) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	if err := os.WriteFile(path, data, defaultFilePerm); err != nil {
		return fmt.Errorf("write json: %w", err)
	}
	return nil
}

func writeRaw(path string, p payload) error {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)

	fmt.Fprintln(bw, "# GoLinkfinderEVO raw results")
	fmt.Fprintf(bw, "# Generated at: %s\n", p.Meta.GeneratedAt)
	fmt.Fprintf(bw, "# Resources scanned: %d\n", p.Meta.TotalResources)
	fmt.Fprintf(bw, "# Total endpoints: %d\n\n", p.Meta.TotalEndpoints)

	for _, r := range p.Resources {
		fmt.Fprintln(bw, "[Resource] "+r.Resource)

		if len(r.Endpoints) == 0 {
			fmt.Fprintln(bw, "#   No endpoints were found.")
			continue
		}
		for _, ep := range r.Endpoints {
			fmt.Fprintln(bw, ep.Link)

			if trimmed := strings.TrimSpace(ep.Context); trimmed != "" {
				for _, line := range strings.Split(trimmed, "\n") {
					fmt.Fprintln(bw, "#   "+line)
				}
			}
			bw.WriteByte('\n')
		}
	}
	_ = bw.Flush()

	if err := os.WriteFile(path, buf.Bytes(), defaultFilePerm); err != nil {
		return fmt.Errorf("write raw: %w", err)
	}
	return nil
}

func writeHTML(path string, p payload) error {
	type endpointView struct {
		Link    string
		Context template.HTML
		Line    int
		Index   int
	}
	type resourceView struct {
		Name      string
		Count     int
		Endpoints []endpointView
	}
	type pageData struct {
		GeneratedAt    string
		TotalResources int
		TotalEndpoints int
		Resources      []resourceView
	}

	highlight := func(ctx string) template.HTML {
		escaped := template.HTMLEscapeString(ctx)
		if escaped == "" {
			return ""
		}
		return template.HTML(escaped)
	}

	tpl := template.Must(template.New("linkfinderevo").Parse(htmlTemplate))

	var resources []resourceView
	for _, r := range p.Resources {
		view := resourceView{Name: r.Resource}
		for idx, ep := range r.Endpoints {
			view.Endpoints = append(view.Endpoints, endpointView{
				Link:    ep.Link,
				Context: highlight(ep.Context),
				Line:    ep.Line,
				Index:   idx + 1,
			})
		}
		view.Count = len(view.Endpoints)
		resources = append(resources, view)
	}

	data := pageData{
		GeneratedAt:    p.Meta.GeneratedAt,
		TotalResources: p.Meta.TotalResources,
		TotalEndpoints: p.Meta.TotalEndpoints,
		Resources:      resources,
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), defaultFilePerm); err != nil {
		return fmt.Errorf("write html: %w", err)
	}
	return nil
}

func writeUndetected(path string, entries []string) error {
	if len(entries) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove undetected: %w", err)
		}
		return nil
	}

	var buf bytes.Buffer
	for _, entry := range entries {
		buf.WriteString(entry)
		buf.WriteByte('\n')
	}

	if err := os.WriteFile(path, buf.Bytes(), defaultFilePerm); err != nil {
		return fmt.Errorf("write undetected: %w", err)
	}
	return nil
}

func persistActiveOutputs(outdir string, emission emissionResult) error {
	type target struct {
		path    string
		entries []string
	}

	targets := []target{
		{path: filepath.Join(outdir, "routes", "routes.active"), entries: emission.Routes},
		{path: filepath.Join(outdir, "routes", "js", "js.active"), entries: emission.JS},
		{path: filepath.Join(outdir, "routes", "html", "html.active"), entries: emission.HTML},
		{path: filepath.Join(outdir, "routes", "images", "images.active"), entries: emission.Images},
	}

	for cat, entries := range emission.Categories {
		if p := categoryActivePath(outdir, cat); p != "" {
			targets = append(targets, target{path: p, entries: entries})
		}
	}

	for _, t := range targets {
		if err := mergeAndWriteEntries(t.path, t.entries); err != nil {
			return fmt.Errorf("merge/write %s: %w", t.path, err)
		}
	}
	return nil
}

func categoryActivePath(outdir string, cat routes.Category) string {
	switch cat {
	case routes.CategoryMaps:
		return filepath.Join(outdir, "routes", "maps", "maps.active")
	case routes.CategoryJSON:
		return filepath.Join(outdir, "routes", "json", "json.active")
	case routes.CategoryAPI:
		return filepath.Join(outdir, "routes", "api", "api.active")
	case routes.CategoryWASM:
		return filepath.Join(outdir, "routes", "wasm", "wasm.active")
	case routes.CategorySVG:
		return filepath.Join(outdir, "routes", "svg", "svg.active")
	case routes.CategoryCrawl:
		return filepath.Join(outdir, "routes", "crawl", "crawl.active")
	case routes.CategoryMeta:
		return filepath.Join(outdir, "routes", "meta", "meta.active")
	default:
		return ""
	}
}

func mergeAndWriteEntries(path string, newEntries []string) error {
	if len(newEntries) == 0 {
		return nil
	}

	entriesSet := make(map[string]struct{})

	// Carga previos si existen.
	if data, err := os.ReadFile(path); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			entry := strings.TrimSpace(scanner.Text())
			if entry != "" {
				entriesSet[entry] = struct{}{}
			}
		}
		if scanErr := scanner.Err(); scanErr != nil {
			return fmt.Errorf("scan existing: %w", scanErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read existing: %w", err)
	}

	initialLen := len(entriesSet)
	for _, entry := range newEntries {
		if trimmed := strings.TrimSpace(entry); trimmed != "" {
			entriesSet[trimmed] = struct{}{}
		}
	}
	if len(entriesSet) == initialLen {
		return nil
	}

	merged := make([]string, 0, len(entriesSet))
	for entry := range entriesSet {
		merged = append(merged, entry)
	}
	sort.Strings(merged)

	if err := os.MkdirAll(filepath.Dir(path), defaultDirPerm); err != nil {
		return fmt.Errorf("mkdir target dir: %w", err)
	}

	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	for _, entry := range merged {
		fmt.Fprintln(bw, entry)
	}
	_ = bw.Flush()

	if err := os.WriteFile(path, buf.Bytes(), defaultFilePerm); err != nil {
		return fmt.Errorf("write merged: %w", err)
	}
	return nil
}

func cleanupOutputs(findingsDir string) {
	targets := []string{
		"findings.json",
		"findings.raw",
		"findings.html",
		"gf.html.txt",
		"gf.html.json",
		"gf.js.txt",
		"gf.js.json",
		"gf.crawl.txt",
		"gf.crawl.json",
		"undetected.active",
		"findings.active",
		"findings.html.raw",
		"findings.html.html",
		"findings.html.json",
		"findings.js.raw",
		"findings.js.html",
		"findings.js.json",
		"findings.crawl.raw",
		"findings.crawl.html",
		"findings.crawl.json",
	}
	for _, name := range targets {
		_ = os.Remove(filepath.Join(findingsDir, name))
	}
}
