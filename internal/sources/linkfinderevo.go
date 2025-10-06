package sources

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"math/rand"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"passive-rec/internal/routes"
	"passive-rec/internal/runner"
)

var (
	linkfinderFindBin = runner.FindBin
	linkfinderRunCmd  = runner.RunCommandWithDir
)

const (
	linkfinderMaxInputEntries = 500
)

type linkfinderEndpoint struct {
	Link    string `json:"Link"`
	Context string `json:"Context"`
	Line    int    `json:"Line"`
}

type linkfinderReport struct {
	Resource  string               `json:"Resource"`
	Endpoints []linkfinderEndpoint `json:"Endpoints"`
}

type linkfinderMetadata struct {
	GeneratedAt    time.Time `json:"GeneratedAt"`
	TotalResources int       `json:"TotalResources"`
	TotalEndpoints int       `json:"TotalEndpoints"`
}

type linkfinderPayload struct {
	Meta      linkfinderMetadata `json:"meta"`
	Resources []linkfinderReport `json:"resources"`
}

type linkfinderAggregate struct {
	mu        sync.Mutex
	order     []string
	resources map[string]*linkfinderAggregateResource
}

type linkfinderAggregateResource struct {
	name      string
	order     []string
	endpoints map[string]linkfinderEndpoint
}

func newLinkfinderAggregate() *linkfinderAggregate {
	return &linkfinderAggregate{resources: make(map[string]*linkfinderAggregateResource)}
}

func (agg *linkfinderAggregate) add(resource string, endpoint linkfinderEndpoint) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return
	}
	endpoint.Link = cleanLinkfinderEndpointLink(endpoint.Link)
	if endpoint.Link == "" {
		return
	}

	agg.mu.Lock()
	defer agg.mu.Unlock()

	res, ok := agg.resources[resource]
	if !ok {
		res = &linkfinderAggregateResource{name: resource, endpoints: make(map[string]linkfinderEndpoint)}
		agg.resources[resource] = res
		agg.order = append(agg.order, resource)
	}

	if _, exists := res.endpoints[endpoint.Link]; exists {
		return
	}

	res.endpoints[endpoint.Link] = endpoint
	res.order = append(res.order, endpoint.Link)
}

func (agg *linkfinderAggregate) reports() []linkfinderReport {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	reports := make([]linkfinderReport, 0, len(agg.order))
	for _, name := range agg.order {
		res := agg.resources[name]
		if res == nil || len(res.order) == 0 {
			continue
		}
		report := linkfinderReport{Resource: name, Endpoints: make([]linkfinderEndpoint, 0, len(res.order))}
		for _, key := range res.order {
			if ep, ok := res.endpoints[key]; ok {
				report.Endpoints = append(report.Endpoints, ep)
			}
		}
		reports = append(reports, report)
	}
	return reports
}

func (agg *linkfinderAggregate) endpointCount() int {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	total := 0
	for _, res := range agg.resources {
		total += len(res.endpoints)
	}
	return total
}

// LinkFinderEVO executes the GoLinkfinderEVO binary across the active HTML, JS and crawl lists.
// It consolidates the resulting findings into the routes/linkFindings directory and streams normalized
// endpoints to the sink for further categorisation.
func LinkFinderEVO(ctx context.Context, target string, outdir string, out chan<- string) error {
	bin, ok := linkfinderFindBin("linkfinderevo", "GoLinkfinderEVO", "golinkfinder")
	if !ok {
		out <- "active: meta: linkfinderevo not found in PATH"
		return runner.ErrMissingBinary
	}

	findingsDir := filepath.Join(outdir, "routes", "linkFindings")
	if err := os.MkdirAll(findingsDir, 0o755); err != nil {
		return err
	}

	inputs := []struct {
		label string
		path  string
	}{
		{label: "html", path: filepath.Join("routes", "html", "html.active")},
		{label: "js", path: filepath.Join("routes", "js", "js.active")},
		{label: "crawl", path: filepath.Join("routes", "crawl", "crawl.active")},
	}

	aggregate := newLinkfinderAggregate()
	var firstErr error

	for _, input := range inputs {
		absPath := filepath.Join(outdir, input.path)
		absPath, err := filepath.Abs(absPath)
		if err != nil {
			recordLinkfinderError(&firstErr, err)
			continue
		}
		data, err := os.ReadFile(absPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				out <- fmt.Sprintf("active: meta: linkfinderevo skipped missing input %s", input.path)
				continue
			}
			recordLinkfinderError(&firstErr, err)
			continue
		}
		if len(bytes.TrimSpace(data)) == 0 {
			continue
		}

		tmpDir, err := os.MkdirTemp("", "passive-rec-linkfinderevo-*")
		if err != nil {
			recordLinkfinderError(&firstErr, err)
			break
		}

		samplePath, totalEntries, sampledEntries, err := maybeSampleLinkfinderInput(tmpDir, input.label, data)
		if err != nil {
			recordLinkfinderError(&firstErr, err)
			os.RemoveAll(tmpDir)
			break
		}
		if samplePath != "" {
			absPath = samplePath
			out <- fmt.Sprintf("active: meta: linkfinderevo sampling %d of %d entries from %s", sampledEntries, totalEntries, input.path)
		}

		rawPath := filepath.Join(tmpDir, "findings.raw")
		htmlPath := filepath.Join(tmpDir, "findings.html")
		jsonPath := filepath.Join(tmpDir, "findings.json")

		args := buildLinkfinderArgs(absPath, target, rawPath, htmlPath, jsonPath)

		intermediate := make(chan string)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range intermediate {
				// Drain CLI output to avoid blocking. Parsed results come from JSON output.
			}
		}()

		runErr := linkfinderRunCmd(ctx, tmpDir, bin, args, intermediate)
		close(intermediate)
		wg.Wait()

		if err := accumulateLinkfinderResults(jsonPath, aggregate); err != nil {
			recordLinkfinderError(&firstErr, err)
		}

		if runErr == nil {
			if err := persistLinkfinderArtifacts(findingsDir, input.label, rawPath, htmlPath, jsonPath); err != nil {
				recordLinkfinderError(&firstErr, err)
			}
			if err := persistLinkfinderGFArtifacts(findingsDir, input.label, tmpDir); err != nil {
				recordLinkfinderError(&firstErr, err)
			}
		}

		if runErr != nil {
			recordLinkfinderError(&firstErr, runErr)
			os.RemoveAll(tmpDir)
			break
		}

		os.RemoveAll(tmpDir)
	}

	if err := writeLinkfinderOutputs(outdir, aggregate, out); err != nil {
		recordLinkfinderError(&firstErr, err)
	}

	return firstErr
}

func recordLinkfinderError(first *error, candidate error) {
	if candidate == nil {
		return
	}
	if *first == nil {
		*first = candidate
	}
}

func writeLinkfinderOutputs(outdir string, aggregate *linkfinderAggregate, out chan<- string) error {
	findingsDir := filepath.Join(outdir, "routes", "linkFindings")
	if err := os.MkdirAll(findingsDir, 0o755); err != nil {
		return err
	}

	reports := aggregate.reports()
	if len(reports) == 0 {
		cleanupLinkfinderOutputs(findingsDir)
		return nil
	}

	meta := linkfinderMetadata{
		GeneratedAt:    time.Now().UTC(),
		TotalResources: len(reports),
		TotalEndpoints: aggregate.endpointCount(),
	}

	payload := linkfinderPayload{Meta: meta, Resources: reports}

	if err := writeLinkfinderJSON(filepath.Join(findingsDir, "findings.json"), payload); err != nil {
		return err
	}
	if err := writeLinkfinderRaw(filepath.Join(findingsDir, "findings.raw"), payload); err != nil {
		return err
	}
	if err := writeLinkfinderHTML(filepath.Join(findingsDir, "findings.html"), payload); err != nil {
		return err
	}

	emission, err := emitLinkfinderFindings(reports, out)
	if err != nil {
		return err
	}

	if err := writeLinkfinderUndetected(filepath.Join(findingsDir, "undetected.active"), emission.Undetected); err != nil {
		return err
	}

	if err := persistLinkfinderActiveOutputs(outdir, emission); err != nil {
		return err
	}

	return nil
}

func buildLinkfinderArgs(inputPath, target, rawPath, htmlPath, jsonPath string) []string {
	args := []string{"-i", inputPath, "-d", "-max-depth", "5", "--insecure"}
	scope := normalizeScope(target)
	if scope != "" {
		args = append(args, "-scope", scope, "--scope-include-subdomains")
	}
	output := fmt.Sprintf("cli,raw=%s,html=%s,json=%s", rawPath, htmlPath, jsonPath)
	args = append(args, "--output", output, "--gf", "all")
	return args
}

func maybeSampleLinkfinderInput(tmpDir, label string, data []byte) (string, int, int, error) {
	entries := parseLinkfinderEntries(data)
	total := len(entries)
	if total <= linkfinderMaxInputEntries {
		return "", total, total, nil
	}

	sampled := sampleLinkfinderEntries(entries, linkfinderMaxInputEntries)
	if len(sampled) == 0 {
		return "", total, 0, nil
	}

	var buf bytes.Buffer
	for _, entry := range sampled {
		buf.Write(entry)
		buf.WriteByte('\n')
	}

	sampleName := fmt.Sprintf("input.%s.sample", sanitizeLinkfinderLabel(label))
	samplePath := filepath.Join(tmpDir, sampleName)
	if err := os.WriteFile(samplePath, buf.Bytes(), 0o644); err != nil {
		return "", total, len(sampled), err
	}

	return samplePath, total, len(sampled), nil
}

func parseLinkfinderEntries(data []byte) [][]byte {
	lines := bytes.Split(data, []byte{'\n'})
	entries := make([][]byte, 0, len(lines))
	for _, line := range lines {
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) == 0 {
			continue
		}
		// Copy to avoid retaining references to the original slice backing array.
		entry := make([]byte, len(trimmed))
		copy(entry, trimmed)
		entries = append(entries, entry)
	}
	return entries
}

func sampleLinkfinderEntries(entries [][]byte, limit int) [][]byte {
	if limit <= 0 || len(entries) <= limit {
		return entries
	}

	idxs := rand.Perm(len(entries))[:limit]
	sort.Ints(idxs)

	sampled := make([][]byte, 0, limit)
	for _, idx := range idxs {
		sampled = append(sampled, entries[idx])
	}
	return sampled
}

func sanitizeLinkfinderLabel(label string) string {
	trimmed := strings.TrimSpace(label)
	if trimmed == "" {
		return "input"
	}
	sanitized := strings.Map(func(r rune) rune {
		switch r {
		case '/', '\\', ':':
			return '_'
		}
		return r
	}, trimmed)
	if sanitized == "" {
		return "input"
	}
	return sanitized
}

func normalizeScope(target string) string {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		if u, err := url.Parse(trimmed); err == nil {
			host := u.Hostname()
			if host != "" {
				return host
			}
		}
	}
	return trimmed
}

func accumulateLinkfinderResults(jsonPath string, aggregate *linkfinderAggregate) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}

	var payload linkfinderPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return err
	}

	for _, report := range payload.Resources {
		for _, ep := range report.Endpoints {
			aggregate.add(report.Resource, ep)
		}
	}

	return nil
}

func cleanupLinkfinderOutputs(findingsDir string) {
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

func persistLinkfinderArtifacts(findingsDir, label, rawPath, htmlPath, jsonPath string) error {
	outputs := []struct {
		src  string
		dest string
	}{
		{src: rawPath, dest: filepath.Join(findingsDir, fmt.Sprintf("findings.%s.raw", label))},
		{src: htmlPath, dest: filepath.Join(findingsDir, fmt.Sprintf("findings.%s.html", label))},
		{src: jsonPath, dest: filepath.Join(findingsDir, fmt.Sprintf("findings.%s.json", label))},
	}

	for _, output := range outputs {
		if err := copyLinkfinderArtifact(output.src, output.dest); err != nil {
			return err
		}
	}

	return nil
}

func persistLinkfinderGFArtifacts(findingsDir, label, srcDir string) error {
	outputs := []struct {
		name string
		dest string
	}{
		{name: "gf.txt", dest: filepath.Join(findingsDir, fmt.Sprintf("gf.%s.txt", label))},
		{name: "gf.json", dest: filepath.Join(findingsDir, fmt.Sprintf("gf.%s.json", label))},
	}

	for _, output := range outputs {
		src := filepath.Join(srcDir, output.name)
		if err := copyLinkfinderArtifact(src, output.dest); err != nil {
			return err
		}
	}

	return nil
}

func copyLinkfinderArtifact(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return nil
		}
		return err
	}

	if len(bytes.TrimSpace(data)) == 0 {
		if err := os.Remove(dest); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}

	return os.WriteFile(dest, data, 0o644)
}

func writeLinkfinderJSON(path string, payload linkfinderPayload) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func writeLinkfinderRaw(path string, payload linkfinderPayload) error {
	var buf bytes.Buffer

	buf.WriteString("# GoLinkfinderEVO raw results\n")
	buf.WriteString(fmt.Sprintf("# Generated at: %s\n", payload.Meta.GeneratedAt.Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("# Resources scanned: %d\n", payload.Meta.TotalResources))
	buf.WriteString(fmt.Sprintf("# Total endpoints: %d\n\n", payload.Meta.TotalEndpoints))

	for _, report := range payload.Resources {
		buf.WriteString("[Resource] ")
		buf.WriteString(report.Resource)
		buf.WriteByte('\n')

		if len(report.Endpoints) == 0 {
			buf.WriteString("#   No endpoints were found.\n\n")
			continue
		}

		for _, ep := range report.Endpoints {
			buf.WriteString(ep.Link)
			buf.WriteByte('\n')

			trimmed := strings.TrimSpace(ep.Context)
			if trimmed != "" {
				for _, line := range strings.Split(trimmed, "\n") {
					buf.WriteString("#   ")
					buf.WriteString(line)
					buf.WriteByte('\n')
				}
			}

			buf.WriteByte('\n')
		}
	}

	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func writeLinkfinderHTML(path string, payload linkfinderPayload) error {
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

	tpl := template.Must(template.New("linkfinderevo").Parse(linkfinderTemplate))

	var resources []resourceView
	for _, report := range payload.Resources {
		view := resourceView{Name: report.Resource}
		for idx, ep := range report.Endpoints {
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
		GeneratedAt:    payload.Meta.GeneratedAt.Format(time.RFC1123),
		TotalResources: payload.Meta.TotalResources,
		TotalEndpoints: payload.Meta.TotalEndpoints,
		Resources:      resources,
	}

	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return err
	}

	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func emitLinkfinderFindings(reports []linkfinderReport, out chan<- string) (linkfinderEmissionResult, error) {
	result := linkfinderEmissionResult{Categories: make(map[routes.Category][]string)}
	seenRoutes := make(map[string]struct{})
	seenJS := make(map[string]struct{})
	seenHTML := make(map[string]struct{})
	seenHTMLTargets := make(map[string]struct{})
	seenImages := make(map[string]struct{})
	seenCategories := make(map[routes.Category]map[string]struct{})
	undetectedSet := make(map[string]struct{})

	for _, report := range reports {
		for _, ep := range report.Endpoints {
			link := strings.TrimSpace(ep.Link)
			if link == "" {
				continue
			}
			if _, ok := seenRoutes[link]; !ok {
				out <- "active: " + link
				seenRoutes[link] = struct{}{}
				result.Routes = append(result.Routes, link)
			}

			classification := classifyLinkfinderEndpoint(link)
			if classification.isJS {
				if _, ok := seenJS[link]; !ok {
					out <- "active: js: " + link
					seenJS[link] = struct{}{}
					result.JS = append(result.JS, link)
				}
			}
			if classification.isHTML || classification.isImage {
				if _, ok := seenHTML[link]; !ok {
					out <- "active: html: " + link
					seenHTML[link] = struct{}{}
				}
				if classification.isHTML {
					if _, ok := seenHTMLTargets[link]; !ok {
						seenHTMLTargets[link] = struct{}{}
						result.HTML = append(result.HTML, link)
					}
				}
				if classification.isImage {
					if _, ok := seenImages[link]; !ok {
						seenImages[link] = struct{}{}
						result.Images = append(result.Images, link)
					}
				}
			}
			if len(classification.categories) > 0 {
				for _, cat := range classification.categories {
					prefix, ok := linkfinderCategoryPrefixes[cat]
					if !ok {
						continue
					}
					set := seenCategories[cat]
					if set == nil {
						set = make(map[string]struct{})
						seenCategories[cat] = set
					}
					if _, ok := set[link]; ok {
						continue
					}
					set[link] = struct{}{}
					out <- "active: " + prefix + ": " + link
					result.Categories[cat] = append(result.Categories[cat], link)
				}
			}
			if classification.undetected {
				undetectedSet[link] = struct{}{}
			}
		}
	}

	if len(undetectedSet) > 0 {
		undetected := make([]string, 0, len(undetectedSet))
		for value := range undetectedSet {
			undetected = append(undetected, value)
		}
		sort.Strings(undetected)
		result.Undetected = undetected
	}

	return result, nil
}

type linkfinderClassification struct {
	isJS       bool
	isHTML     bool
	isImage    bool
	undetected bool
	categories []routes.Category
}

func classifyLinkfinderEndpoint(link string) linkfinderClassification {
	lower := strings.ToLower(link)
	clean := lower
	if idx := strings.IndexAny(clean, "?#"); idx != -1 {
		clean = clean[:idx]
	}
	ext := strings.ToLower(filepath.Ext(clean))

	cls := linkfinderClassification{}

	switch ext {
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx":
		cls.isJS = true
	case ".html", ".htm", ".php", ".asp", ".aspx", ".jsp", ".jspx", ".cfm", ".shtml":
		cls.isHTML = true
	case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".svg", ".ico", ".tif", ".tiff", ".jfif", ".avif", ".apng", ".heic", ".heif":
		cls.isImage = true
	}

	cls.categories = routes.DetectCategories(link)

	if !hasCompleteURLPrefix(lower) {
		cls.undetected = true
	}

	return cls
}

type linkfinderEmissionResult struct {
	Routes     []string
	JS         []string
	HTML       []string
	Images     []string
	Categories map[routes.Category][]string
	Undetected []string
}

var linkfinderCategoryPrefixes = map[routes.Category]string{
	routes.CategoryMaps:  "maps",
	routes.CategoryJSON:  "json",
	routes.CategoryAPI:   "api",
	routes.CategoryWASM:  "wasm",
	routes.CategorySVG:   "svg",
	routes.CategoryCrawl: "crawl",
	routes.CategoryMeta:  "meta-route",
}

func hasCompleteURLPrefix(link string) bool {
	prefixes := []string{"http://", "https://", "file://", "ftp://", "ftps://", "//", "/", "./", "../"}
	for _, prefix := range prefixes {
		if strings.HasPrefix(link, prefix) {
			return true
		}
	}
	return false
}

func writeLinkfinderUndetected(path string, entries []string) error {
	if len(entries) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}

	var buf bytes.Buffer
	for _, entry := range entries {
		buf.WriteString(entry)
		buf.WriteByte('\n')
	}

	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func persistLinkfinderActiveOutputs(outdir string, emission linkfinderEmissionResult) error {
	type target struct {
		path    string
		entries []string
	}

	targets := []target{{
		path:    filepath.Join(outdir, "routes", "routes.active"),
		entries: emission.Routes,
	}, {
		path:    filepath.Join(outdir, "routes", "js", "js.active"),
		entries: emission.JS,
	}, {
		path:    filepath.Join(outdir, "routes", "html", "html.active"),
		entries: emission.HTML,
	}, {
		path:    filepath.Join(outdir, "routes", "images", "images.active"),
		entries: emission.Images,
	}}

	for cat, entries := range emission.Categories {
		path := linkfinderCategoryActivePath(outdir, cat)
		if path == "" {
			continue
		}
		targets = append(targets, target{path: path, entries: entries})
	}

	for _, t := range targets {
		if err := mergeAndWriteLinkfinderEntries(t.path, t.entries); err != nil {
			return err
		}
	}
	return nil
}

func linkfinderCategoryActivePath(outdir string, cat routes.Category) string {
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

func mergeAndWriteLinkfinderEntries(path string, newEntries []string) error {
	if len(newEntries) == 0 {
		return nil
	}

	entriesSet := make(map[string]struct{})
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			entry := strings.TrimSpace(scanner.Text())
			if entry == "" {
				continue
			}
			entriesSet[entry] = struct{}{}
		}
		if err := scanner.Err(); err != nil {
			return err
		}
	}

	initialLen := len(entriesSet)
	for _, entry := range newEntries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		entriesSet[trimmed] = struct{}{}
	}
	if len(entriesSet) == initialLen {
		return nil
	}

	merged := make([]string, 0, len(entriesSet))
	for entry := range entriesSet {
		merged = append(merged, entry)
	}
	sort.Strings(merged)

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	var buf bytes.Buffer
	for _, entry := range merged {
		buf.WriteString(entry)
		buf.WriteByte('\n')
	}

	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func cleanLinkfinderEndpointLink(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	trimmed = strings.Trim(trimmed, "\"'`")

	if idx := strings.IndexAny(trimmed, " \t\r\n\"'<>[]{}()"); idx != -1 {
		trimmed = trimmed[:idx]
	}

	trimmed = strings.TrimRight(trimmed, ",.;")

	return strings.TrimSpace(trimmed)
}

const linkfinderTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>GoLinkfinderEVO findings</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2rem; background: #0b0c10; color: #f0f3f6; }
        h1 { margin-bottom: 0.5rem; }
        .summary { margin-bottom: 2rem; }
        .resource { margin-bottom: 2rem; padding: 1.25rem; background: #1f2833; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
        .resource-title { display: flex; justify-content: space-between; align-items: baseline; }
        .resource-title a { color: #66fcf1; text-decoration: none; word-break: break-all; }
        .badge { background: #45a29e; padding: 0.25rem 0.75rem; border-radius: 999px; color: #0b0c10; font-weight: bold; }
        ul { list-style: none; padding-left: 0; margin: 1rem 0 0 0; }
        li { margin-bottom: 1rem; padding: 0.75rem; background: #0b0c10; border-radius: 6px; }
        .endpoint-header { display: flex; flex-wrap: wrap; gap: 0.75rem; align-items: baseline; }
        .endpoint-header a { color: #c5c6c7; text-decoration: none; word-break: break-all; }
        .endpoint-index { background: #45a29e; color: #0b0c10; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.85rem; font-weight: bold; }
        .endpoint-line { font-size: 0.85rem; color: #66fcf1; }
        pre { background: #0b0c10; color: #f0f3f6; padding: 0.75rem; border-radius: 4px; overflow-x: auto; margin: 0.5rem 0 0; }
    </style>
</head>
<body>
    <h1>GoLinkfinderEVO findings</h1>
    <div class="summary">
        <p>Generated at: {{.GeneratedAt}}</p>
        <p>Total resources: {{.TotalResources}}</p>
        <p>Total endpoints: {{.TotalEndpoints}}</p>
    </div>
    {{range .Resources}}
    <section class="resource">
        <div class="resource-title">
            <a href="{{.Name}}" target="_blank" rel="nofollow noopener noreferrer">{{.Name}}</a>
            <span class="badge">{{.Count}} endpoint{{if ne .Count 1}}s{{end}}</span>
        </div>
        {{if .Endpoints}}
        <ul>
            {{range .Endpoints}}
            <li>
                <div class="endpoint-header">
                    <span class="endpoint-index">#{{.Index}}</span>
                    <a href="{{.Link}}" target="_blank" rel="nofollow noopener noreferrer">{{.Link}}</a>
                    {{if gt .Line 0}}<span class="endpoint-line">Line {{.Line}}</span>{{end}}
                </div>
                {{if .Context}}
                <pre><code>{{.Context}}</code></pre>
                {{end}}
            </li>
            {{end}}
        </ul>
        {{else}}
        <p>No endpoints were found.</p>
        {{end}}
    </section>
    {{end}}
</body>
</html>
`
