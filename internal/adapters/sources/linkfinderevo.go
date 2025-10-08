// Package sources coordina la ejecución de GoLinkfinderEVO sobre artefactos activos,
// agrega hallazgos, los persiste (raw/HTML/JSON), los clasifica por tipo/categoría
// y reinyecta rutas al pipeline mediante listas *.active y emisiones por canal.
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

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/adapters/routes"
	"passive-rec/internal/core/runner"
)

var (
	// Permite inyección en tests.
	linkfinderFindBin = runner.FindBin
	linkfinderRunCmd  = runner.RunCommandWithDir
)

const (
	linkfinderMaxInputEntries  = 200
	linkfinderEntriesPerSecond = 15

	defaultFilePerm  = 0o644
	defaultDirPerm   = 0o755
	tmpPrefix        = "passive-rec-linkfinderevo-*"
	findingsDirName  = "linkFindings"
	globalFindings   = "findings"
	gfPrefix         = "gf"
	undetectedActive = "undetected.active"
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

type linkfinderGFAggregate struct {
	mu       sync.Mutex
	findings map[linkfinderGFFindingKey]*linkfinderGFFinding
}

type linkfinderGFFindingKey struct {
	Resource string
	Line     int
	Evidence string
}

type linkfinderGFFinding struct {
	Resource string
	Line     int
	Evidence string
	Context  string
	Rules    map[string]struct{}
}

type linkfinderGFFindingResult struct {
	Resource string
	Line     int
	Evidence string
	Context  string
	Rules    []string
}

type linkfinderAggregateResource struct {
	name      string
	order     []string
	endpoints map[string]linkfinderEndpoint
}

func newLinkfinderAggregate() *linkfinderAggregate {
	return &linkfinderAggregate{resources: make(map[string]*linkfinderAggregateResource)}
}

func newLinkfinderGFAggregate() *linkfinderGFAggregate {
	return &linkfinderGFAggregate{findings: make(map[linkfinderGFFindingKey]*linkfinderGFFinding)}
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
		res = &linkfinderAggregateResource{
			name:      resource,
			endpoints: make(map[string]linkfinderEndpoint),
		}
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

func (agg *linkfinderGFAggregate) add(resource string, line int, evidence string, context string, rules []string) {
	if agg == nil {
		return
	}
	resource = strings.TrimSpace(resource)
	evidence = strings.TrimSpace(evidence)
	if evidence == "" {
		return
	}

	key := linkfinderGFFindingKey{Resource: resource, Line: line, Evidence: evidence}

	agg.mu.Lock()
	defer agg.mu.Unlock()

	entry, ok := agg.findings[key]
	if !ok {
		entry = &linkfinderGFFinding{
			Resource: resource,
			Line:     line,
			Evidence: evidence,
			Context:  strings.TrimSpace(context),
			Rules:    make(map[string]struct{}),
		}
		agg.findings[key] = entry
	} else if entry.Context == "" {
		entry.Context = strings.TrimSpace(context)
	}

	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		if entry.Rules == nil {
			entry.Rules = make(map[string]struct{})
		}
		entry.Rules[rule] = struct{}{}
	}
}

func (agg *linkfinderGFAggregate) results() []linkfinderGFFindingResult {
	if agg == nil {
		return nil
	}

	agg.mu.Lock()
	defer agg.mu.Unlock()

	if len(agg.findings) == 0 {
		return nil
	}

	keys := make([]linkfinderGFFindingKey, 0, len(agg.findings))
	for key := range agg.findings {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Resource != keys[j].Resource {
			return keys[i].Resource < keys[j].Resource
		}
		if keys[i].Line != keys[j].Line {
			return keys[i].Line < keys[j].Line
		}
		return keys[i].Evidence < keys[j].Evidence
	})

	results := make([]linkfinderGFFindingResult, 0, len(keys))
	for _, key := range keys {
		entry := agg.findings[key]
		if entry == nil {
			continue
		}
		rules := make([]string, 0, len(entry.Rules))
		for rule := range entry.Rules {
			if rule == "" {
				continue
			}
			rules = append(rules, rule)
		}
		sort.Strings(rules)
		results = append(results, linkfinderGFFindingResult{
			Resource: entry.Resource,
			Line:     entry.Line,
			Evidence: entry.Evidence,
			Context:  entry.Context,
			Rules:    rules,
		})
	}

	return results
}

// LinkFinderEVO ejecuta el binario GoLinkfinderEVO sobre HTML/JS/crawl activos,
// agrega resultados, persiste artefactos y emite rutas clasificadas al sink.
func LinkFinderEVO(ctx context.Context, target string, outdir string, out chan<- string) error {
	bin, ok := linkfinderFindBin("linkfinderevo", "GoLinkfinderEVO", "golinkfinder")
	if !ok {
		emit(out, "active: meta: linkfinderevo not found in PATH")
		return runner.ErrMissingBinary
	}

	findingsDir := filepath.Join(outdir, "routes", findingsDirName)
	if err := os.MkdirAll(findingsDir, defaultDirPerm); err != nil {
		return fmt.Errorf("mkdir findings dir: %w", err)
	}

	selectors := map[string]artifacts.ActiveState{
		"html":  artifacts.ActiveOnly,
		"js":    artifacts.ActiveOnly,
		"crawl": artifacts.ActiveOnly,
	}
	valuesByType, err := artifacts.CollectValuesByType(outdir, selectors)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			emit(out, "active: meta: linkfinderevo skipped (missing artifacts.jsonl)")
			return nil
		}
		return fmt.Errorf("collect artifacts: %w", err)
	}

	inputs := []struct {
		label  string
		values []string
	}{
		{label: "html", values: valuesByType["html"]},
		{label: "js", values: valuesByType["js"]},
		{label: "crawl", values: valuesByType["crawl"]},
	}

	aggregate := newLinkfinderAggregate()
	gfAggregate := newLinkfinderGFAggregate()
	var firstErr error

	totalBudget := linkfinderEntryBudget(ctx, len(inputs)*linkfinderMaxInputEntries)
	if totalBudget <= 0 {
		emit(out, "active: meta: linkfinderevo skipped (insufficient time budget)")
		return nil
	}

	// Semilla separada por ejecución para muestreos.
	rand.Seed(time.Now().UnixNano())

	for _, input := range inputs {
		// Cancelación temprana por contexto.
		if ctx.Err() != nil {
			recordLinkfinderError(&firstErr, ctx.Err())
			break
		}

		data := encodeLinkfinderEntries(input.values)
		if len(bytes.TrimSpace(data)) == 0 {
			continue
		}

		if totalBudget <= 0 {
			emit(out, fmt.Sprintf("active: meta: linkfinderevo skipped %s (time budget exhausted)", input.label))
			break
		}

		tmpDir, err := os.MkdirTemp("", tmpPrefix)
		if err != nil {
			recordLinkfinderError(&firstErr, fmt.Errorf("mktemp: %w", err))
			break
		}

		limit := linkfinderMaxInputEntries
		if totalBudget < limit {
			limit = totalBudget
		}

		inputPath, err := writeLinkfinderInput(tmpDir, input.label, data)
		if err != nil {
			recordLinkfinderError(&firstErr, fmt.Errorf("write input: %w", err))
			_ = os.RemoveAll(tmpDir)
			continue
		}

		absPath := inputPath

		samplePath, totalEntries, sampledEntries, err := maybeSampleLinkfinderInput(tmpDir, input.label, data, limit)
		if err != nil {
			recordLinkfinderError(&firstErr, fmt.Errorf("sampling: %w", err))
			_ = os.RemoveAll(tmpDir)
			break
		}
		if samplePath != "" {
			absPath = samplePath
			emit(out, fmt.Sprintf("active: meta: linkfinderevo sampling %d of %d entries from %s", sampledEntries, totalEntries, input.label))
		}
		if sampledEntries == 0 {
			emit(out, fmt.Sprintf("active: meta: linkfinderevo skipped %s (no entries within time budget)", input.label))
			_ = os.RemoveAll(tmpDir)
			continue
		}

		totalBudget -= sampledEntries
		if totalBudget < 0 {
			totalBudget = 0
		}

		rawPath := filepath.Join(tmpDir, "findings.raw")
		htmlPath := filepath.Join(tmpDir, "findings.html")
		jsonPath := filepath.Join(tmpDir, "findings.json")

		args := buildLinkfinderArgs(absPath, target, rawPath, htmlPath, jsonPath)

		// Drenaje de salida CLI para evitar bloqueo.
		intermediate := make(chan string)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range intermediate {
			}
		}()

		runErr := linkfinderRunCmd(ctx, tmpDir, bin, args, intermediate)
		close(intermediate)
		wg.Wait()

		if err := accumulateLinkfinderResults(jsonPath, aggregate); err != nil {
			recordLinkfinderError(&firstErr, fmt.Errorf("accumulate results: %w", err))
		}
		if err := accumulateLinkfinderGFFindings(filepath.Join(tmpDir, "gf.json"), gfAggregate); err != nil {
			recordLinkfinderError(&firstErr, fmt.Errorf("accumulate gf: %w", err))
		}

		shouldPersist := runErr == nil || errors.Is(runErr, context.Canceled) || errors.Is(runErr, context.DeadlineExceeded)
		if shouldPersist {
			if err := persistLinkfinderArtifacts(findingsDir, input.label, rawPath, htmlPath, jsonPath); err != nil {
				recordLinkfinderError(&firstErr, fmt.Errorf("persist artifacts: %w", err))
			}
			if err := persistLinkfinderGFArtifacts(findingsDir, input.label, tmpDir); err != nil {
				recordLinkfinderError(&firstErr, fmt.Errorf("persist gf: %w", err))
			}
		}

		if runErr != nil {
			recordLinkfinderError(&firstErr, runErr)
		}

		_ = os.RemoveAll(tmpDir)

		if runErr != nil {
			break
		}
		if totalBudget == 0 {
			emit(out, "active: meta: linkfinderevo stopped (time budget consumed)")
			break
		}
	}

	if err := writeLinkfinderOutputs(outdir, aggregate, gfAggregate, out); err != nil {
		recordLinkfinderError(&firstErr, fmt.Errorf("write outputs: %w", err))
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

func writeLinkfinderOutputs(outdir string, aggregate *linkfinderAggregate, gfAggregate *linkfinderGFAggregate, out chan<- string) error {
	findingsDir := filepath.Join(outdir, "routes", findingsDirName)
	if err := os.MkdirAll(findingsDir, defaultDirPerm); err != nil {
		return fmt.Errorf("mkdir findings dir: %w", err)
	}

	reports := aggregate.reports()
	if len(reports) == 0 {
		cleanupLinkfinderOutputs(findingsDir)
		return nil
	}

	nowUTC := time.Now().UTC()
	meta := linkfinderMetadata{
		GeneratedAt:    nowUTC,
		TotalResources: len(reports),
		TotalEndpoints: aggregate.endpointCount(),
	}

	payload := linkfinderPayload{Meta: meta, Resources: reports}

	if err := writeLinkfinderJSON(filepath.Join(findingsDir, globalFindings+".json"), payload); err != nil {
		return fmt.Errorf("write global json: %w", err)
	}
	if err := writeLinkfinderRaw(filepath.Join(findingsDir, globalFindings+".raw"), payload); err != nil {
		return fmt.Errorf("write global raw: %w", err)
	}
	if err := writeLinkfinderHTML(filepath.Join(findingsDir, globalFindings+".html"), payload); err != nil {
		return fmt.Errorf("write global html: %w", err)
	}

	emission, err := emitLinkfinderFindings(reports, out)
	if err != nil {
		return fmt.Errorf("emit findings: %w", err)
	}

	if err := writeLinkfinderUndetected(filepath.Join(findingsDir, undetectedActive), emission.Undetected); err != nil {
		return fmt.Errorf("write undetected: %w", err)
	}

	if err := persistLinkfinderActiveOutputs(outdir, emission); err != nil {
		return fmt.Errorf("persist active outputs: %w", err)
	}

	if err := emitLinkfinderGFFindings(gfAggregate, out); err != nil {
		return fmt.Errorf("emit gf findings: %w", err)
	}

	return nil
}

func buildLinkfinderArgs(inputPath, target, rawPath, htmlPath, jsonPath string) []string {
	args := []string{"-i", inputPath, "-d", "-max-depth", "2", "--insecure"}
	if scope := normalizeScope(target); scope != "" {
		args = append(args, "-scope", scope, "--scope-include-subdomains")
	}
	output := fmt.Sprintf("cli,raw=%s,html=%s,json=%s", rawPath, htmlPath, jsonPath)
	args = append(args, "--output", output, "--gf", "all")
	return args
}

func linkfinderEntryBudget(ctx context.Context, maxTotal int) int {
	if maxTotal <= 0 {
		return 0
	}
	deadline, hasDeadline := ctx.Deadline()
	if !hasDeadline {
		return maxTotal
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}
	budget := int(remaining.Seconds() * linkfinderEntriesPerSecond)
	if budget > maxTotal {
		budget = maxTotal
	}
	if budget < 0 {
		return 0
	}
	return budget
}

func encodeLinkfinderEntries(entries []string) []byte {
	var buf bytes.Buffer
	for _, entry := range entries {
		trimmed := strings.TrimSpace(entry)
		if trimmed == "" {
			continue
		}
		buf.WriteString(trimmed)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func writeLinkfinderInput(tmpDir, label string, data []byte) (string, error) {
	sanitized := sanitizeLinkfinderLabel(label)
	name := fmt.Sprintf("input.%s", sanitized)
	path := filepath.Join(tmpDir, name)
	if err := os.WriteFile(path, data, defaultFilePerm); err != nil {
		return "", fmt.Errorf("write input file: %w", err)
	}
	return path, nil
}

func maybeSampleLinkfinderInput(tmpDir, label string, data []byte, limit int) (string, int, int, error) {
	entries := parseLinkfinderEntries(data)
	total := len(entries)
	if limit <= 0 {
		return "", total, 0, nil
	}
	if total <= limit {
		return "", total, total, nil
	}

	sampled := sampleLinkfinderEntries(entries, limit)
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
	if err := os.WriteFile(samplePath, buf.Bytes(), defaultFilePerm); err != nil {
		return "", total, len(sampled), fmt.Errorf("write sampled input: %w", err)
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
		default:
			return r
		}
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
			if host := u.Hostname(); host != "" {
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
		return fmt.Errorf("read results json: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}

	var payload linkfinderPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("unmarshal results: %w", err)
	}

	for _, report := range payload.Resources {
		for _, ep := range report.Endpoints {
			aggregate.add(report.Resource, ep)
		}
	}
	return nil
}

func accumulateLinkfinderGFFindings(jsonPath string, aggregate *linkfinderGFAggregate) error {
	if aggregate == nil {
		return nil
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read gf json: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}

	type gfReport struct {
		Findings []struct {
			Resource string   `json:"resource"`
			Line     int      `json:"line"`
			Evidence string   `json:"evidence"`
			Context  string   `json:"context"`
			Rules    []string `json:"rules"`
		} `json:"findings"`
	}

	var report gfReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("unmarshal gf: %w", err)
	}

	for _, f := range report.Findings {
		aggregate.add(f.Resource, f.Line, f.Evidence, f.Context, f.Rules)
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
		{src: rawPath, dest: filepath.Join(findingsDir, fmt.Sprintf("%s.%s.raw", globalFindings, label))},
		{src: htmlPath, dest: filepath.Join(findingsDir, fmt.Sprintf("%s.%s.html", globalFindings, label))},
		{src: jsonPath, dest: filepath.Join(findingsDir, fmt.Sprintf("%s.%s.json", globalFindings, label))},
	}
	for _, o := range outputs {
		if err := copyLinkfinderArtifact(o.src, o.dest); err != nil {
			return fmt.Errorf("copy %s -> %s: %w", o.src, o.dest, err)
		}
	}
	return nil
}

func persistLinkfinderGFArtifacts(findingsDir, label, srcDir string) error {
	outputs := []struct {
		name string
		dest string
	}{
		{name: "gf.txt", dest: filepath.Join(findingsDir, fmt.Sprintf("%s.%s.txt", gfPrefix, label))},
		{name: "gf.json", dest: filepath.Join(findingsDir, fmt.Sprintf("%s.%s.json", gfPrefix, label))},
	}
	for _, o := range outputs {
		src := filepath.Join(srcDir, o.name)
		if err := copyLinkfinderArtifact(src, o.dest); err != nil {
			return fmt.Errorf("copy gf %s -> %s: %w", src, o.dest, err)
		}
	}
	return nil
}

func copyLinkfinderArtifact(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// si el src no existe, elimina destino previo si lo hubiera
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

func writeLinkfinderJSON(path string, payload linkfinderPayload) error {
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal json: %w", err)
	}
	if err := os.WriteFile(path, data, defaultFilePerm); err != nil {
		return fmt.Errorf("write json: %w", err)
	}
	return nil
}

func writeLinkfinderRaw(path string, payload linkfinderPayload) error {
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)

	fmt.Fprintln(bw, "# GoLinkfinderEVO raw results")
	fmt.Fprintf(bw, "# Generated at: %s\n", payload.Meta.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(bw, "# Resources scanned: %d\n", payload.Meta.TotalResources)
	fmt.Fprintf(bw, "# Total endpoints: %d\n\n", payload.Meta.TotalEndpoints)

	for _, report := range payload.Resources {
		fmt.Fprintln(bw, "[Resource] "+report.Resource)

		if len(report.Endpoints) == 0 {
			fmt.Fprintln(bw, "#   No endpoints were found.")
			continue
		}
		for _, ep := range report.Endpoints {
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
		return fmt.Errorf("execute template: %w", err)
	}
	if err := os.WriteFile(path, buf.Bytes(), defaultFilePerm); err != nil {
		return fmt.Errorf("write html: %w", err)
	}
	return nil
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

	addOnce := func(set map[string]struct{}, value string, emitPrefix string, bucket *[]string) {
		if _, ok := set[value]; ok {
			return
		}
		set[value] = struct{}{}
		if emitPrefix != "" {
			emit(out, emitPrefix+value)
		}
		if bucket != nil {
			*bucket = append(*bucket, value)
		}
	}

	for _, report := range reports {
		for _, ep := range report.Endpoints {
			link := strings.TrimSpace(ep.Link)
			if link == "" {
				continue
			}
			// Emit ruta base siempre
			if _, seen := seenRoutes[link]; !seen {
				addOnce(seenRoutes, link, "active: ", &result.Routes)
			}

			classification := classifyLinkfinderEndpoint(link)
			if classification.isJS {
				addOnce(seenJS, link, "active: js: ", &result.JS)
			}
			if classification.isHTML || classification.isImage {
				// marca que es HTML para potenciales consumidores
				addOnce(seenHTML, link, "active: html: ", nil)
				if classification.isHTML {
					addOnce(seenHTMLTargets, link, "", &result.HTML)
				}
				if classification.isImage {
					addOnce(seenImages, link, "", &result.Images)
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
					emit(out, "active: "+prefix+": "+link)
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

func emitLinkfinderGFFindings(aggregate *linkfinderGFAggregate, out chan<- string) error {
	if aggregate == nil {
		return nil
	}

	findings := aggregate.results()
	if len(findings) == 0 {
		return nil
	}

	type payload struct {
		Resource string   `json:"resource,omitempty"`
		Line     int      `json:"line,omitempty"`
		Evidence string   `json:"evidence"`
		Context  string   `json:"context,omitempty"`
		Rules    []string `json:"rules,omitempty"`
	}

	for _, finding := range findings {
		data, err := json.Marshal(payload{
			Resource: finding.Resource,
			Line:     finding.Line,
			Evidence: finding.Evidence,
			Context:  finding.Context,
			Rules:    finding.Rules,
		})
		if err != nil {
			return fmt.Errorf("marshal gf payload: %w", err)
		}
		emit(out, "active: gffinding: "+string(data))
	}

	return nil
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

func persistLinkfinderActiveOutputs(outdir string, emission linkfinderEmissionResult) error {
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
		if p := linkfinderCategoryActivePath(outdir, cat); p != "" {
			targets = append(targets, target{path: p, entries: entries})
		}
	}

	for _, t := range targets {
		if err := mergeAndWriteLinkfinderEntries(t.path, t.entries); err != nil {
			return fmt.Errorf("merge/write %s: %w", t.path, err)
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

func cleanLinkfinderEndpointLink(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	// quita comillas envolventes comunes
	trimmed = strings.Trim(trimmed, "\"'`")

	// corta a primer separador extraño (espacios, brackets, etc.)
	if idx := strings.IndexAny(trimmed, " \t\r\n\"'<>[]{}()"); idx != -1 {
		trimmed = trimmed[:idx]
	}

	// quita puntuación final común
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

// emit envía al canal solo si existe; ayuda en tests y evita panics.
func emit(out chan<- string, msg string) {
	if out == nil || msg == "" {
		return
	}
	out <- msg
}
