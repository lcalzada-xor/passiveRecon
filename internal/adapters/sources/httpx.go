package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/sync/errgroup"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/core/runner"
	"passive-rec/internal/platform/urlutil"
)

const (
	// httpxDefaultBatchSize determines how many URLs are processed in a single httpx invocation.
	// Larger batches reduce overhead but may cause timeouts on slow systems.
	httpxDefaultBatchSize = 5000

	// httpxIntermediateBufferSize sets the channel buffer for httpx output forwarding.
	// A generous buffer prevents blocking when processing bursts of responses.
	httpxIntermediateBufferSize = 1024

	// httpxMaxThreads límite máximo de threads para httpx
	httpxMaxThreads = 150

	// httpxRateLimit requests per second
	httpxRateLimit = 400
)

// httpxJSONResponse representa la respuesta JSON de httpx con la nueva configuración
type httpxJSONResponse struct {
	Timestamp     string   `json:"timestamp"`
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	StatusCode    int      `json:"status_code"`
	ContentType   string   `json:"content_type"`
	ContentLength int      `json:"content_length"`
	Title         string   `json:"title"`
	Webserver     string   `json:"webserver"`
	Tech          []string `json:"tech"`
	Host          string   `json:"host"`
	Port          string   `json:"port"`
	Scheme        string   `json:"scheme"`
	Path          string   `json:"path"`
	Method        string   `json:"method"`
	A             []string `json:"a"` // DNS A records
	Failed        bool     `json:"failed"`
}

var (
	httpxBinFinder = runner.HTTPXBin
	httpxRunCmd    = runner.RunCommand
	// httpxBatchSize can be overridden for testing or tuning
	httpxBatchSize = httpxDefaultBatchSize
	// httpxWorkerCount defaults to number of CPUs but can be adjusted
	httpxWorkerCount = runtime.NumCPU()

	httpxMetaEmit   = func(string) {}
	HTTPXInputsHook = func(int) {}

	lowPriorityHTTPXExtensions = urlutil.LowPriorityExtensions

	ansiEscapeSequences = regexp.MustCompile(`\x1b\[[0-9;?]*[ -/]*[@-~]`)
)

func HTTPX(ctx context.Context, outdir string, out chan<- string) error {
	bin, err := httpxBinFinder()
	if err != nil {
		if out != nil {
			out <- "active: meta: httpx not found in PATH"
		}
		return err
	}

	originalMeta := httpxMetaEmit
	httpxMetaEmit = func(line string) {
		if out != nil {
			out <- line
		}
	}
	defer func() { httpxMetaEmit = originalMeta }()

	combined, err := collectHTTPXInputs(outdir)
	if err != nil {
		return err
	}
	if len(combined) == 0 {
		HTTPXInputsHook(0)
		return nil
	}
	HTTPXInputsHook(len(combined))

	intermediate, cleanup := forwardHTTPXOutput(out)
	defer cleanup()

	return runHTTPXWorkers(ctx, bin, combined, intermediate, httpxRunCmd, func(lines []string) (string, func(), error) {
		return artifacts.WriteTempInput("httpx", lines)
	})
}

func collectHTTPXInputs(outdir string) ([]string, error) {
	var combined []string
	seen := make(map[string]struct{})

	selectors := map[string]artifacts.ActiveState{
		"domain": artifacts.AnyState,
		"route":  artifacts.AnyState,
	}

	values, err := artifacts.CollectValuesByType(outdir, selectors)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			httpxMetaEmit("active: meta: httpx skipped (missing artifacts.jsonl)")
			return nil, nil
		}
		return nil, err
	}

	appendValue := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || shouldSkipHTTPXInput(line) {
			return
		}
		if _, ok := seen[line]; ok {
			return
		}
		seen[line] = struct{}{}
		combined = append(combined, line)
	}

	for _, domain := range values["domain"] {
		appendValue(domain)
	}
	for _, route := range values["route"] {
		appendValue(route)
	}

	return combined, nil
}

func forwardHTTPXOutput(out chan<- string) (chan<- string, func()) {
	// Buffer generoso para absorber ráfagas de httpx sin bloquear
	intermediate := make(chan string, httpxIntermediateBufferSize)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for line := range intermediate {
			for _, normalized := range normalizeHTTPXLine(line) {
				if out != nil {
					out <- normalized
				}
			}
		}
	}()

	cleanup := func() {
		close(intermediate)
		wg.Wait()
	}
	return intermediate, cleanup
}

func runHTTPXWorkers(
	ctx context.Context,
	bin string,
	combined []string,
	intermediate chan<- string,
	runCmd func(context.Context, string, []string, chan<- string) error,
	inputWriter func([]string) (string, func(), error),
) error {
	if len(combined) == 0 {
		return nil
	}

	// Determinar tamaño de lote real
	batchSize := httpxBatchSize
	if batchSize <= 0 || batchSize > len(combined) {
		batchSize = len(combined)
	}

	// Calcular nº de lotes
	numBatches := (len(combined) + batchSize - 1) / batchSize

	// Ajustar workers a nº de lotes para evitar goroutines ociosas
	workerCount := httpxWorkerCount
	if workerCount <= 0 {
		workerCount = 1
	}
	if numBatches < workerCount {
		workerCount = numBatches
	}

	type batchRange struct{ start, end int }

	jobs := make(chan batchRange, numBatches)
	group, groupCtx := errgroup.WithContext(ctx)

	// Productor de trabajos
	group.Go(func() error {
		defer close(jobs)
		for start := 0; start < len(combined); start += batchSize {
			end := start + batchSize
			if end > len(combined) {
				end = len(combined)
			}
			select {
			case <-groupCtx.Done():
				return nil
			case jobs <- batchRange{start: start, end: end}:
			}
		}
		return nil
	})

	// Workers
	for i := 0; i < workerCount; i++ {
		group.Go(func() error {
			for br := range jobs {
				select {
				case <-groupCtx.Done():
					return groupCtx.Err()
				default:
				}

				tmpPath, cleanup, err := inputWriter(combined[br.start:br.end])
				if err != nil {
					if cleanup != nil {
						cleanup()
					}
					return err
				}
				// Usar directamente httpxMaxThreads - las herramientas de red pueden manejar
				// muchos más threads que CPUs físicos debido a I/O bound operations
				threads := httpxMaxThreads

				// Asegurar cleanup incluso si runCmd falla
				func() {
					defer cleanup()
					err = runCmd(groupCtx, bin, []string{
						"-l", tmpPath,
						"-silent",
						"-no-color",
						"-timeout", "7",
						"-retries", "1",
						"-follow-redirects",
						"-threads", strconv.Itoa(threads),
						"-rl", strconv.Itoa(httpxRateLimit),
						"-x", "HEAD",
						"-status-code",
						"-title",
						"-content-type",
						"-json",
						"-nf",  // no-fallback: display both HTTP and HTTPS results
						"-nfs", // no-fallback-scheme: respect input scheme (http/https)
					}, intermediate)
				}()
				if err != nil {
					return err
				}
			}
			return nil
		})
	}

	return group.Wait()
}

func normalizeHTTPXLine(line string) []string {
	line = stripANSIEscapeSequences(line)
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

	// Intentar parsear como JSON primero
	if strings.HasPrefix(line, "{") {
		return processHTTPXJSON(line)
	}

	// Fallback a formato antiguo (legacy)
	return processHTTPXLegacy(line)
}

func processHTTPXJSON(line string) []string {
	var resp httpxJSONResponse
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		// Si falla el parseo, intentar con formato legacy
		return processHTTPXLegacy(line)
	}

	// Si la request falló, no emitir nada
	if resp.Failed {
		return nil
	}

	var out []string

	// Emitir la URL si tiene un status code válido
	if shouldForwardHTTPXRoute(true, resp.StatusCode) && resp.URL != "" {
		out = append(out, resp.URL)
	}

	// Emitir dominio
	if domain := extractHTTPXDomain(resp.URL); domain != "" && shouldEmitHTTPXDomain(true, resp.StatusCode) {
		out = append(out, domain)
	}

	// Emitir HTML si corresponde
	hasHTMLContent := strings.Contains(strings.ToLower(resp.ContentType), "text/html")
	if shouldEmitHTTPXHTML(hasHTMLContent, true, resp.StatusCode) && resp.URL != "" {
		out = append(out, "html: "+resp.URL)
	}

	// Crear keyFindings con información relevante
	keyFindings := extractKeyFindings(resp)
	for _, finding := range keyFindings {
		out = append(out, "keyFinding: "+finding)
	}

	if len(out) == 0 {
		return nil
	}

	// Añadir prefijo "active: " a todos
	for i := range out {
		out[i] = "active: " + out[i]
	}
	return out
}

func extractKeyFindings(resp httpxJSONResponse) []string {
	var findings []string

	// Webserver/tecnología principal
	if resp.Webserver != "" {
		findings = append(findings, fmt.Sprintf(`{"type":"webserver","url":"%s","value":"%s"}`, resp.URL, resp.Webserver))
	}

	// Tecnologías detectadas
	for _, tech := range resp.Tech {
		if tech != "" {
			findings = append(findings, fmt.Sprintf(`{"type":"technology","url":"%s","value":"%s"}`, resp.URL, tech))
		}
	}

	// Content-Type interesante (no HTML estándar)
	if resp.ContentType != "" && !strings.Contains(strings.ToLower(resp.ContentType), "text/html") {
		// Solo emitir content-types no estándar o relevantes
		lower := strings.ToLower(resp.ContentType)
		if strings.Contains(lower, "application/") ||
			strings.Contains(lower, "font") ||
			strings.Contains(lower, "wasm") ||
			strings.Contains(lower, "json") {
			findings = append(findings, fmt.Sprintf(`{"type":"content-type","url":"%s","value":"%s"}`, resp.URL, resp.ContentType))
		}
	}

	// Título de la página (si existe y no es la URL)
	if resp.Title != "" && resp.Title != resp.URL {
		// Escapar comillas en el título
		escapedTitle := strings.ReplaceAll(resp.Title, `"`, `\"`)
		findings = append(findings, fmt.Sprintf(`{"type":"title","url":"%s","value":"%s"}`, resp.URL, escapedTitle))
	}

	return findings
}

func processHTTPXLegacy(line string) []string {
	var (
		urlPart  = line
		metaPart string
	)

	if i := strings.IndexAny(line, " \t"); i != -1 {
		urlPart = strings.TrimSpace(line[:i])
		metaPart = strings.TrimSpace(line[i+1:])
	}

	metas := splitHTTPXMeta(metaPart)
	statusCode, hasStatus := parseHTTPXStatusCode(metas)
	hasHTMLContent := httpxHasHTMLContentType(metas)

	var out []string

	if urlPart != "" && shouldForwardHTTPXRoute(hasStatus, statusCode) {
		combined := urlPart
		if metaPart != "" {
			combined = strings.TrimSpace(urlPart + " " + metaPart)
		}
		out = append(out, combined)
	}

	if urlPart != "" {
		if domain := extractHTTPXDomain(urlPart); domain != "" && shouldEmitHTTPXDomain(hasStatus, statusCode) {
			combinedDomain := domain
			if metaPart != "" {
				combinedDomain = strings.TrimSpace(domain + " " + metaPart)
			}
			out = append(out, combinedDomain)
		}
	}

	if urlPart != "" && shouldEmitHTTPXHTML(hasHTMLContent, hasStatus, statusCode) {
		out = append(out, "html: "+urlPart)
	}

	for _, meta := range metas {
		meta = strings.TrimSpace(meta)
		if meta == "" {
			continue
		}
		out = append(out, "meta: "+meta)
	}

	if len(out) == 0 {
		return nil
	}

	for i := range out {
		out[i] = "active: " + out[i]
	}
	return out
}

func shouldSkipHTTPXInput(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	return urlutil.ShouldSkipByExtension(trimmed, lowPriorityHTTPXExtensions)
}

func shouldForwardHTTPXRoute(hasStatus bool, status int) bool {
	if !hasStatus {
		return true
	}
	if status == 0 || status == 404 {
		return false
	}
	return true
}

func shouldEmitHTTPXDomain(hasStatus bool, status int) bool {
	return true
}

func parseHTTPXStatusCode(metas []string) (int, bool) {
	if len(metas) == 0 {
		return 0, false
	}
	status := strings.TrimSpace(metas[0])
	if len(status) < 2 || status[0] != '[' || status[len(status)-1] != ']' {
		return 0, false
	}
	inside := strings.TrimSpace(status[1 : len(status)-1])
	if inside == "" {
		return 0, false
	}
	for i, r := range inside {
		if !unicode.IsDigit(r) {
			inside = inside[:i]
			break
		}
	}
	if inside == "" {
		return 0, false
	}
	code, err := strconv.Atoi(inside)
	if err != nil {
		return 0, false
	}
	return code, true
}

func shouldEmitHTTPXHTML(hasHTML bool, hasStatus bool, status int) bool {
	if !hasHTML {
		return false
	}
	if !hasStatus {
		return true
	}
	return status >= 200 && status < 400
}

func httpxHasHTMLContentType(metas []string) bool {
	for _, meta := range metas {
		trimmed := strings.TrimSpace(meta)
		if trimmed == "" {
			continue
		}
		normalized := strings.ToLower(strings.Trim(trimmed, "[]"))
		if normalized == "" {
			continue
		}
		if strings.Contains(normalized, "text/html") {
			return true
		}
	}
	return false
}

func extractHTTPXDomain(rawURL string) string {
	trimmed := strings.TrimSpace(rawURL)
	if trimmed == "" {
		return ""
	}
	if strings.Contains(trimmed, "://") {
		if parsed, err := url.Parse(trimmed); err == nil {
			host := parsed.Hostname()
			return strings.TrimSpace(host)
		}
	}
	// Fallback host[:port]
	if idx := strings.Index(trimmed, "/"); idx != -1 {
		trimmed = trimmed[:idx]
	}
	if idx := strings.Index(trimmed, ":"); idx != -1 {
		trimmed = trimmed[:idx]
	}
	return strings.TrimSpace(trimmed)
}

func splitHTTPXMeta(meta string) []string {
	meta = stripANSIEscapeSequences(meta)
	meta = strings.TrimSpace(meta)
	if meta == "" {
		return nil
	}

	var (
		parts      []string
		current    strings.Builder
		inBrackets bool
	)

	flush := func() {
		if current.Len() == 0 {
			return
		}
		parts = append(parts, current.String())
		current.Reset()
	}

	for _, r := range meta {
		switch {
		case r == '[':
			if current.Len() > 0 {
				flush()
			}
			inBrackets = true
			current.WriteRune(r)
		case r == ']':
			current.WriteRune(r)
			flush()
			inBrackets = false
		case unicode.IsSpace(r) && !inBrackets:
			flush()
		default:
			current.WriteRune(r)
		}
	}
	flush()

	for i, p := range parts {
		parts[i] = strings.TrimSpace(p)
	}
	return parts
}

func stripANSIEscapeSequences(s string) string {
	if s == "" {
		return s
	}
	// Elimina secuencias CSI y además cualquier ESC residual
	cleaned := ansiEscapeSequences.ReplaceAllString(s, "")
	return strings.ReplaceAll(cleaned, "\x1b", "")
}
