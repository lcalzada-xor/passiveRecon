package sources

import (
	"bufio"
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/sync/errgroup"

	"passive-rec/internal/artifacts"
	"passive-rec/internal/runner"
)

var (
	httpxBinFinder   = runner.HTTPXBin
	httpxRunCmd      = runner.RunCommand
	httpxBatchSize   = 5000
	httpxWorkerCount = runtime.NumCPU()

	httpxMetaEmit = func(string) {}

	lowPriorityHTTPXExtensions = map[string]struct{}{
		".ico": {},
		".cur": {},
		".bmp": {},
		".gif": {},
		".pbm": {},
		".pgm": {},
		".pnm": {},
	}
)

func HTTPX(ctx context.Context, outdir string, out chan<- string) error {
	bin, err := httpxBinFinder()
	if err != nil {
		out <- "active: meta: httpx not found in PATH"
		return err
	}

	originalMeta := httpxMetaEmit
	httpxMetaEmit = func(line string) {
		out <- line
	}
	defer func() {
		httpxMetaEmit = originalMeta
	}()

	combined, err := collectHTTPXInputs(outdir)
	if err != nil {
		return err
	}

	if len(combined) == 0 {
		return nil
	}

	intermediate, cleanup := forwardHTTPXOutput(out)
	defer cleanup()

	return runHTTPXWorkers(ctx, bin, combined, intermediate, httpxRunCmd, writeHTTPXInput)
}

func collectHTTPXInputs(outdir string) ([]string, error) {
	var combined []string
	seen := make(map[string]struct{})

	selectors := map[string]artifacts.ActiveState{
		"domain": artifacts.AnyState,
		"route":  artifacts.PassiveOnly,
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
		if line == "" {
			return
		}
		if strings.HasPrefix(line, "#") {
			return
		}
		if shouldSkipHTTPXInput(line) {
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
	intermediate := make(chan string)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for line := range intermediate {
			for _, normalized := range normalizeHTTPXLine(line) {
				out <- normalized
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

	batchSize := httpxBatchSize
	if batchSize <= 0 || batchSize > len(combined) {
		batchSize = len(combined)
	}

	workerCount := httpxWorkerCount
	if workerCount <= 0 {
		workerCount = 1
	}

	type batchRange struct {
		start int
		end   int
	}

	jobs := make(chan batchRange)
	group, groupCtx := errgroup.WithContext(ctx)

	group.Go(func() error {
		defer close(jobs)
		for start := 0; start < len(combined); start += batchSize {
			end := start + batchSize
			if end > len(combined) {
				end = len(combined)
			}

			br := batchRange{start: start, end: end}
			select {
			case <-groupCtx.Done():
				return nil
			case jobs <- br:
			}
		}
		return nil
	})

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
					return err
				}

				err = runCmd(groupCtx, bin, []string{
					"-sc",
					"-title",
					"-content-type",
					"-silent",
					"-l",
					tmpPath,
				}, intermediate)
				cleanup()
				if err != nil {
					return err
				}
			}
			return nil
		})
	}

	if err := group.Wait(); err != nil {
		return err
	}

	return nil
}

func writeHTTPXInput(lines []string) (string, func(), error) {
	tmpFile, err := os.CreateTemp("", "passive-rec-httpx-*.txt")
	if err != nil {
		return "", nil, err
	}

	cleanup := func() {
		os.Remove(tmpFile.Name())
	}

	writer := bufio.NewWriter(tmpFile)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			tmpFile.Close()
			cleanup()
			return "", nil, err
		}
	}
	if err := writer.Flush(); err != nil {
		tmpFile.Close()
		cleanup()
		return "", nil, err
	}
	if err := tmpFile.Close(); err != nil {
		cleanup()
		return "", nil, err
	}

	return tmpFile.Name(), cleanup, nil
}

func normalizeHTTPXLine(line string) []string {
	line = strings.TrimSpace(line)
	if line == "" {
		return nil
	}

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

	path := extractHTTPXPath(trimmed)
	if path == "" {
		return false
	}

	path = strings.ToLower(path)
	if idx := strings.IndexAny(path, "?#"); idx != -1 {
		path = path[:idx]
	}

	base := filepath.Base(path)
	if base == "" || base == "/" || base == "." {
		return false
	}

	if base == "thumbs.db" {
		return true
	}

	ext := filepath.Ext(base)
	if ext != "" {
		if _, ok := lowPriorityHTTPXExtensions[ext]; ok {
			return true
		}
	}

	name := strings.TrimSuffix(base, ext)
	if strings.Contains(name, "thumb") {
		switch ext {
		case ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp":
			return true
		}
	}

	if strings.Contains(name, "sprite") {
		switch ext {
		case ".png", ".svg", ".jpg", ".jpeg", ".webp":
			return true
		}
	}

	return false
}

func extractHTTPXPath(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}

	if strings.Contains(trimmed, "://") {
		if parsed, err := url.Parse(trimmed); err == nil {
			if parsed.Path != "" {
				return parsed.Path
			}
		}
	}

	if idx := strings.Index(trimmed, "/"); idx != -1 {
		return trimmed[idx:]
	}

	return ""
}

func shouldForwardHTTPXRoute(hasStatus bool, status int) bool {
	if !hasStatus {
		return true
	}
	if status == 0 {
		return false
	}
	if status == 404 {
		return false
	}
	return true
}

func shouldEmitHTTPXDomain(hasStatus bool, status int) bool {
	// Emit domains for any status so users can see redirects or erroring hosts
	// discovered by httpx. This mirrors httpx's output and avoids hiding
	// potentially interesting infrastructure such as 3xx redirectors.
	// Even when httpx doesn't report a status we still want to keep the
	// domain entry.
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

	// Some httpx status fields may include additional information (e.g. "301,301").
	// Consider the leading numeric portion when deciding whether the target responded.
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
		parsed, err := url.Parse(trimmed)
		if err == nil {
			host := parsed.Hostname()
			return strings.TrimSpace(host)
		}
	}

	// Fallback: split on '/', then ':' for host:port.
	if idx := strings.Index(trimmed, "/"); idx != -1 {
		trimmed = trimmed[:idx]
	}
	if idx := strings.Index(trimmed, ":"); idx != -1 {
		trimmed = trimmed[:idx]
	}

	return strings.TrimSpace(trimmed)
}

func splitHTTPXMeta(meta string) []string {
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
