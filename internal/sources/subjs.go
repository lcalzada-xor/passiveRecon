package sources

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"passive-rec/internal/runner"
)

var (
	subjsFindBin      = runner.FindBin
	subjsRunCmd       = runner.RunCommand
	subjsValidator    = validateJSURLs
	subjsWorkerCount  = runtime.NumCPU()
	subjsHTTPTimeout  = 15 * time.Second
	subjsClientLoader = func() *http.Client {
		transport := &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			ResponseHeaderTimeout: 10 * time.Second,
		}
		return &http.Client{Transport: transport, Timeout: subjsHTTPTimeout}
	}
)

// SubJS executes the subjs binary using the routes active list as input. It collects
// the discovered JavaScript URLs, validates that they respond with HTTP 200 and
// writes the surviving URLs to the sink using the "active: js:" prefix so they
// are tracked as active findings.
func SubJS(ctx context.Context, routesFile string, outdir string, out chan<- string) error {
	bin, ok := subjsFindBin("subjs")
	if !ok {
		out <- "active: meta: subjs not found in PATH"
		return runner.ErrMissingBinary
	}

	inputs, err := loadSubJSInput(filepath.Join(outdir, routesFile))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			out <- "active: meta: subjs skipped missing input " + routesFile
			return nil
		}
		return err
	}
	if len(inputs) == 0 {
		return nil
	}

	tmpPath, cleanup, err := writeSubJSInput(inputs)
	if err != nil {
		return err
	}
	defer cleanup()

	intermediate := make(chan string)
	runErr := make(chan error, 1)
	go func() {
		runErr <- subjsRunCmd(ctx, bin, []string{"-i", tmpPath}, intermediate)
		close(intermediate)
	}()

	seen := make(map[string]struct{})
	var candidates []string
	for line := range intermediate {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		candidates = append(candidates, trimmed)
	}

	if err := <-runErr; err != nil {
		return err
	}
	if len(candidates) == 0 {
		return nil
	}

	valid, err := subjsValidator(ctx, candidates)
	if err != nil {
		return err
	}
	for _, url := range valid {
		out <- "active: js: " + url
	}
	return nil
}

func loadSubJSInput(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	seen := make(map[string]struct{})
	var inputs []string
	for scanner.Scan() {
		line := extractSubJSInput(scanner.Text())
		if line == "" {
			continue
		}
		if _, ok := seen[line]; ok {
			continue
		}
		seen[line] = struct{}{}
		inputs = append(inputs, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return inputs, nil
}

func extractSubJSInput(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "#") {
		return ""
	}
	if idx := strings.IndexAny(trimmed, " \t"); idx != -1 {
		trimmed = trimmed[:idx]
	}
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return ""
	}
	return trimmed
}

func writeSubJSInput(lines []string) (string, func(), error) {
	tmpFile, err := os.CreateTemp("", "passive-rec-subjs-*.txt")
	if err != nil {
		return "", nil, err
	}

	cleanup := func() {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
	}

	writer := bufio.NewWriter(tmpFile)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			cleanup()
			return "", nil, err
		}
	}
	if err := writer.Flush(); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := tmpFile.Close(); err != nil {
		cleanup()
		return "", nil, err
	}
	return tmpFile.Name(), cleanup, nil
}

func validateJSURLs(ctx context.Context, urls []string) ([]string, error) {
	if len(urls) == 0 {
		return nil, nil
	}

	client := subjsClientLoader()
	if client == nil {
		client = &http.Client{Timeout: subjsHTTPTimeout}
	}

	workerCount := subjsWorkerCount
	if workerCount <= 0 {
		workerCount = 1
	}

	jobs := make(chan string)
	results := make(chan string, workerCount)
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for url := range jobs {
				if ctx.Err() != nil {
					return
				}
				if checkJSURL(ctx, client, url) {
					select {
					case results <- url:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	go func() {
		defer close(jobs)
		for _, url := range urls {
			select {
			case <-ctx.Done():
				return
			case jobs <- url:
			}
		}
	}()

	seen := make(map[string]struct{})
	var valid []string
	for url := range results {
		if _, ok := seen[url]; ok {
			continue
		}
		seen[url] = struct{}{}
		valid = append(valid, url)
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return valid, nil
}

func checkJSURL(ctx context.Context, client *http.Client, url string) bool {
	if status, err := doJSRequest(ctx, client, http.MethodHead, url); err == nil && status == http.StatusOK {
		return true
	}
	status, err := doJSRequest(ctx, client, http.MethodGet, url)
	return err == nil && status == http.StatusOK
}

func doJSRequest(ctx context.Context, client *http.Client, method, url string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return 0, err
	}
	req.Close = true
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}
