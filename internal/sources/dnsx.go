package sources

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"passive-rec/internal/netutil"
	"passive-rec/internal/runner"
)

var (
	dnsxBinFinder = runner.DNSXBin
	dnsxRunCmd    = runner.RunCommand
)

// DNSX executes ProjectDiscovery's dnsx against the provided domains and writes
// the raw output to dns/dns.active within outDir. Any informational messages are
// emitted via the provided out channel (using the active meta format).
func DNSX(ctx context.Context, domains []string, outDir string, out chan<- string) (err error) {
	cleaned := make([]string, 0, len(domains))
	for _, raw := range domains {
		d := strings.TrimSpace(raw)
		if d == "" {
			continue
		}
		cleaned = append(cleaned, d)
	}

	outputPath := filepath.Join(outDir, "dns", "dns.active")
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o755); err != nil {
		return err
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	writer := bufio.NewWriter(file)
	defer func() {
		if writer != nil {
			if flushErr := writer.Flush(); err == nil && flushErr != nil {
				err = flushErr
			}
		}
		if file != nil {
			if closeErr := file.Close(); err == nil && closeErr != nil {
				err = closeErr
			}
		}
	}()

	if len(cleaned) == 0 {
		if out != nil {
			out <- "active: meta: dnsx omitido (sin dominios deduplicados)"
		}
		return nil
	}

	bin, binErr := dnsxBinFinder()
	if binErr != nil {
		if out != nil {
			out <- "active: meta: dnsx not found in PATH"
		}
		return runner.ErrMissingBinary
	}

	tmpFile, err := os.CreateTemp("", "passive-rec-dnsx-*.txt")
	if err != nil {
		return err
	}
	tmpWriter := bufio.NewWriter(tmpFile)
	for _, domain := range cleaned {
		if _, err := tmpWriter.WriteString(domain); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return err
		}
		if err := tmpWriter.WriteByte('\n'); err != nil {
			tmpFile.Close()
			os.Remove(tmpFile.Name())
			return err
		}
	}
	if err := tmpWriter.Flush(); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return err
	}
	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpFile.Name())
		return err
	}
	defer os.Remove(tmpFile.Name())

	lineCh := make(chan string, 128)
	var wg sync.WaitGroup
	var writeErr error
	records := 0
	seenHosts := make(map[string]struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for line := range lineCh {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			records++
			host := trimmed
			if idx := strings.IndexAny(trimmed, " \t"); idx != -1 {
				host = trimmed[:idx]
			}
			if normalized := netutil.NormalizeDomain(host); normalized != "" {
				seenHosts[normalized] = struct{}{}
			}
			if writeErr != nil {
				continue
			}
			if _, err := writer.WriteString(trimmed); err != nil {
				writeErr = err
				continue
			}
			if err := writer.WriteByte('\n'); err != nil {
				writeErr = err
				continue
			}
		}
	}()

	execErr := dnsxRunCmd(ctx, bin, []string{"-all", "-l", tmpFile.Name()}, lineCh)
	close(lineCh)
	wg.Wait()

	if execErr != nil {
		if out != nil {
			out <- fmt.Sprintf("active: meta: dnsx error: %v", execErr)
		}
		return execErr
	}
	if writeErr != nil {
		if out != nil {
			out <- fmt.Sprintf("active: meta: dnsx error: %v", writeErr)
		}
		return writeErr
	}

	if out != nil {
		out <- fmt.Sprintf("active: meta: dnsx resolvió %d registros (%d dominios)", records, len(seenHosts))
	}

	return nil
}
