package sources

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
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
	dnsxPTRLookup = func(ctx context.Context, addr string) ([]string, error) {
		return net.DefaultResolver.LookupAddr(ctx, addr)
	}
)

type dnsxRecord struct {
	Host  string   `json:"host,omitempty"`
	Type  string   `json:"type,omitempty"`
	Value string   `json:"value,omitempty"`
	Raw   string   `json:"raw,omitempty"`
	PTR   []string `json:"ptr,omitempty"`
}

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
			host, recordType, value := parseDNSXLine(trimmed)
			record := dnsxRecord{Raw: trimmed}
			if host != "" {
				record.Host = host
			}
			if recordType != "" {
				record.Type = recordType
			}
			if value != "" {
				record.Value = value
			}
			if normalized := extractNormalizedHost(host, trimmed); normalized != "" {
				seenHosts[normalized] = struct{}{}
			}
			if recordType != "" && (strings.EqualFold(recordType, "A") || strings.EqualFold(recordType, "AAAA")) {
				ptrs := resolvePTRs(ctx, value)
				if len(ptrs) > 0 {
					record.PTR = ptrs
				}
			}
			if writeErr != nil {
				continue
			}

			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(record); err != nil {
				writeErr = err
				continue
			}
			serialized := strings.TrimSpace(buf.String())
			if serialized == "" {
				continue
			}
			if _, err := writer.WriteString(serialized); err != nil {
				writeErr = err
				continue
			}
			if err := writer.WriteByte('\n'); err != nil {
				writeErr = err
				continue
			}
			if out != nil {
				out <- "active: dns:" + serialized
			}
		}
	}()

	execErr := dnsxRunCmd(ctx, bin, []string{"-all", "-json", "-l", tmpFile.Name()}, lineCh)
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

func parseDNSXLine(line string) (host, recordType, value string) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", "", ""
	}
	host = trimmed
	start := strings.Index(trimmed, "[")
	if start == -1 {
		return host, "", ""
	}
	end := strings.Index(trimmed[start+1:], "]")
	if end == -1 {
		return strings.TrimSpace(trimmed[:start]), "", strings.TrimSpace(trimmed[start+1:])
	}
	end += start + 1
	host = strings.TrimSpace(trimmed[:start])
	recordType = strings.TrimSpace(trimmed[start+1 : end])
	if end+1 < len(trimmed) {
		value = strings.TrimSpace(trimmed[end+1:])
	}
	return host, recordType, value
}

func extractNormalizedHost(host, raw string) string {
	if normalized := netutil.NormalizeDomain(host); normalized != "" {
		return normalized
	}
	candidate := strings.TrimSpace(raw)
	if idx := strings.IndexAny(candidate, " \t"); idx != -1 {
		candidate = candidate[:idx]
	}
	return netutil.NormalizeDomain(candidate)
}

func resolvePTRs(ctx context.Context, value string) []string {
	ips := extractIPs(value)
	if len(ips) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, ip := range ips {
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				break
			}
		}
		ptrs, err := dnsxPTRLookup(ctx, ip)
		if err != nil {
			continue
		}
		for _, ptr := range ptrs {
			cleaned := cleanPTR(ptr)
			if cleaned == "" {
				continue
			}
			if _, ok := seen[cleaned]; ok {
				continue
			}
			seen[cleaned] = struct{}{}
			out = append(out, cleaned)
		}
	}
	return out
}

func extractIPs(value string) []string {
	if value == "" {
		return nil
	}
	var ips []string
	fields := strings.Fields(value)
	for _, field := range fields {
		cleaned := strings.Trim(field, "\"'()[]{}<>,;")
		if cleaned == "" {
			continue
		}
		if ip := net.ParseIP(cleaned); ip != nil {
			ips = append(ips, cleaned)
		}
	}
	return ips
}

func cleanPTR(value string) string {
	if value == "" {
		return ""
	}
	cleaned := strings.TrimSpace(value)
	cleaned = strings.TrimSuffix(cleaned, ".")
	cleaned = strings.TrimSpace(cleaned)
	if cleaned == "" {
		return ""
	}
	return strings.ToLower(cleaned)
}
