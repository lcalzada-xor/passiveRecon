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

// DNSX ejecuta dnsx sobre los dominios y escribe salida cruda JSONL en dns/dns.active.
// Mensajes informativos se emiten por el canal `out` con el formato "active: meta: ...".
func DNSX(ctx context.Context, domains []string, outDir string, out chan<- string) (err error) {
	// Pre-filtrado mínimo (mantén comportamiento: no normalizamos aquí).
	cleaned := make([]string, 0, len(domains))
	for _, raw := range domains {
		if d := strings.TrimSpace(raw); d != "" {
			cleaned = append(cleaned, d)
		}
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
		// flush + close seguros, preservando el primer error
		if writer != nil {
			if e := writer.Flush(); err == nil && e != nil {
				err = e
			}
		}
		if file != nil {
			if e := file.Close(); err == nil && e != nil {
				err = e
			}
		}
	}()

	if len(cleaned) == 0 {
		emitMeta(out, "dnsx omitido (sin dominios deduplicados)")
		return nil
	}

	bin, binErr := dnsxBinFinder()
	if binErr != nil {
		emitMeta(out, "dnsx not found in PATH")
		return runner.ErrMissingBinary
	}

	// Volcar dominios a un fichero temporal para -l
	tmpFile, err := os.CreateTemp("", "passive-rec-dnsx-*.txt")
	if err != nil {
		return err
	}
	// Cleanup garantizado del temp file
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	tmpWriter := bufio.NewWriter(tmpFile)
	for _, domain := range cleaned {
		if _, err := tmpWriter.WriteString(domain); err != nil {
			_ = tmpFile.Close()
			return err
		}
		if err := tmpWriter.WriteByte('\n'); err != nil {
			_ = tmpFile.Close()
			return err
		}
	}
	if err := tmpWriter.Flush(); err != nil {
		_ = tmpFile.Close()
		return err
	}
	if err := tmpFile.Close(); err != nil {
		return err
	}

	// Canal intermedio para desacoplar el lector del proceso
	lineCh := make(chan string, 1024)

	var (
		wg        sync.WaitGroup
		writeErr  error
		records   int
		seenHosts = make(map[string]struct{})
	)

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
			rec := dnsxRecord{Raw: trimmed}
			if host != "" {
				rec.Host = host
			}
			if recordType != "" {
				rec.Type = recordType
			}
			if value != "" {
				rec.Value = value
			}

			// Track hosts normalizados para el resumen final
			if normalized := extractNormalizedHost(host, trimmed); normalized != "" {
				seenHosts[normalized] = struct{}{}
			}

			// PTRs para A/AAAA
			if recordType != "" && (strings.EqualFold(recordType, "A") || strings.EqualFold(recordType, "AAAA")) {
				if ptrs := resolvePTRs(ctx, value); len(ptrs) > 0 {
					rec.PTR = ptrs
				}
			}

			if writeErr != nil {
				continue
			}

			serialized, err := marshalOneLine(rec)
			if err != nil {
				writeErr = err
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

	execErr := dnsxRunCmd(ctx, bin, []string{"-all", "-json", "-l", tmpPath}, lineCh)
	close(lineCh)
	wg.Wait()

	if execErr != nil {
		emitMeta(out, "dnsx error: %v", execErr)
		return execErr
	}
	if writeErr != nil {
		emitMeta(out, "dnsx error: %v", writeErr)
		return writeErr
	}

	emitMeta(out, "dnsx resolvió %d registros (%d dominios)", records, len(seenHosts))
	return nil
}

// parseDNSXLine extrae host, tipo y valor de una línea estilo "host [TYPE] value".
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

// extractNormalizedHost intenta normalizar primero el host explícito y,
// si falla, intenta con el primer token de la línea completa.
func extractNormalizedHost(host, raw string) string {
	if normalized := netutil.NormalizeDomain(host); normalized != "" {
		return normalized
	}
	candidate := strings.TrimSpace(raw)
	if i := strings.IndexAny(candidate, " \t"); i != -1 {
		candidate = candidate[:i]
	}
	return netutil.NormalizeDomain(candidate)
}

// resolvePTRs resuelve PTRs para todas las IPs presentes en value.
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
			if cleaned := cleanPTR(ptr); cleaned != "" {
				if _, ok := seen[cleaned]; ok {
					continue
				}
				seen[cleaned] = struct{}{}
				out = append(out, cleaned)
			}
		}
	}
	return out
}

// extractIPs escoge todas las IPs que aparezcan en value (separadores variados).
func extractIPs(value string) []string {
	if value == "" {
		return nil
	}
	var ips []string
	for _, field := range strings.Fields(value) {
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

// marshalOneLine serializa un dnsxRecord en una línea JSON compacta sin escapado HTML.
func marshalOneLine(rec dnsxRecord) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return "", err
	}
	// Encode añade '\n'; lo recortamos para mantener control del newline.
	return strings.TrimSpace(buf.String()), nil
}

// emitMeta emite un mensaje active: meta: … si el canal existe.
func emitMeta(out chan<- string, format string, args ...any) {
	if out == nil {
		return
	}
	msg := strings.TrimSpace(fmt.Sprintf(format, args...))
	if msg == "" {
		return
	}
	out <- "active: meta: " + msg
}
