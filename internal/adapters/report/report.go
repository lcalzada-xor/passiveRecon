package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/publicsuffix"

	"passive-rec/internal/adapters/artifacts"
	"passive-rec/internal/platform/certs"
	"passive-rec/internal/platform/config"
	"passive-rec/internal/platform/netutil"
)

// Generate reads the artifact manifest and renders an HTML report in cfg.OutDir.
func Generate(ctx context.Context, cfg *config.Config) error {
	if cfg == nil {
		return errors.New("report: missing config")
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	exists, err := artifacts.Exists(cfg.OutDir)
	if err != nil {
		return fmt.Errorf("report: artifacts manifest: %w", err)
	}

	selectors := map[string]artifacts.ActiveState{
		"domain":      artifacts.PassiveOnly,
		"route":       artifacts.PassiveOnly,
		"certificate": artifacts.PassiveOnly,
		"meta":        artifacts.PassiveOnly,
	}
	var passiveArtifacts map[string][]artifacts.Artifact
	if exists {
		passiveArtifacts, err = artifacts.CollectArtifactsByType(cfg.OutDir, selectors)
		if err != nil {
			return fmt.Errorf("report: passive artifacts: %w", err)
		}
	}

	domains := artifactValues(passiveArtifacts["domain"])
	routes := artifactValues(passiveArtifacts["route"])
	certs := artifactValues(passiveArtifacts["certificate"])
	meta := artifactValues(passiveArtifacts["meta"])

	var active activeData
	if cfg.Active {
		if err := ctx.Err(); err != nil {
			return err
		}

		activeSelectors := map[string]artifacts.ActiveState{
			"domain":      artifacts.ActiveOnly,
			"route":       artifacts.ActiveOnly,
			"certificate": artifacts.ActiveOnly,
			"meta":        artifacts.ActiveOnly,
			"dns":         artifacts.ActiveOnly,
		}

		var activeArtifacts map[string][]artifacts.Artifact
		if exists {
			activeArtifacts, err = artifacts.CollectArtifactsByType(cfg.OutDir, activeSelectors)
			if err != nil {
				return fmt.Errorf("report: active artifacts: %w", err)
			}
		}

		activeDomains := artifactValues(activeArtifacts["domain"])
		activeRoutes := artifactValues(activeArtifacts["route"])
		activeCerts := artifactValues(activeArtifacts["certificate"])
		activeMeta := artifactValues(activeArtifacts["meta"])
		activeDNSRecords, err := parseDNSArtifacts(activeArtifacts["dns"])
		if err != nil {
			return fmt.Errorf("report: active dns artifacts: %w", err)
		}

		active = activeData{
			RawDomains: artifactRawValues(activeArtifacts["domain"]),
			RawRoutes:  artifactRawValues(activeArtifacts["route"]),
			RawDNS:     formatDNSRecords(activeDNSRecords),
			Meta:       activeMeta,
		}
		active.Domains = buildDomainStats(activeDomains)
		active.Routes = buildRouteStats(activeRoutes)
		active.DNS = buildDNSStats(activeDNSRecords)
		active.Certificates = buildCertStats(activeCerts)
		active.Highlights = buildHighlights(active.Domains, active.Routes, active.Certificates)
	}

	domainStats := buildDomainStats(domains)
	routeStats := buildRouteStats(routes)
	certStats := buildCertStats(certs)

	data := reportData{
		Target:      cfg.Target,
		OutDir:      cfg.OutDir,
		GeneratedAt: time.Now().Format(time.RFC3339),
		Overview: overviewStats{
			TotalArtifacts:        domainStats.Total + routeStats.Total + certStats.Total,
			UniqueDomains:         domainStats.Unique,
			UniqueHosts:           routeStats.UniqueHosts,
			UniqueCertificates:    certStats.Unique,
			SecureRoutesPercent:   routeStats.SecurePercentage,
			InsecureRoutesPercent: 100 - routeStats.SecurePercentage,
		},
		Domains:      domainStats,
		Routes:       routeStats,
		Certificates: certStats,
		Meta:         meta,
		Highlights:   buildHighlights(domainStats, routeStats, certStats),
		ActiveMode:   cfg.Active,
		Active:       active,
	}

	reportPath := filepath.Join(cfg.OutDir, "report.html")
	if err := ctx.Err(); err != nil {
		return err
	}

	f, err := os.Create(reportPath)
	if err != nil {
		return fmt.Errorf("report: create %q: %w", reportPath, err)
	}
	defer func() {
		_ = f.Close()
	}()

	if err := reportTmpl.Execute(f, data); err != nil {
		return fmt.Errorf("report: render: %w", err)
	}
	return nil
}

type countItem struct {
	Name  string
	Count int
}

type domainStats struct {
	Total             int
	Unique            int
	UniqueRegistrable int
	AverageLabels     float64
	TopRegistrable    []countItem
	LabelHistogram    []countItem
	TopTLDs           []countItem
	WildcardCount     int
	Interesting       []string
}

type routeStats struct {
	Total             int
	UniqueHosts       int
	UniqueSchemes     int
	SecurePercentage  float64
	TopHosts          []countItem
	SchemeHistogram   []countItem
	DepthHistogram    []countItem
	AveragePathDepth  float64
	InsecureHosts     []countItem
	InsecureHostTotal int
	TopPorts          []countItem
	InterestingPaths  []string
	NonStandardPorts  []string
}

type certStats struct {
	Total             int
	Unique            int
	UniqueRegistrable int
	UniqueIssuers     int
	Expired           int
	ExpiringSoon      int
	SoonThresholdDays int
	NextExpiration    string
	LatestExpiration  string
	TopRegistrable    []countItem
	TopIssuers        []countItem
	ExpiringSoonList  []string
	ExpiredList       []string
}

type overviewStats struct {
	TotalArtifacts        int
	UniqueDomains         int
	UniqueHosts           int
	UniqueCertificates    int
	SecureRoutesPercent   float64
	InsecureRoutesPercent float64
}

type reportData struct {
	Target       string
	OutDir       string
	GeneratedAt  string
	Overview     overviewStats
	Domains      domainStats
	Routes       routeStats
	Certificates certStats
	Meta         []string
	Highlights   []string
	ActiveMode   bool
	Active       activeData
}

type activeData struct {
	Domains      domainStats
	Routes       routeStats
	Certificates certStats
	DNS          dnsStats
	Meta         []string
	RawDomains   []string
	RawRoutes    []string
	RawDNS       []string
	Highlights   []string
}

type dnsStats struct {
	Total       int
	UniqueHosts int
	RecordTypes []countItem
}

type dnsRecord struct {
	Host  string   `json:"host,omitempty"`
	Type  string   `json:"type,omitempty"`
	Value string   `json:"value,omitempty"`
	Raw   string   `json:"raw,omitempty"`
	PTR   []string `json:"ptr,omitempty"`
}

const (
	topN               = 10
	certExpirySoonDays = 30
	maxInterestingRows = 10
)

var certTimeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

var ansiSequence = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

var reportTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"hasData":    func(items []countItem) bool { return len(items) > 0 },
	"hasStrings": func(items []string) bool { return len(items) > 0 },
	"limit":      func(items []string, n int) []string { return limitStrings(items, n) },
}).Parse(reportTemplate))

var (
	interestingDomainKeywords = []string{
		"admin", "portal", "intranet", "vpn", "dev", "test", "stage", "staging", "qa", "beta", "login", "sso", "auth", "api", "secure", "internal", "manage", "ops", "billing", "payments",
	}
	interestingRouteKeywords = []string{
		"admin", "login", "portal", "debug", "backup", "dev", "test", "stage", "config", "console", "manage", "git", "jenkins", "api", "token", "sso", "callback",
	}
)

func artifactValues(list []artifacts.Artifact) []string {
	if len(list) == 0 {
		return nil
	}
	values := make([]string, 0, len(list))
	for _, artifact := range list {
		value := cleanReportText(artifact.Value)
		if value == "" {
			continue
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func artifactRawValues(list []artifacts.Artifact) []string {
	if len(list) == 0 {
		return nil
	}
	values := make([]string, 0, len(list))
	for _, artifact := range list {
		candidates := make([]string, 0, 1)
		if artifact.Metadata != nil {
			switch raw := artifact.Metadata["raw"].(type) {
			case string:
				candidates = append(candidates, raw)
			case []string:
				candidates = append(candidates, raw...)
			case []any:
				for _, entry := range raw {
					if s, ok := entry.(string); ok {
						candidates = append(candidates, s)
					}
				}
			}
		}
		if len(candidates) == 0 {
			candidates = append(candidates, artifact.Value)
		}
		for _, candidate := range candidates {
			candidate = cleanReportText(candidate)
			if candidate == "" {
				continue
			}
			values = append(values, candidate)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return values
}

func parseDNSArtifacts(list []artifacts.Artifact) ([]dnsRecord, error) {
	if len(list) == 0 {
		return nil, nil
	}
	records := make([]dnsRecord, 0, len(list))
	for _, artifact := range list {
		value := strings.TrimSpace(artifact.Value)
		if value == "" {
			continue
		}
		var record dnsRecord
		if err := json.Unmarshal([]byte(value), &record); err != nil {
			return nil, fmt.Errorf("report: decode dns record: %w", err)
		}
		if record.Raw == "" {
			record.Raw = value
		}
		records = append(records, record)
	}
	if len(records) == 0 {
		return nil, nil
	}
	return records, nil
}

func formatDNSRecords(records []dnsRecord) []string {
	if len(records) == 0 {
		return nil
	}
	formatted := make([]string, 0, len(records))
	for _, record := range records {
		host := strings.TrimSpace(record.Host)
		recordType := strings.TrimSpace(record.Type)
		value := strings.TrimSpace(record.Value)
		raw := strings.TrimSpace(record.Raw)
		var display string
		var extra string
		if recordType == "" {
			extra = summarizeDNSRaw(raw)
		}
		if host != "" && recordType != "" {
			display = fmt.Sprintf("%s [%s]", host, recordType)
			if value != "" {
				display += " " + value
			}
		} else if host != "" {
			display = host
			if value != "" {
				display = fmt.Sprintf("%s %s", display, value)
			}
			if extra != "" {
				display = fmt.Sprintf("%s %s", display, extra)
			}
		} else if raw != "" {
			if extra != "" {
				display = extra
			} else {
				display = raw
			}
		} else {
			continue
		}
		if len(record.PTR) > 0 {
			display = fmt.Sprintf("%s (PTR: %s)", display, strings.Join(record.PTR, ", "))
		}
		cleaned := cleanReportText(display)
		if cleaned == "" {
			continue
		}
		formatted = append(formatted, cleaned)
	}
	return formatted
}

func summarizeDNSRaw(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "{") {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		return ""
	}
	type entry struct {
		key   string
		label string
	}
	var parts []string
	collect := func(values any) []string {
		switch v := values.(type) {
		case string:
			if s := strings.TrimSpace(v); s != "" {
				return []string{s}
			}
		case []any:
			items := make([]string, 0, len(v))
			for _, item := range v {
				s := strings.TrimSpace(fmt.Sprint(item))
				if s != "" {
					items = append(items, s)
				}
			}
			if len(items) > 0 {
				return items
			}
		}
		return nil
	}
	for _, item := range []entry{{"a", "A"}, {"aaaa", "AAAA"}, {"cname", "CNAME"}, {"mx", "MX"}, {"ns", "NS"}, {"txt", "TXT"}, {"ptr", "PTR"}, {"srv", "SRV"}, {"caa", "CAA"}} {
		if values, ok := payload[item.key]; ok {
			entries := collect(values)
			if len(entries) == 0 {
				continue
			}
			parts = append(parts, fmt.Sprintf("[%s] %s", item.label, strings.Join(entries, ", ")))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "; ")
}

func buildDomainStats(domains []string) domainStats {
	stats := domainStats{}
	if len(domains) == 0 {
		return stats
	}
	registrableCounts := make(map[string]int)
	labelHistogram := make(map[string]int)
	tldCounts := make(map[string]int)
	uniqueDomains := make(map[string]struct{})
	uniqueRegistrable := make(map[string]struct{})
	interesting := make(map[string]struct{})
	var totalLabels int
	for _, raw := range domains {
		d := strings.TrimSpace(raw)
		if d == "" {
			continue
		}
		lowered := strings.ToLower(d)
		stats.Total++
		uniqueDomains[lowered] = struct{}{}
		if strings.HasPrefix(strings.TrimSpace(raw), "*.") {
			stats.WildcardCount++
		}
		registrable := registrableDomain(d)
		if registrable != "" {
			uniqueRegistrable[registrable] = struct{}{}
			registrableCounts[registrable]++
		}
		if suffix, _ := publicsuffix.PublicSuffix(lowered); suffix != "" {
			tldCounts[suffix]++
		} else {
			parts := strings.Split(lowered, ".")
			if len(parts) > 0 {
				tldCounts[parts[len(parts)-1]]++
			}
		}
		levels := strings.Count(lowered, ".") + 1
		labelKey := fmt.Sprintf("%d niveles", levels)
		labelHistogram[labelKey]++
		totalLabels += levels
		for _, keyword := range interestingDomainKeywords {
			if strings.Contains(lowered, keyword) {
				interesting[lowered] = struct{}{}
				break
			}
		}
	}
	stats.TopRegistrable = topItems(registrableCounts, topN)
	stats.LabelHistogram = topItems(labelHistogram, len(labelHistogram))
	stats.TopTLDs = topItems(tldCounts, topN)
	stats.Unique = len(uniqueDomains)
	stats.UniqueRegistrable = len(uniqueRegistrable)
	if len(interesting) > 0 {
		stats.Interesting = sortedStringsWithLimit(interesting, maxInterestingRows)
	}
	if stats.Total > 0 {
		stats.AverageLabels = float64(totalLabels) / float64(stats.Total)
	}
	return stats
}

func buildDNSStats(records []dnsRecord) dnsStats {
	stats := dnsStats{}
	if len(records) == 0 {
		return stats
	}
	typeCounts := make(map[string]int)
	seenHosts := make(map[string]struct{})
	for _, record := range records {
		trimmedRaw := strings.TrimSpace(record.Raw)
		host := strings.TrimSpace(record.Host)
		if host == "" && trimmedRaw == "" {
			continue
		}
		stats.Total++
		candidate := host
		if candidate == "" {
			candidate = trimmedRaw
			if idx := strings.IndexAny(candidate, " \t"); idx != -1 {
				candidate = candidate[:idx]
			}
		}
		if normalized := netutil.NormalizeDomain(candidate); normalized != "" {
			seenHosts[normalized] = struct{}{}
		}
		recordType := strings.TrimSpace(record.Type)
		if recordType == "" && trimmedRaw != "" {
			if strings.HasPrefix(trimmedRaw, "{") {
				if summary := summarizeDNSRaw(trimmedRaw); summary != "" {
					for _, part := range strings.Split(summary, "; ") {
						if idx := strings.Index(part, "]"); idx > 0 {
							label := strings.Trim(part[1:idx], " ")
							if label != "" {
								typeCounts[label]++
							}
						}
					}
				}
				continue
			}
			if start := strings.Index(trimmedRaw, "["); start >= 0 {
				if end := strings.Index(trimmedRaw[start+1:], "]"); end >= 0 {
					end += start + 1
					recordType = strings.TrimSpace(trimmedRaw[start+1 : end])
				}
			}
		}
		if recordType != "" {
			typeCounts[recordType]++
		}
	}
	stats.UniqueHosts = len(seenHosts)
	stats.RecordTypes = topItems(typeCounts, topN)
	return stats
}

func cleanReportText(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = ansiSequence.ReplaceAllString(value, "")
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	if strings.Contains(value, "\n") {
		value = strings.ReplaceAll(value, "\n", " ")
	}
	fields := strings.Fields(value)
	if len(fields) == 0 {
		return ""
	}
	return strings.Join(fields, " ")
}

func buildCertStats(certsLines []string) certStats {
	return buildCertStatsAt(certsLines, time.Now())
}

func buildCertStatsAt(certsLines []string, now time.Time) certStats {
	stats := certStats{SoonThresholdDays: certExpirySoonDays}
	if len(certsLines) == 0 {
		return stats
	}
	registrableCounts := make(map[string]int)
	issuerCounts := make(map[string]int)
	uniqueCerts := make(map[string]struct{})
	uniqueRegistrable := make(map[string]struct{})
	uniqueIssuers := make(map[string]struct{})
	expiringSoon := make(map[string]struct{})
	expired := make(map[string]struct{})
	var nextExpiration time.Time
	var latestExpiration time.Time
	for _, raw := range certsLines {
		record, err := certs.Parse(raw)
		if err != nil {
			continue
		}
		stats.Total++
		key := record.Key()
		if key == "" {
			key = strings.TrimSpace(strings.ToLower(raw))
		}
		uniqueCerts[key] = struct{}{}
		issuer := strings.TrimSpace(record.Issuer)
		if issuer != "" {
			issuerCounts[issuer]++
			uniqueIssuers[strings.ToLower(issuer)] = struct{}{}
		}
		for _, name := range record.AllNames() {
			registrable := registrableDomain(name)
			if registrable == "" {
				continue
			}
			uniqueRegistrable[registrable] = struct{}{}
			registrableCounts[registrable]++
		}
		if expiry := parseCertTime(record.NotAfter); !expiry.IsZero() {
			displayName := certDisplayName(record)
			if expiry.Before(now) {
				stats.Expired++
				if displayName != "" {
					expired[fmt.Sprintf("%s (venció %s)", displayName, expiry.Format("2006-01-02"))] = struct{}{}
				}
				continue
			}
			if expiry.Sub(now) <= certExpirySoonWindow() {
				stats.ExpiringSoon++
				if displayName != "" {
					expiringSoon[fmt.Sprintf("%s (vence %s)", displayName, expiry.Format("2006-01-02"))] = struct{}{}
				}
			}
			if nextExpiration.IsZero() || expiry.Before(nextExpiration) {
				nextExpiration = expiry
			}
			if latestExpiration.IsZero() || expiry.After(latestExpiration) {
				latestExpiration = expiry
			}
		}
	}
	stats.TopRegistrable = topItems(registrableCounts, topN)
	stats.TopIssuers = topItems(issuerCounts, topN)
	stats.Unique = len(uniqueCerts)
	stats.UniqueRegistrable = len(uniqueRegistrable)
	stats.UniqueIssuers = len(uniqueIssuers)
	if len(expiringSoon) > 0 {
		stats.ExpiringSoonList = sortedStringsWithLimit(expiringSoon, maxInterestingRows)
	}
	if len(expired) > 0 {
		stats.ExpiredList = sortedStringsWithLimit(expired, maxInterestingRows)
	}
	if !nextExpiration.IsZero() {
		stats.NextExpiration = nextExpiration.Format("2006-01-02")
	}
	if !latestExpiration.IsZero() {
		stats.LatestExpiration = latestExpiration.Format("2006-01-02")
	}
	return stats
}

func buildRouteStats(routes []string) routeStats {
	stats := routeStats{}
	if len(routes) == 0 {
		return stats
	}
	hostCounts := make(map[string]int)
	schemeHistogram := make(map[string]int)
	depthHistogram := make(map[string]int)
	insecureHostCounts := make(map[string]int)
	portCounts := make(map[string]int)
	interestingPaths := make(map[string]struct{})
	nonStandard := make(map[string]struct{})
	var totalDepth int
	uniqueHosts := make(map[string]struct{})
	httpsCount := 0
	for _, raw := range routes {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		fields := strings.Fields(trimmed)
		candidate := trimmed
		if len(fields) > 0 {
			candidate = fields[0]
		}
		u, err := url.Parse(candidate)
		if err != nil {
			continue
		}
		stats.Total++
		host := strings.TrimSpace(u.Host)
		if host == "" {
			host = "(sin host)"
		}
		loweredHost := strings.ToLower(host)
		hostCounts[loweredHost]++
		uniqueHosts[loweredHost] = struct{}{}
		rawScheme := strings.ToLower(u.Scheme)
		scheme := rawScheme
		if scheme == "" {
			scheme = "(vacío)"
		}
		schemeHistogram[scheme]++
		if rawScheme == "https" {
			httpsCount++
		} else if rawScheme != "" {
			hostname := strings.ToLower(u.Hostname())
			if hostname != "" {
				insecureHostCounts[hostname]++
			}
		}
		path := strings.Trim(u.Path, "/")
		depth := 0
		if path != "" {
			depth = len(strings.Split(path, "/"))
		}
		depthKey := fmt.Sprintf("%d segmentos", depth)
		depthHistogram[depthKey]++
		totalDepth += depth
		port := u.Port()
		if port == "" {
			if def := defaultPortForScheme(rawScheme); def != "" {
				port = def
			}
		}
		displayPort := port
		if displayPort == "" {
			displayPort = "(sin puerto)"
		}
		portCounts[displayPort]++
		if port != "" && isNonStandardPort(rawScheme, port) {
			endpointScheme := rawScheme
			if endpointScheme == "" {
				endpointScheme = scheme
			}
			endpoint := fmt.Sprintf("%s://%s", endpointScheme, host)
			nonStandard[strings.ToLower(endpoint)] = struct{}{}
		}
		loweredCandidate := strings.ToLower(candidate)
		for _, keyword := range interestingRouteKeywords {
			if strings.Contains(loweredCandidate, keyword) {
				normalized := candidate
				if u.Scheme != "" && u.Host != "" {
					normalized = u.Scheme + "://" + u.Host + u.Path
					if u.RawQuery != "" {
						normalized += "?" + u.RawQuery
					}
				} else if normalized == "" {
					normalized = fmt.Sprintf("%s://%s", rawScheme, host)
				}
				interestingPaths[normalized] = struct{}{}
				break
			}
		}
	}
	stats.TopHosts = topItems(hostCounts, topN)
	stats.SchemeHistogram = topItems(schemeHistogram, len(schemeHistogram))
	stats.DepthHistogram = topItems(depthHistogram, len(depthHistogram))
	stats.AveragePathDepth = float64(totalDepth)
	stats.UniqueHosts = len(uniqueHosts)
	stats.UniqueSchemes = len(schemeHistogram)
	if len(insecureHostCounts) > 0 {
		stats.InsecureHosts = topItems(insecureHostCounts, topN)
		stats.InsecureHostTotal = len(insecureHostCounts)
	}
	if len(portCounts) > 0 {
		stats.TopPorts = topItems(portCounts, len(portCounts))
	}
	if len(interestingPaths) > 0 {
		stats.InterestingPaths = sortedStringsWithLimit(interestingPaths, maxInterestingRows)
	}
	if len(nonStandard) > 0 {
		stats.NonStandardPorts = sortedStringsWithLimit(nonStandard, maxInterestingRows)
	}
	if stats.Total > 0 {
		stats.AveragePathDepth = stats.AveragePathDepth / float64(stats.Total)
		stats.SecurePercentage = (float64(httpsCount) / float64(stats.Total)) * 100
	}
	return stats
}

func registrableDomain(domain string) string {
	trimmed := strings.TrimSpace(domain)
	if trimmed == "" {
		return ""
	}
	cleaned := strings.ToLower(strings.TrimSuffix(trimmed, "."))
	cleaned = strings.TrimPrefix(cleaned, "*.")
	if cleaned == "" {
		return ""
	}
	registrable, err := publicsuffix.EffectiveTLDPlusOne(cleaned)
	if err != nil {
		return cleaned
	}
	return strings.ToLower(registrable)
}

func topItems(counts map[string]int, n int) []countItem {
	if len(counts) == 0 || n == 0 {
		return nil
	}
	items := make([]countItem, 0, len(counts))
	for name, count := range counts {
		items = append(items, countItem{Name: name, Count: count})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Count == items[j].Count {
			return items[i].Name < items[j].Name
		}
		return items[i].Count > items[j].Count
	})
	if n > len(items) {
		n = len(items)
	}
	return items[:n]
}

func parseCertTime(value string) time.Time {
	value = strings.TrimSpace(value)
	if value == "" {
		return time.Time{}
	}
	for _, layout := range certTimeLayouts {
		if t, err := time.Parse(layout, value); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func certExpirySoonWindow() time.Duration {
	return time.Duration(certExpirySoonDays) * 24 * time.Hour
}

func sortedStringsWithLimit(m map[string]struct{}, limit int) []string {
	out := make([]string, 0, len(m))
	for value := range m {
		out = append(out, value)
	}
	sort.Strings(out)
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func defaultPortForScheme(scheme string) string {
	switch scheme {
	case "http":
		return "80"
	case "https":
		return "443"
	case "ssh":
		return "22"
	case "ftp":
		return "21"
	case "rdp":
		return "3389"
	}
	return ""
}

func isNonStandardPort(scheme, port string) bool {
	if scheme == "" || port == "" {
		return false
	}
	def := defaultPortForScheme(scheme)
	if def == "" {
		return false
	}
	return port != def
}

func certDisplayName(record certs.Record) string {
	if record.CommonName != "" {
		return record.CommonName
	}
	if len(record.DNSNames) > 0 {
		return record.DNSNames[0]
	}
	if record.Subject != "" {
		return record.Subject
	}
	return ""
}

func limitStrings(values []string, max int) []string {
	if max <= 0 || len(values) <= max {
		return values
	}
	return values[:max]
}

func buildHighlights(domains domainStats, routes routeStats, certs certStats) []string {
	var highlights []string
	if routes.SecurePercentage < 100 {
		if len(routes.InsecureHosts) > 0 {
			count := routes.InsecureHostTotal
			verb := "exponen"
			noun := "hosts"
			if count == 1 {
				verb = "expone"
				noun = "host"
			}
			highlights = append(highlights, fmt.Sprintf("%d %s %s servicios sin HTTPS (por ejemplo %s)", count, noun, verb, routes.InsecureHosts[0].Name))
		} else {
			highlights = append(highlights, fmt.Sprintf("%.1f%% de las rutas carecen de HTTPS", 100-routes.SecurePercentage))
		}
	}
	if len(routes.NonStandardPorts) > 0 {
		highlights = append(highlights, fmt.Sprintf("Servicios en puertos no estándar detectados: %s", strings.Join(limitStrings(routes.NonStandardPorts, 3), ", ")))
	}
	if len(routes.InterestingPaths) > 0 {
		highlights = append(highlights, fmt.Sprintf("Endpoints potencialmente sensibles encontrados (ej. %s)", routes.InterestingPaths[0]))
	}
	if len(domains.Interesting) > 0 {
		highlights = append(highlights, fmt.Sprintf("Dominios que sugieren entornos sensibles: %s", strings.Join(limitStrings(domains.Interesting, 3), ", ")))
	}
	if certs.Expired > 0 {
		if len(certs.ExpiredList) > 0 {
			highlights = append(highlights, fmt.Sprintf("%d certificados vencidos, incluyendo %s", certs.Expired, certs.ExpiredList[0]))
		} else {
			highlights = append(highlights, fmt.Sprintf("%d certificados vencidos detectados", certs.Expired))
		}
	}
	if certs.ExpiringSoon > 0 {
		if len(certs.ExpiringSoonList) > 0 {
			highlights = append(highlights, fmt.Sprintf("%d certificados por expirar pronto (ej. %s)", certs.ExpiringSoon, certs.ExpiringSoonList[0]))
		} else {
			highlights = append(highlights, fmt.Sprintf("%d certificados por expirar en %d días", certs.ExpiringSoon, certExpirySoonDays))
		}
	}
	return highlights
}

const reportTemplate = `<!DOCTYPE html>
<html lang="es">
<head>
        <meta charset="utf-8">
        <title>Informe passive-rec</title>
        <style>
                :root {
                        color-scheme: light;
                }
                * {
                        box-sizing: border-box;
                }
                body {
                        font-family: "Inter", "Segoe UI", Arial, sans-serif;
                        margin: 0;
                        background: #0f172a;
                        color: #0f172a;
                }
                a {
                        color: inherit;
                }
                .layout {
                        max-width: 1200px;
                        margin: 0 auto;
                        padding: 2.5rem 2rem 3rem;
                }
                .masthead {
                        display: flex;
                        flex-wrap: wrap;
                        justify-content: space-between;
                        align-items: flex-end;
                        gap: 1.5rem;
                        padding: 2rem 2.5rem;
                        background: linear-gradient(135deg, #1e293b 0%, #0f172a 55%, #1e293b 100%);
                        border-radius: 20px;
                        box-shadow: 0 25px 45px rgba(15, 23, 42, 0.35);
                        color: #f8fafc;
                }
                .masthead h1 {
                        margin: 0 0 0.35rem;
                        font-size: 2rem;
                        letter-spacing: 0.03em;
                }
                .masthead p {
                        margin: 0.35rem 0;
                        color: #e2e8f0;
                }
                .masthead strong {
                        color: #facc15;
                }
                .meta-line {
                        font-size: 0.9rem;
                        color: #cbd5f5;
                }
                .badge-set {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 0.5rem;
                        align-items: center;
                }
                .tag {
                        display: inline-flex;
                        align-items: center;
                        gap: 0.4rem;
                        font-size: 0.85rem;
                        font-weight: 600;
                        text-transform: uppercase;
                        letter-spacing: 0.08em;
                        border-radius: 999px;
                        padding: 0.35rem 0.9rem;
                }
                .tag-product {
                        background: rgba(248, 250, 252, 0.2);
                        color: #f8fafc;
                        border: 1px solid rgba(248, 250, 252, 0.3);
                }
                .tag-passive {
                        background: rgba(16, 185, 129, 0.18);
                        color: #bbf7d0;
                        border: 1px solid rgba(52, 211, 153, 0.45);
                }
                .tag-active {
                        background: rgba(248, 113, 113, 0.18);
                        color: #fecaca;
                        border: 1px solid rgba(248, 113, 113, 0.45);
                }
                .quick-nav {
                        display: flex;
                        flex-wrap: wrap;
                        gap: 0.75rem;
                        margin: 1.75rem 0 2.25rem;
                        padding: 0.85rem 1.25rem;
                        background: rgba(15, 23, 42, 0.85);
                        border-radius: 999px;
                        box-shadow: 0 20px 35px rgba(15, 23, 42, 0.28);
                }
                .quick-nav a {
                        color: #f8fafc;
                        text-decoration: none;
                        font-size: 0.9rem;
                        font-weight: 500;
                        letter-spacing: 0.02em;
                        padding: 0.35rem 0.75rem;
                        border-radius: 999px;
                        transition: background 0.2s ease;
                }
                .quick-nav a:hover {
                        background: rgba(248, 250, 252, 0.15);
                }
                main {
                        display: flex;
                        flex-direction: column;
                        gap: 2rem;
                }
                section.panel {
                        background: #ffffff;
                        border-radius: 20px;
                        padding: 1.75rem 2rem;
                        box-shadow: 0 25px 45px rgba(15, 23, 42, 0.12);
                }
                section.panel h2 {
                        margin-top: 0;
                        font-size: 1.55rem;
                        letter-spacing: 0.02em;
                        color: #0f172a;
                }
                section.panel h3 {
                        color: #1e293b;
                }
                section.panel h4 {
                        color: #334155;
                }
                section.panel p {
                        color: #334155;
                        line-height: 1.6;
                }
                ul {
                        padding-left: 1.5rem;
                }
                .muted {
                        color: #94a3b8;
                }
                .cards {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
                        gap: 1.15rem;
                        margin-top: 1.35rem;
                }
                .card {
                        position: relative;
                        border-radius: 16px;
                        padding: 1.5rem;
                        background: linear-gradient(165deg, rgba(15, 23, 42, 0.92) 0%, rgba(30, 41, 59, 0.85) 100%);
                        color: #f8fafc;
                        box-shadow: 0 20px 35px rgba(15, 23, 42, 0.18);
                        border: 1px solid rgba(148, 163, 184, 0.2);
                }
                .card h3 {
                        margin: 0;
                        font-size: 0.95rem;
                        text-transform: uppercase;
                        letter-spacing: 0.08em;
                        color: #cbd5f5;
                }
                .metric {
                        font-size: 2.6rem;
                        font-weight: 600;
                        margin: 0.5rem 0 0.35rem;
                        color: #f8fafc;
                }
                .subtext {
                        font-size: 0.95rem;
                        color: #475569;
                        margin-top: 0.35rem;
                }
                .card .subtext {
                        color: #cbd5f5;
                }
                .grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                        gap: 1.5rem;
                }
                table {
                        border-collapse: collapse;
                        width: 100%;
                        margin-top: 1.25rem;
                        background: #ffffff;
                        border-radius: 14px;
                        overflow: hidden;
                        box-shadow: 0 12px 25px rgba(15, 23, 42, 0.08);
                }
                th,
                td {
                        padding: 0.85rem 1rem;
                        text-align: left;
                        color: #1f2937;
                }
                th {
                        background: #0f172a;
                        color: #f8fafc;
                        text-transform: uppercase;
                        font-size: 0.78rem;
                        letter-spacing: 0.08em;
                }
                tr:nth-child(even) td {
                        background: #f8fafc;
                }
                .insights {
                        list-style: none;
                        padding: 0;
                        margin: 1.25rem 0 0;
                        display: grid;
                        gap: 0.85rem;
                }
                .insights li {
                        display: flex;
                        gap: 0.75rem;
                        align-items: flex-start;
                        padding: 0.95rem 1.1rem;
                        border: 1px solid #e2e8f0;
                        border-radius: 14px;
                        background: linear-gradient(145deg, #ffffff 0%, #f8fafc 100%);
                        box-shadow: 0 18px 35px rgba(15, 23, 42, 0.08);
                }
                .insight-tag {
                        display: inline-flex;
                        align-items: center;
                        padding: 0.35rem 0.75rem;
                        font-size: 0.7rem;
                        font-weight: 700;
                        text-transform: uppercase;
                        letter-spacing: 0.08em;
                        border-radius: 999px;
                        background: #dbeafe;
                        color: #1d4ed8;
                        flex-shrink: 0;
                }
                .insight-text {
                        color: #1f2937;
                }
                footer {
                        margin-top: 3rem;
                        text-align: center;
                        color: #cbd5f5;
                        font-size: 0.85rem;
                        line-height: 1.6;
                }
                @media (max-width: 768px) {
                        .layout {
                                padding: 1.75rem 1.25rem 2.5rem;
                        }
                        .masthead {
                                padding: 1.5rem;
                                border-radius: 18px;
                        }
                        .quick-nav {
                                border-radius: 1.25rem;
                        }
                        section.panel {
                                padding: 1.5rem;
                        }
                        .cards {
                                grid-template-columns: 1fr;
                        }
                }
        </style>
</head>
<body>
        <div class="layout">
                <header class="masthead">
                        <div>
                                <h1>Informe de passive-rec</h1>
                                <p>Evaluación de superficie para <strong>{{.Target}}</strong></p>
                                <p class="meta-line">Generado: {{.GeneratedAt}} · Directorio de salida: {{.OutDir}}</p>
                        </div>
                        <div class="badge-set">
                                <span class="tag tag-product">passive-rec</span>
                                {{if .ActiveMode}}
                                <span class="tag tag-active">Modo mixto (pasivo + activo)</span>
                                {{else}}
                                <span class="tag tag-passive">Modo pasivo</span>
                                {{end}}
                        </div>
                </header>
                <nav class="quick-nav">
                        <a href="#resumen">Resumen ejecutivo</a>
                        <a href="#hallazgos">Hallazgos clave</a>
                        <a href="#dominios">Dominios</a>
                        <a href="#rutas">Rutas</a>
                        <a href="#certificados">Certificados</a>
                        <a href="#meta">Meta</a>
                        {{if .ActiveMode}}<a href="#activo">Recolección activa</a>{{end}}
                </nav>
                <main>
                        <section id="resumen" class="panel">
                                <h2>Resumen ejecutivo</h2>
                                <p class="subtext">Vista rápida de los hallazgos más relevantes para priorizar acciones.</p>
                                <div class="cards">
                                        <div class="card">
                                                <h3>Total de artefactos procesados</h3>
                                                <p class="metric">{{.Overview.TotalArtifacts}}</p>
                                                <p class="subtext">Entradas combinadas de dominios, rutas y certificados.</p>
                                        </div>
                                        <div class="card">
                                                <h3>Dominios únicos</h3>
                                                <p class="metric">{{.Overview.UniqueDomains}}</p>
                                                <p class="subtext">Incluye {{.Domains.UniqueRegistrable}} dominios registrables distintos.</p>
                                        </div>
                                        <div class="card">
                                                <h3>Hosts únicos en rutas</h3>
                                                <p class="metric">{{.Overview.UniqueHosts}}</p>
                                                <p class="subtext">Cobertura sobre {{.Routes.UniqueSchemes}} esquemas de servicio; {{printf "%.1f" .Overview.InsecureRoutesPercent}}% sin HTTPS.</p>
                                        </div>
                                        <div class="card">
                                                <h3>Certificados únicos</h3>
                                                <p class="metric">{{.Overview.UniqueCertificates}}</p>
                                                <p class="subtext">{{.Certificates.ExpiringSoon}} por expirar en {{.Certificates.SoonThresholdDays}} días.</p>
                                        </div>
                                </div>
                        </section>

                        <section id="hallazgos" class="panel">
                                <h2>Hallazgos clave</h2>
                                {{if hasStrings .Highlights}}
                                <ul class="insights">
                                        {{range .Highlights}}
                                        <li><span class="insight-tag">Hallazgo</span><span class="insight-text">{{.}}</span></li>
                                        {{end}}
                                </ul>
                                {{else}}
                                <p class="muted">Sin hallazgos destacados generados automáticamente.</p>
                                {{end}}
                        </section>

                        <section id="dominios" class="panel">
                                <h2>Dominios</h2>
                                <div class="grid">
                                        <div>
                                                <p><strong>Total de dominios recolectados:</strong> {{.Domains.Total}}</p>
                                                <p><strong>Dominios únicos:</strong> {{.Domains.Unique}} (registrables: {{.Domains.UniqueRegistrable}})</p>
                                                <p><strong>Niveles promedio por dominio:</strong> {{printf "%.2f" .Domains.AverageLabels}}</p>
                                                <p><strong>Dominios comodín detectados:</strong> {{.Domains.WildcardCount}}</p>
                                        </div>
                                        <div>
                                                <p class="subtext">Los dominios con mayor frecuencia ayudan a identificar activos críticos y oportunidades para consolidar cobertura.</p>
                                        </div>
                                </div>
                                {{if hasData .Domains.TopRegistrable}}
                                <h3>Top dominios registrables</h3>
                                <table>
                                        <tr><th>Dominio</th><th>Conteo</th></tr>
                                        {{range .Domains.TopRegistrable}}
                                        <tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>
                                        {{end}}
                                </table>
                                {{end}}
                                {{if hasData .Domains.LabelHistogram}}
                                <h3>Distribución por niveles</h3>
                                <table>
                                        <tr><th>Niveles</th><th>Conteo</th></tr>
                                        {{range .Domains.LabelHistogram}}
                                        <tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>
                                        {{end}}
                                </table>
                                {{end}}
                                {{if hasData .Domains.TopTLDs}}
                                <h3>Top TLDs observados</h3>
                                <table>
                                        <tr><th>TLD</th><th>Conteo</th></tr>
                                        {{range .Domains.TopTLDs}}
                                        <tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>
                                        {{end}}
                                </table>
                                {{end}}
                                {{if hasStrings .Domains.Interesting}}
                                <h3>Dominios potencialmente sensibles</h3>
                                <ul>
                                        {{range .Domains.Interesting}}
                                        <li>{{.}}</li>
                                        {{end}}
                                </ul>
                                {{end}}
                        </section>

                        <section id="rutas" class="panel">
                                <h2>Rutas</h2>
                                <div class="grid">
                                        <div>
                                                <p><strong>Total de rutas:</strong> {{.Routes.Total}}</p>
                                                <p><strong>Hosts únicos observados:</strong> {{.Routes.UniqueHosts}}</p>
                                                <p><strong>Profundidad promedio de ruta:</strong> {{printf "%.2f" .Routes.AveragePathDepth}}</p>
                                                <p><strong>Uso de HTTPS:</strong> {{printf "%.1f" .Routes.SecurePercentage}}% de las rutas.</p>
                                        </div>
                                        <div>
                                                <p class="subtext">Las rutas identificadas permiten priorizar revisiones de servicios y detectar activos expuestos.</p>
                                                <p><strong>Hosts con protocolos inseguros:</strong> {{.Routes.InsecureHostTotal}}</p>
                                        </div>
                                </div>
                                {{if hasData .Routes.SchemeHistogram}}
                                <h3>Esquemas por volumen</h3>
                                <table>
                                        <tr><th>Esquema</th><th>Conteo</th></tr>
                                        {{range .Routes.SchemeHistogram}}
                                        <tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>
                                        {{end}}
                                </table>
                                {{end}}
                                {{if hasData .Routes.DepthHistogram}}
                                <h3>Profundidad de rutas</h3>
                                <table>
                                        <tr><th>Segmentos</th><th>Conteo</th></tr>
                                        {{range .Routes.DepthHistogram}}
                                        <tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>
                                        {{end}}
                                </table>
                                {{end}}
                                {{if hasData .Routes.InsecureHosts}}
                                <h3>Hosts con tráfico no cifrado</h3>
                                <table>
                                        <tr><th>Host</th><th>Rutas</th></tr>
                                        {{range .Routes.InsecureHosts}}
                                        <tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>
                                        {{end}}
                                </table>
                                {{end}}
                                {{if hasData .Routes.TopPorts}}
                                <h3>Puertos observados</h3>
                                <table>
                                        <tr><th>Puerto</th><th>Conteo</th></tr>
                                        {{range .Routes.TopPorts}}
                                        <tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>
                                        {{end}}
                                </table>
                                {{end}}
                                {{if hasStrings .Routes.NonStandardPorts}}
                                <h3>Servicios en puertos no estándar</h3>
                                <ul>
                                        {{range .Routes.NonStandardPorts}}
                                        <li>{{.}}</li>
                                        {{end}}
                                </ul>
                                {{end}}
                                {{if hasStrings .Routes.InterestingPaths}}
                                <h3>Endpoints con palabras clave sensibles</h3>
                                <ul>
                                        {{range .Routes.InterestingPaths}}
                                        <li>{{.}}</li>
                                        {{end}}
                                </ul>
                                {{end}}
                        </section>

                        <section id="certificados" class="panel">
                                <h2>Certificados</h2>
                                <div class="grid">
                                        <div>
                                                <p><strong>Certificados únicos:</strong> {{.Certificates.Unique}}</p>
                                                <p><strong>Emisores únicos:</strong> {{.Certificates.UniqueIssuers}}</p>
                                                <p><strong>Certificados vencidos:</strong> {{.Certificates.Expired}}</p>
                                                <p><strong>Dominios registrables únicos:</strong> {{.Certificates.UniqueRegistrable}}</p>
                                        </div>
                                        <div>
                                                <p class="subtext">Los certificados permiten medir la higiene criptográfica y planificar renovaciones.</p>
                                                <p><strong>Certificados por expirar ({{.Certificates.SoonThresholdDays}} días):</strong> {{.Certificates.ExpiringSoon}}</p>
                                                {{if .Certificates.NextExpiration}}
                                                <p><strong>Próximo vencimiento:</strong> {{.Certificates.NextExpiration}}</p>
                                                {{end}}
                                                {{if .Certificates.LatestExpiration}}
                                                <p><strong>Último vencimiento observado:</strong> {{.Certificates.LatestExpiration}}</p>
                                                {{end}}
                                        </div>
                                </div>
                                {{if hasData .Certificates.TopRegistrable}}
                                <h3>Top dominios registrables asociados</h3>
                                <table>
                                        <tr><th>Dominio</th><th>Conteo</th></tr>
                                        {{range .Certificates.TopRegistrable}}
                                        <tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>
                                        {{end}}
                                </table>
                                {{end}}
                                {{if hasData .Certificates.TopIssuers}}
                                <h3>Top emisores</h3>
                                <table>
                                        <tr><th>Emisor</th><th>Conteo</th></tr>
                                        {{range .Certificates.TopIssuers}}
                                        <tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>
                                        {{end}}
                                </table>
                                {{end}}
                                {{if hasStrings .Certificates.ExpiredList}}
                                <h3>Certificados vencidos destacados</h3>
                                <ul>
                                        {{range .Certificates.ExpiredList}}
                                        <li>{{.}}</li>
                                        {{end}}
                                </ul>
                                {{end}}
                                {{if hasStrings .Certificates.ExpiringSoonList}}
                                <h3>Certificados próximos a expirar</h3>
                                <ul>
                                        {{range .Certificates.ExpiringSoonList}}
                                        <li>{{.}}</li>
                                        {{end}}
                                </ul>
                                {{end}}
                        </section>

                        <section id="meta" class="panel">
                                <h2>Meta</h2>
                                {{if .Meta}}
                                <ul>
                                        {{range .Meta}}
                                        <li>{{.}}</li>
                                        {{end}}
                                </ul>
                                {{else}}
                                <p class="muted">Sin entradas meta.</p>
                                {{end}}
                        </section>
                        {{if .ActiveMode}}
                        <section id="activo" class="panel">
                                <h2>Resultados de recolección activa</h2>
                                <p class="subtext">Hallazgos derivados de validaciones activas contra los activos descubiertos.</p>
                                {{if or (gt .Active.Domains.Total 0) (gt .Active.Routes.Total 0) (gt .Active.DNS.Total 0) (gt (len .Active.Meta) 0) (gt .Active.Certificates.Total 0)}}
                                <div class="cards">
                                        <div class="card">
                                                <h3>Dominios activos detectados</h3>
                                                <p class="metric">{{.Active.Domains.Total}}</p>
                                                <p class="subtext">{{.Active.Domains.Unique}} dominios únicos observados.</p>
                                        </div>
                                        <div class="card">
                                                <h3>Rutas activas evaluadas</h3>
                                                <p class="metric">{{.Active.Routes.Total}}</p>
                                                <p class="subtext">{{.Active.Routes.UniqueHosts}} hosts; {{printf "%.1f" .Active.Routes.SecurePercentage}}% con HTTPS.</p>
                                        </div>
                                        <div class="card">
                                                <h3>Registros DNS activos</h3>
                                                <p class="metric">{{.Active.DNS.Total}}</p>
                                                <p class="subtext">{{.Active.DNS.UniqueHosts}} dominios con registros.</p>
                                        </div>
                                        <div class="card">
                                                <h3>Certificados activos observados</h3>
                                                <p class="metric">{{.Active.Certificates.Total}}</p>
                                                <p class="subtext">{{.Active.Certificates.Unique}} certificados únicos.</p>
                                        </div>
                                </div>
                                {{if hasStrings .Active.Highlights}}
                                <h3>Hallazgos activos clave</h3>
                                <ul class="insights">
                                        {{range .Active.Highlights}}
                                        <li><span class="insight-tag">Hallazgo</span><span class="insight-text">{{.}}</span></li>
                                        {{end}}
                                </ul>
                                {{else}}
                                <p class="muted">Sin hallazgos activos destacados.</p>
                                {{end}}
                                <h3>Dominios detectados</h3>
                                {{if hasStrings .Active.RawDomains}}
                                <ul>
                                        {{range (limit .Active.RawDomains 25)}}
                                        <li>{{.}}</li>
                                        {{end}}
                                </ul>
                                {{if gt (len .Active.RawDomains) 25}}
                                <p class="muted">Mostrando 25 de {{len .Active.RawDomains}} dominios activos.</p>
                                {{end}}
                                {{else}}
                                <p class="muted">No se recolectaron dominios activos.</p>
                                {{end}}
                                <h3>Registros DNS</h3>
                                {{if hasStrings .Active.RawDNS}}
                                <ul>
                                        {{range (limit .Active.RawDNS 25)}}
                                        <li>{{.}}</li>
                                        {{end}}
                                </ul>
                                {{if gt (len .Active.RawDNS) 25}}
                                <p class="muted">Mostrando 25 de {{len .Active.RawDNS}} registros DNS.</p>
                                {{end}}
                                {{else}}
                                <p class="muted">No se registraron resultados DNS activos.</p>
                                {{end}}
                                {{if hasData .Active.DNS.RecordTypes}}
                                <h4>Tipos de registros observados</h4>
                                <table class="metrics">
                                        <tr><th>Tipo</th><th>Conteo</th></tr>
                                        {{range .Active.DNS.RecordTypes}}
                                        <tr><td>{{.Name}}</td><td>{{.Count}}</td></tr>
                                        {{end}}
                                </table>
                                {{end}}
                                <h3>Rutas activas</h3>
                                {{if hasStrings .Active.RawRoutes}}
                                <ul>
                                        {{range (limit .Active.RawRoutes 25)}}
                                        <li>{{.}}</li>
                                        {{end}}
                                </ul>
                                {{if gt (len .Active.RawRoutes) 25}}
                                <p class="muted">Mostrando 25 de {{len .Active.RawRoutes}} rutas activas.</p>
                                {{end}}
                                {{else}}
                                <p class="muted">No se registraron rutas activas.</p>
                                {{end}}
                                <h3>Meta activa</h3>
                                {{if hasStrings .Active.Meta}}
                                <ul>
                                        {{range .Active.Meta}}
                                        <li>{{.}}</li>
                                        {{end}}
                                </ul>
                                {{else}}
                                <p class="muted">Sin entradas meta activas.</p>
                                {{end}}
                                {{if gt .Active.Certificates.Total 0}}
                                <h3>Certificados (activos)</h3>
                                <p><strong>Total recolectado:</strong> {{.Active.Certificates.Total}} (únicos: {{.Active.Certificates.Unique}})</p>
                                {{if hasStrings .Active.Certificates.ExpiredList}}
                                <h4>Certificados vencidos detectados</h4>
                                <ul>
                                        {{range .Active.Certificates.ExpiredList}}
                                        <li>{{.}}</li>
                                        {{end}}
                                </ul>
                                {{end}}
                                {{if hasStrings .Active.Certificates.ExpiringSoonList}}
                                <h4>Certificados por expirar pronto</h4>
                                <ul>
                                        {{range .Active.Certificates.ExpiringSoonList}}
                                        <li>{{.}}</li>
                                        {{end}}
                                </ul>
                                {{end}}
                                {{end}}
                                {{else}}
                                <p class="muted">No se recolectaron hallazgos activos.</p>
                                {{end}}
                        </section>
                        {{end}}
                </main>
                <footer>
                        <p>Este informe resume artefactos recolectados de manera pasiva{{if .ActiveMode}} y activa{{end}}. Revise los hallazgos y priorice acciones según el apetito de riesgo de la organización.</p>
                </footer>
        </div>
</body>
</html>`
