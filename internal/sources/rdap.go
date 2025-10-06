package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strings"
	"time"

	"passive-rec/internal/netutil"
)

type rdapResponse struct {
	LDHName     string       `json:"ldhName"`
	UnicodeName string       `json:"unicodeName"`
	Status      []string     `json:"status"`
	Nameservers []rdapObject `json:"nameservers"`
	Events      []rdapEvent  `json:"events"`
	Entities    []rdapEntity `json:"entities"`
}

type rdapObject struct {
	LDHName     string `json:"ldhName"`
	UnicodeName string `json:"unicodeName"`
}

type rdapEvent struct {
	Action string `json:"eventAction"`
	Date   string `json:"eventDate"`
}

type rdapEntity struct {
	Roles      []string       `json:"roles"`
	Handle     string         `json:"handle"`
	VCardArray []any          `json:"vcardArray"`
	PublicIDs  []rdapPublicID `json:"publicIds"`
}

type rdapPublicID struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

type rdapSummary struct {
	Domain          string
	Registrar       string
	RegistrarID     string
	Statuses        []string
	Nameservers     []string
	Created         string
	Updated         string
	Expires         string
	RDAPLastUpdated string
}

var (
	rdapBaseURL    = "https://rdap.org/domain/"
	rdapHTTPClient = &http.Client{Timeout: 30 * time.Second}
)

// RDAP queries the public RDAP service for the supplied target and emits summary
// information and raw metadata lines into the sink.
func RDAP(ctx context.Context, target string, out chan<- string) error {
	domain := normalizeRDAPDomain(target)
	if domain == "" {
		out <- "meta: rdap skipped (invalid domain)"
		return nil
	}

	endpoint, err := buildRDAPURL(domain)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "passive-rec/rdap")

	client := rdapHTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		out <- fmt.Sprintf("meta: rdap request failed: %v", err)
		return err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		// proceed
	case http.StatusNotFound:
		out <- fmt.Sprintf("meta: rdap no data for %s (HTTP 404)", domain)
		return nil
	default:
		out <- fmt.Sprintf("meta: rdap lookup failed for %s: HTTP %d", domain, resp.StatusCode)
		return fmt.Errorf("rdap: unexpected status %d", resp.StatusCode)
	}

	var payload rdapResponse
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		out <- fmt.Sprintf("meta: rdap decode failed: %v", err)
		return err
	}

	summary := summarizeRDAP(&payload, domain)
	emitRDAPSummary(out, summary)

	return nil
}

func normalizeRDAPDomain(target string) string {
	domain := netutil.NormalizeDomain(target)
	if domain != "" {
		return domain
	}

	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return ""
	}

	host := trimmed
	if strings.Contains(host, "://") {
		if u, err := url.Parse(host); err == nil {
			if h := u.Hostname(); h != "" {
				host = h
			} else if u.Host != "" {
				host = u.Host
			}
		}
	}

	sanitized := strings.ReplaceAll(host, "*", "")
	sanitized = strings.Trim(sanitized, ".")
	for strings.Contains(sanitized, "..") {
		sanitized = strings.ReplaceAll(sanitized, "..", ".")
	}

	if sanitized == "" {
		return ""
	}

	return netutil.NormalizeDomain(sanitized)
}

func buildRDAPURL(domain string) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("rdap: empty domain")
	}
	base, err := url.Parse(rdapBaseURL)
	if err != nil {
		return "", err
	}
	ref := &url.URL{Path: path.Join(base.Path, url.PathEscape(domain))}
	u := base.ResolveReference(ref)
	return u.String(), nil
}

func summarizeRDAP(resp *rdapResponse, fallbackDomain string) rdapSummary {
	if resp == nil {
		return rdapSummary{}
	}
	sum := rdapSummary{}
	if resp.LDHName != "" {
		sum.Domain = strings.ToLower(resp.LDHName)
	} else if resp.UnicodeName != "" {
		sum.Domain = strings.ToLower(resp.UnicodeName)
	} else {
		sum.Domain = strings.ToLower(fallbackDomain)
	}

	sum.Statuses = dedupeStrings(resp.Status)

	for _, ns := range resp.Nameservers {
		name := ns.UnicodeName
		if name == "" {
			name = ns.LDHName
		}
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if netutil.NormalizeDomain(name) == "" {
			continue
		}
		sum.Nameservers = appendUnique(sum.Nameservers, name)
	}

	for _, event := range resp.Events {
		date := strings.TrimSpace(event.Date)
		if date == "" {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(event.Action)) {
		case "registration":
			if sum.Created == "" {
				sum.Created = date
			}
		case "expiration":
			if sum.Expires == "" {
				sum.Expires = date
			}
		case "last changed":
			if sum.Updated == "" {
				sum.Updated = date
			}
		case "last update of rdap database":
			if sum.RDAPLastUpdated == "" {
				sum.RDAPLastUpdated = date
			}
		}
	}

	if registrar, registrarID := extractRegistrar(resp.Entities); registrar != "" {
		sum.Registrar = registrar
		sum.RegistrarID = registrarID
	}

	sortStrings(sum.Statuses)
	sortStrings(sum.Nameservers)

	return sum
}

func extractRegistrar(entities []rdapEntity) (string, string) {
	for _, entity := range entities {
		if !hasRole(entity.Roles, "registrar") {
			continue
		}
		name := extractEntityName(entity)
		id := extractRegistrarID(entity)
		return name, id
	}
	return "", ""
}

func extractEntityName(entity rdapEntity) string {
	if len(entity.VCardArray) < 2 {
		return strings.TrimSpace(entity.Handle)
	}
	entries, ok := entity.VCardArray[1].([]any)
	if !ok {
		return strings.TrimSpace(entity.Handle)
	}
	for _, entry := range entries {
		parts, ok := entry.([]any)
		if !ok || len(parts) < 4 {
			continue
		}
		name, _ := parts[0].(string)
		if name != "fn" {
			continue
		}
		value := parts[len(parts)-1]
		if text, ok := value.(string); ok {
			trimmed := strings.TrimSpace(text)
			if trimmed != "" {
				return trimmed
			}
		}
	}
	return strings.TrimSpace(entity.Handle)
}

func extractRegistrarID(entity rdapEntity) string {
	for _, id := range entity.PublicIDs {
		if strings.EqualFold(strings.TrimSpace(id.Type), "iana registrar id") {
			return strings.TrimSpace(id.Identifier)
		}
	}
	return ""
}

func emitRDAPSummary(out chan<- string, summary rdapSummary) {
	var metaLines, rawLines []string
	if summary.Domain != "" {
		metaLines = append(metaLines, fmt.Sprintf("meta: rdap domain: %s", summary.Domain))
		rawLines = append(rawLines, fmt.Sprintf("rdap: domain=%s", summary.Domain))
	}
	registrarLine := buildRegistrarLine(summary.Registrar, summary.RegistrarID)
	if registrarLine != "" {
		metaLines = append(metaLines, fmt.Sprintf("meta: rdap registrar: %s", registrarLine))
		rawLines = append(rawLines, fmt.Sprintf("rdap: registrar=%s", registrarLine))
	}
	for _, status := range summary.Statuses {
		metaLines = append(metaLines, fmt.Sprintf("meta: rdap status: %s", status))
		rawLines = append(rawLines, fmt.Sprintf("rdap: status=%s", status))
	}
	for _, ns := range summary.Nameservers {
		metaLines = append(metaLines, fmt.Sprintf("meta: rdap nameserver: %s", ns))
		rawLines = append(rawLines, fmt.Sprintf("rdap: nameserver=%s", ns))
	}
	if summary.Created != "" {
		metaLines = append(metaLines, fmt.Sprintf("meta: rdap created: %s", summary.Created))
		rawLines = append(rawLines, fmt.Sprintf("rdap: event=registration %s", summary.Created))
	}
	if summary.Updated != "" {
		metaLines = append(metaLines, fmt.Sprintf("meta: rdap last changed: %s", summary.Updated))
		rawLines = append(rawLines, fmt.Sprintf("rdap: event=last changed %s", summary.Updated))
	}
	if summary.Expires != "" {
		metaLines = append(metaLines, fmt.Sprintf("meta: rdap expiration: %s", summary.Expires))
		rawLines = append(rawLines, fmt.Sprintf("rdap: event=expiration %s", summary.Expires))
	}
	if summary.RDAPLastUpdated != "" {
		metaLines = append(metaLines, fmt.Sprintf("meta: rdap last update of database: %s", summary.RDAPLastUpdated))
		rawLines = append(rawLines, fmt.Sprintf("rdap: event=last update of rdap database %s", summary.RDAPLastUpdated))
	}
	for _, line := range metaLines {
		out <- line
	}
	for _, line := range rawLines {
		out <- line
	}
}

func buildRegistrarLine(name, id string) string {
	name = strings.TrimSpace(name)
	id = strings.TrimSpace(id)
	if name == "" {
		return id
	}
	if id == "" {
		return name
	}
	return fmt.Sprintf("%s (IANA %s)", name, id)
}

func dedupeStrings(values []string) []string {
	var result []string
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		result = appendUnique(result, trimmed)
	}
	return result
}

func appendUnique(list []string, value string) []string {
	if value == "" {
		return list
	}
	for _, existing := range list {
		if strings.EqualFold(existing, value) {
			return list
		}
	}
	return append(list, value)
}

func hasRole(roles []string, want string) bool {
	for _, role := range roles {
		if strings.EqualFold(strings.TrimSpace(role), want) {
			return true
		}
	}
	return false
}

func sortStrings(values []string) {
	if len(values) <= 1 {
		return
	}
	sort.SliceStable(values, func(i, j int) bool {
		li := strings.ToLower(values[i])
		lj := strings.ToLower(values[j])
		if li == lj {
			return values[i] < values[j]
		}
		return li < lj
	})
}
