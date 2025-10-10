// Package linkfinderevo coordina la ejecución de GoLinkfinderEVO sobre artefactos activos.
package linkfinderevo

import (
	"sort"
	"strings"
	"sync"
)

type endpoint struct {
	Link    string `json:"Link"`
	Context string `json:"Context"`
	Line    int    `json:"Line"`
}

type report struct {
	Resource  string     `json:"Resource"`
	Endpoints []endpoint `json:"Endpoints"`
}

type metadata struct {
	GeneratedAt    string `json:"GeneratedAt"`
	TotalResources int    `json:"TotalResources"`
	TotalEndpoints int    `json:"TotalEndpoints"`
}

type payload struct {
	Meta      metadata `json:"meta"`
	Resources []report `json:"resources"`
}

type aggregate struct {
	mu        sync.Mutex
	order     []string
	resources map[string]*aggregateResource
}

type aggregateResource struct {
	name      string
	order     []string
	endpoints map[string]endpoint
}

type gfAggregate struct {
	mu       sync.Mutex
	findings map[gfFindingKey]*gfFinding
}

type gfFindingKey struct {
	Resource string
	Line     int
	Evidence string
}

type gfFinding struct {
	Resource string
	Line     int
	Evidence string
	Context  string
	Rules    map[string]struct{}
}

type gfFindingResult struct {
	Resource string   `json:"resource,omitempty"`
	Line     int      `json:"line,omitempty"`
	Evidence string   `json:"evidence"`
	Context  string   `json:"context,omitempty"`
	Rules    []string `json:"rules,omitempty"`
}

func newAggregate() *aggregate {
	return &aggregate{resources: make(map[string]*aggregateResource)}
}

func newGFAggregate() *gfAggregate {
	return &gfAggregate{findings: make(map[gfFindingKey]*gfFinding)}
}

func (agg *aggregate) add(resource string, ep endpoint) {
	resource = strings.TrimSpace(resource)
	if resource == "" {
		return
	}
	ep.Link = cleanEndpointLink(ep.Link)
	if ep.Link == "" {
		return
	}

	agg.mu.Lock()
	defer agg.mu.Unlock()

	res, ok := agg.resources[resource]
	if !ok {
		res = &aggregateResource{
			name:      resource,
			endpoints: make(map[string]endpoint),
		}
		agg.resources[resource] = res
		agg.order = append(agg.order, resource)
	}

	if _, exists := res.endpoints[ep.Link]; exists {
		return
	}

	res.endpoints[ep.Link] = ep
	res.order = append(res.order, ep.Link)
}

func (agg *aggregate) reports() []report {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	reports := make([]report, 0, len(agg.order))
	for _, name := range agg.order {
		res := agg.resources[name]
		if res == nil || len(res.order) == 0 {
			continue
		}
		r := report{Resource: name, Endpoints: make([]endpoint, 0, len(res.order))}
		for _, key := range res.order {
			if ep, ok := res.endpoints[key]; ok {
				r.Endpoints = append(r.Endpoints, ep)
			}
		}
		reports = append(reports, r)
	}
	return reports
}

func (agg *aggregate) endpointCount() int {
	agg.mu.Lock()
	defer agg.mu.Unlock()

	total := 0
	for _, res := range agg.resources {
		total += len(res.endpoints)
	}
	return total
}

func (agg *gfAggregate) add(resource string, line int, evidence string, context string, rules []string) {
	if agg == nil {
		return
	}
	resource = strings.TrimSpace(resource)
	evidence = strings.TrimSpace(evidence)
	if evidence == "" {
		return
	}

	key := gfFindingKey{Resource: resource, Line: line, Evidence: evidence}

	agg.mu.Lock()
	defer agg.mu.Unlock()

	entry, ok := agg.findings[key]
	if !ok {
		entry = &gfFinding{
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

func (agg *gfAggregate) results() []gfFindingResult {
	if agg == nil {
		return nil
	}

	agg.mu.Lock()
	defer agg.mu.Unlock()

	if len(agg.findings) == 0 {
		return nil
	}

	keys := make([]gfFindingKey, 0, len(agg.findings))
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

	results := make([]gfFindingResult, 0, len(keys))
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
		results = append(results, gfFindingResult{
			Resource: entry.Resource,
			Line:     entry.Line,
			Evidence: entry.Evidence,
			Context:  entry.Context,
			Rules:    rules,
		})
	}

	return results
}

func cleanEndpointLink(raw string) string {
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
