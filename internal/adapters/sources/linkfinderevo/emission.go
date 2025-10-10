package linkfinderevo

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"passive-rec/internal/adapters/routes"
)

func emitFindings(reports []report, out chan<- string) (emissionResult, error) {
	result := emissionResult{Categories: make(map[routes.Category][]string)}
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

	for _, r := range reports {
		for _, ep := range r.Endpoints {
			link := strings.TrimSpace(ep.Link)
			if link == "" {
				continue
			}
			// Emit ruta base siempre
			if _, seen := seenRoutes[link]; !seen {
				addOnce(seenRoutes, link, "active: ", &result.Routes)
			}

			cls := classifyEndpoint(link)
			if cls.isJS {
				addOnce(seenJS, link, "active: js: ", &result.JS)
			}
			if cls.isHTML || cls.isImage {
				// marca que es HTML para potenciales consumidores
				addOnce(seenHTML, link, "active: html: ", nil)
				if cls.isHTML {
					addOnce(seenHTMLTargets, link, "", &result.HTML)
				}
				if cls.isImage {
					addOnce(seenImages, link, "", &result.Images)
				}
			}
			if len(cls.categories) > 0 {
				for _, cat := range cls.categories {
					prefix, ok := categoryPrefixes[cat]
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
			if cls.undetected {
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

func emitGFFindings(agg *gfAggregate, out chan<- string) error {
	if agg == nil {
		return nil
	}

	findings := agg.results()
	if len(findings) == 0 {
		return nil
	}

	for _, finding := range findings {
		data, err := json.Marshal(finding)
		if err != nil {
			return fmt.Errorf("marshal gf payload: %w", err)
		}
		emit(out, "active: gffinding: "+string(data))
	}

	return nil
}

func emit(out chan<- string, msg string) {
	if out == nil || msg == "" {
		return
	}
	out <- msg
}
