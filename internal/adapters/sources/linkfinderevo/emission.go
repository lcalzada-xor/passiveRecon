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
	seenCSS := make(map[string]struct{})
	seenPDF := make(map[string]struct{})
	seenDocs := make(map[string]struct{})
	seenFonts := make(map[string]struct{})
	seenVideos := make(map[string]struct{})
	seenArchives := make(map[string]struct{})
	seenXML := make(map[string]struct{})
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

			cls := classifyEndpoint(link)

			// Determinar tipo primario basado en clasificación
			emitAsRoute := false

			// Priorizar tipos más específicos sobre "route"
			switch {
			case cls.isJS:
				addOnce(seenJS, link, "active: js: ", &result.JS)
			case cls.isCSS:
				addOnce(seenCSS, link, "active: css: ", nil)
			case cls.isPDF:
				addOnce(seenPDF, link, "active: pdf: ", nil)
			case cls.isDoc:
				addOnce(seenDocs, link, "active: doc: ", nil)
			case cls.isFont:
				addOnce(seenFonts, link, "active: font: ", nil)
			case cls.isVideo:
				addOnce(seenVideos, link, "active: video: ", nil)
			case cls.isArchive:
				addOnce(seenArchives, link, "active: archive: ", nil)
			case cls.isXML:
				addOnce(seenXML, link, "active: xml: ", nil)
			case cls.isHTML:
				addOnce(seenHTML, link, "active: html: ", nil)
				addOnce(seenHTMLTargets, link, "", &result.HTML)
			case cls.isImage:
				addOnce(seenHTML, link, "active: html: ", nil) // legacy compatibility
				addOnce(seenImages, link, "", &result.Images)
			default:
				// Si no tiene tipo específico, emitir como route
				emitAsRoute = true
			}

			// Emitir ruta base si no tiene tipo específico
			if emitAsRoute {
				if _, seen := seenRoutes[link]; !seen {
					addOnce(seenRoutes, link, "active: ", &result.Routes)
				}
			}

			// Emitir categorías especializadas (API, WASM, Maps, etc.)
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
