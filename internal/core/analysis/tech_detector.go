package analysis

import (
	"path"
	"strings"
)

// detectTechnology analiza los artefactos para detectar tecnologías utilizadas.
func (a *Analyzer) detectTechnology() *TechStack {
	stack := &TechStack{
		JavaScript: []Technology{},
		CSS:        []Technology{},
		Frameworks: []Technology{},
		Libraries:  []Technology{},
		Languages:  []Technology{},
		Servers:    []Technology{},
		CMS:        []Technology{},
		CDN:        []Technology{},
		Analytics:  []Technology{},
		Deprecated: []Technology{},
		Confidence: "medium",
	}

	// Detectar JavaScript libraries y frameworks
	a.detectJavaScript(stack)

	// Detectar CSS frameworks
	a.detectCSS(stack)

	// Detectar CMS y plataformas
	a.detectCMS(stack)

	// Detectar CDN
	a.detectCDN(stack)

	// Detectar tecnologías obsoletas
	a.detectDeprecated(stack)

	// Detectar servidores web (de metadata de httpx)
	a.detectServers(stack)

	// Determinar confianza general
	if len(stack.JavaScript)+len(stack.CSS)+len(stack.Frameworks) >= 5 {
		stack.Confidence = "high"
	} else if len(stack.JavaScript)+len(stack.CSS)+len(stack.Frameworks) == 0 {
		stack.Confidence = "low"
	}

	return stack
}

// detectJavaScript detecta librerías y frameworks JavaScript.
func (a *Analyzer) detectJavaScript(stack *TechStack) {
	jsArtifacts := a.FilterBySubtype("resource", "javascript")

	detectedLibs := make(map[string]*Technology)

	for _, art := range jsArtifacts {
		value := strings.ToLower(art.Value)
		basename := strings.ToLower(path.Base(value))

		// jQuery
		if strings.Contains(basename, "jquery") {
			if _, exists := detectedLibs["jQuery"]; !exists {
				detectedLibs["jQuery"] = &Technology{
					Name:       "jQuery",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			} else {
				detectedLibs["jQuery"].Evidence = append(detectedLibs["jQuery"].Evidence, art.Value)
			}
		}

		// React
		if strings.Contains(basename, "react") {
			if _, exists := detectedLibs["React"]; !exists {
				detectedLibs["React"] = &Technology{
					Name:       "React",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			} else {
				detectedLibs["React"].Evidence = append(detectedLibs["React"].Evidence, art.Value)
			}
		}

		// Vue.js
		if strings.Contains(basename, "vue") {
			if _, exists := detectedLibs["Vue.js"]; !exists {
				detectedLibs["Vue.js"] = &Technology{
					Name:       "Vue.js",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			} else {
				detectedLibs["Vue.js"].Evidence = append(detectedLibs["Vue.js"].Evidence, art.Value)
			}
		}

		// Angular
		if strings.Contains(basename, "angular") {
			if _, exists := detectedLibs["Angular"]; !exists {
				detectedLibs["Angular"] = &Technology{
					Name:       "Angular",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			} else {
				detectedLibs["Angular"].Evidence = append(detectedLibs["Angular"].Evidence, art.Value)
			}
		}

		// Bootstrap JS
		if strings.Contains(basename, "bootstrap") {
			if _, exists := detectedLibs["Bootstrap"]; !exists {
				detectedLibs["Bootstrap"] = &Technology{
					Name:       "Bootstrap",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			} else {
				detectedLibs["Bootstrap"].Evidence = append(detectedLibs["Bootstrap"].Evidence, art.Value)
			}
		}

		// Lodash/Underscore
		if strings.Contains(basename, "lodash") || strings.Contains(basename, "underscore") {
			name := "Lodash"
			if strings.Contains(basename, "underscore") {
				name = "Underscore.js"
			}
			if _, exists := detectedLibs[name]; !exists {
				detectedLibs[name] = &Technology{
					Name:       name,
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			} else {
				detectedLibs[name].Evidence = append(detectedLibs[name].Evidence, art.Value)
			}
		}

		// Moment.js
		if strings.Contains(basename, "moment") {
			if _, exists := detectedLibs["Moment.js"]; !exists {
				detectedLibs["Moment.js"] = &Technology{
					Name:       "Moment.js",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			} else {
				detectedLibs["Moment.js"].Evidence = append(detectedLibs["Moment.js"].Evidence, art.Value)
			}
		}

		// Chart.js
		if strings.Contains(basename, "chart") {
			if _, exists := detectedLibs["Chart.js"]; !exists {
				detectedLibs["Chart.js"] = &Technology{
					Name:       "Chart.js",
					Evidence:   []string{art.Value},
					Confidence: "medium",
				}
			} else {
				detectedLibs["Chart.js"].Evidence = append(detectedLibs["Chart.js"].Evidence, art.Value)
			}
		}

		// D3.js
		if strings.Contains(basename, "d3") {
			if _, exists := detectedLibs["D3.js"]; !exists {
				detectedLibs["D3.js"] = &Technology{
					Name:       "D3.js",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			} else {
				detectedLibs["D3.js"].Evidence = append(detectedLibs["D3.js"].Evidence, art.Value)
			}
		}

		// Google Analytics
		if strings.Contains(value, "google-analytics") || strings.Contains(value, "gtag") || strings.Contains(value, "ga.js") {
			if _, exists := detectedLibs["Google Analytics"]; !exists {
				detectedLibs["Google Analytics"] = &Technology{
					Name:       "Google Analytics",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			}
		}
	}

	// Convertir map a slices
	for _, tech := range detectedLibs {
		// Limitar evidencia a los primeros 3 ejemplos
		if len(tech.Evidence) > 3 {
			tech.Evidence = tech.Evidence[:3]
		}

		// Categorizar
		if tech.Name == "React" || tech.Name == "Vue.js" || tech.Name == "Angular" {
			stack.Frameworks = append(stack.Frameworks, *tech)
		} else if tech.Name == "Google Analytics" {
			stack.Analytics = append(stack.Analytics, *tech)
		} else {
			stack.JavaScript = append(stack.JavaScript, *tech)
		}
	}
}

// detectCSS detecta frameworks CSS.
func (a *Analyzer) detectCSS(stack *TechStack) {
	cssArtifacts := a.FilterBySubtype("resource", "css")

	detectedCSS := make(map[string]*Technology)

	for _, art := range cssArtifacts {
		value := strings.ToLower(art.Value)
		basename := strings.ToLower(path.Base(value))

		// Bootstrap
		if strings.Contains(basename, "bootstrap") {
			if _, exists := detectedCSS["Bootstrap"]; !exists {
				detectedCSS["Bootstrap"] = &Technology{
					Name:       "Bootstrap",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			} else {
				detectedCSS["Bootstrap"].Evidence = append(detectedCSS["Bootstrap"].Evidence, art.Value)
			}
		}

		// Tailwind
		if strings.Contains(basename, "tailwind") {
			if _, exists := detectedCSS["Tailwind CSS"]; !exists {
				detectedCSS["Tailwind CSS"] = &Technology{
					Name:       "Tailwind CSS",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			} else {
				detectedCSS["Tailwind CSS"].Evidence = append(detectedCSS["Tailwind CSS"].Evidence, art.Value)
			}
		}

		// Foundation
		if strings.Contains(basename, "foundation") {
			if _, exists := detectedCSS["Foundation"]; !exists {
				detectedCSS["Foundation"] = &Technology{
					Name:       "Foundation",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			} else {
				detectedCSS["Foundation"].Evidence = append(detectedCSS["Foundation"].Evidence, art.Value)
			}
		}

		// Bulma
		if strings.Contains(basename, "bulma") {
			if _, exists := detectedCSS["Bulma"]; !exists {
				detectedCSS["Bulma"] = &Technology{
					Name:       "Bulma",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			} else {
				detectedCSS["Bulma"].Evidence = append(detectedCSS["Bulma"].Evidence, art.Value)
			}
		}

		// Font Awesome
		if strings.Contains(value, "font-awesome") || strings.Contains(value, "fontawesome") {
			if _, exists := detectedCSS["Font Awesome"]; !exists {
				detectedCSS["Font Awesome"] = &Technology{
					Name:       "Font Awesome",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			}
		}
	}

	// Convertir map a slice
	for _, tech := range detectedCSS {
		if len(tech.Evidence) > 3 {
			tech.Evidence = tech.Evidence[:3]
		}
		stack.CSS = append(stack.CSS, *tech)
	}
}

// detectCMS detecta CMS y plataformas.
func (a *Analyzer) detectCMS(stack *TechStack) {
	routes := a.FilterArtifacts("route")
	htmlPages := a.FilterBySubtype("resource", "html")

	allArtifacts := append(routes, htmlPages...)

	detectedCMS := make(map[string]*Technology)

	for _, art := range allArtifacts {
		value := strings.ToLower(art.Value)

		// WordPress
		if strings.Contains(value, "wp-content") || strings.Contains(value, "wp-includes") || strings.Contains(value, "wp-admin") {
			if _, exists := detectedCMS["WordPress"]; !exists {
				detectedCMS["WordPress"] = &Technology{
					Name:       "WordPress",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			}
		}

		// Drupal
		if strings.Contains(value, "/sites/default") || strings.Contains(value, "/modules/") || strings.Contains(value, "drupal") {
			if _, exists := detectedCMS["Drupal"]; !exists {
				detectedCMS["Drupal"] = &Technology{
					Name:       "Drupal",
					Evidence:   []string{art.Value},
					Confidence: "medium",
				}
			}
		}

		// Joomla
		if strings.Contains(value, "/components/com_") || strings.Contains(value, "joomla") {
			if _, exists := detectedCMS["Joomla"]; !exists {
				detectedCMS["Joomla"] = &Technology{
					Name:       "Joomla",
					Evidence:   []string{art.Value},
					Confidence: "medium",
				}
			}
		}

		// Shopify
		if strings.Contains(value, "shopify") || strings.Contains(value, "myshopify.com") {
			if _, exists := detectedCMS["Shopify"]; !exists {
				detectedCMS["Shopify"] = &Technology{
					Name:       "Shopify",
					Evidence:   []string{art.Value},
					Confidence: "high",
				}
			}
		}
	}

	for _, tech := range detectedCMS {
		if len(tech.Evidence) > 3 {
			tech.Evidence = tech.Evidence[:3]
		}
		stack.CMS = append(stack.CMS, *tech)
	}
}

// detectCDN detecta uso de CDN.
func (a *Analyzer) detectCDN(stack *TechStack) {
	routes := a.FilterArtifacts("route")

	detectedCDN := make(map[string]*Technology)

	cdnPatterns := map[string]string{
		"cloudflare":  "Cloudflare",
		"akamai":      "Akamai",
		"fastly":      "Fastly",
		"cdn.":        "Generic CDN",
		"cloudfront":  "Amazon CloudFront",
		"googleapis":  "Google Cloud CDN",
		"jsdelivr":    "jsDelivr",
		"unpkg":       "unpkg",
		"cdnjs":       "cdnjs",
	}

	for _, art := range routes {
		value := strings.ToLower(art.Value)

		for pattern, name := range cdnPatterns {
			if strings.Contains(value, pattern) {
				if _, exists := detectedCDN[name]; !exists {
					detectedCDN[name] = &Technology{
						Name:       name,
						Evidence:   []string{art.Value},
						Confidence: "high",
					}
				}
			}
		}
	}

	for _, tech := range detectedCDN {
		if len(tech.Evidence) > 3 {
			tech.Evidence = tech.Evidence[:3]
		}
		stack.CDN = append(stack.CDN, *tech)
	}
}

// detectDeprecated detecta tecnologías obsoletas.
func (a *Analyzer) detectDeprecated(stack *TechStack) {
	allArtifacts := a.artifacts

	for _, art := range allArtifacts {
		value := strings.ToLower(art.Value)

		// Flash (SWF)
		if strings.HasSuffix(value, ".swf") {
			tech := Technology{
				Name:       "Adobe Flash",
				Evidence:   []string{art.Value},
				Confidence: "high",
				Deprecated: true,
				Risk:       "critical",
			}
			stack.Deprecated = append(stack.Deprecated, tech)
			break // Solo una vez
		}

		// Silverlight
		if strings.Contains(value, "silverlight") {
			tech := Technology{
				Name:       "Microsoft Silverlight",
				Evidence:   []string{art.Value},
				Confidence: "high",
				Deprecated: true,
				Risk:       "high",
			}
			stack.Deprecated = append(stack.Deprecated, tech)
			break
		}

		// IE6/IE7 specific CSS
		if strings.Contains(value, "ie6.css") || strings.Contains(value, "ie7.css") {
			tech := Technology{
				Name:       "Internet Explorer 6/7 Support",
				Evidence:   []string{art.Value},
				Confidence: "high",
				Deprecated: true,
				Risk:       "medium",
			}
			stack.Deprecated = append(stack.Deprecated, tech)
			break
		}
	}
}

// detectServers detecta servidores web desde metadata.
func (a *Analyzer) detectServers(stack *TechStack) {
	// Buscar en metadata de artifacts activos (httpx típicamente agrega server headers)
	activeArtifacts := a.FilterActive()

	detectedServers := make(map[string]*Technology)

	for _, art := range activeArtifacts {
		if server := GetArtifactMetadataString(art, "server"); server != "" {
			serverLower := strings.ToLower(server)

			// Normalizar nombres
			name := server
			confidence := "medium"

			if strings.Contains(serverLower, "nginx") {
				name = "Nginx"
				confidence = "high"
			} else if strings.Contains(serverLower, "apache") {
				name = "Apache"
				confidence = "high"
			} else if strings.Contains(serverLower, "iis") {
				name = "Microsoft IIS"
				confidence = "high"
			} else if strings.Contains(serverLower, "cloudflare") {
				name = "Cloudflare"
				confidence = "high"
			} else if strings.Contains(serverLower, "litespeed") {
				name = "LiteSpeed"
				confidence = "high"
			}

			if _, exists := detectedServers[name]; !exists {
				detectedServers[name] = &Technology{
					Name:       name,
					Version:    extractVersion(server),
					Evidence:   []string{server},
					Confidence: confidence,
				}
			}
		}
	}

	for _, tech := range detectedServers {
		stack.Servers = append(stack.Servers, *tech)
	}
}

// extractVersion intenta extraer la versión de un string.
func extractVersion(input string) string {
	parts := strings.Split(input, "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return ""
}
