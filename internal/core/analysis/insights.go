package analysis

import (
	"fmt"
	"strings"
	"time"
)

// generateInsights genera insights inteligentes basados en el análisis.
func (a *Analyzer) generateInsights(report *Report) []Insight {
	insights := []Insight{}

	// Insights de dominio
	insights = append(insights, a.generateDomainInsights(report)...)

	// Insights de tecnología
	insights = append(insights, a.generateTechInsights(report)...)

	// Insights de seguridad
	insights = append(insights, a.generateSecurityInsights(report)...)

	// Insights de infraestructura
	insights = append(insights, a.generateInfrastructureInsights(report)...)

	// Insights de negocio
	insights = append(insights, a.generateBusinessInsights(report)...)

	return insights
}

// generateDomainInsights genera insights sobre el dominio.
func (a *Analyzer) generateDomainInsights(report *Report) []Insight {
	insights := []Insight{}

	if report.Infrastructure == nil {
		return insights
	}

	// Dominio próximo a expirar
	if report.Infrastructure.Expires != nil {
		daysUntilExpiration := int(time.Until(*report.Infrastructure.Expires).Hours() / 24)

		if daysUntilExpiration < 30 && daysUntilExpiration > 0 {
			insights = append(insights, Insight{
				Type:        "critical",
				Category:    "infrastructure",
				Title:       fmt.Sprintf("Domain Expires in %d Days", daysUntilExpiration),
				Description: fmt.Sprintf("The domain is set to expire on %s. Renew it immediately to avoid service disruption.", report.Infrastructure.Expires.Format("2006-01-02")),
				Priority:    1,
				Action:      "Renew domain registration immediately",
			})
		} else if daysUntilExpiration <= 0 {
			insights = append(insights, Insight{
				Type:        "critical",
				Category:    "infrastructure",
				Title:       "Domain Has Expired",
				Description: fmt.Sprintf("The domain expired on %s. Service disruption is imminent or already occurring.", report.Infrastructure.Expires.Format("2006-01-02")),
				Priority:    1,
				Action:      "Renew domain registration IMMEDIATELY",
			})
		} else if daysUntilExpiration < 90 {
			insights = append(insights, Insight{
				Type:        "warning",
				Category:    "infrastructure",
				Title:       fmt.Sprintf("Domain Expires in %d Days", daysUntilExpiration),
				Description: fmt.Sprintf("The domain will expire on %s. Consider renewing it soon.", report.Infrastructure.Expires.Format("2006-01-02")),
				Priority:    2,
				Action:      "Schedule domain renewal",
			})
		}
	}

	// Dominio antiguo (puede ser positivo)
	if report.Infrastructure.Registered != nil {
		ageYears := int(time.Since(*report.Infrastructure.Registered).Hours() / 24 / 365)
		if ageYears >= 20 {
			insights = append(insights, Insight{
				Type:        "info",
				Category:    "business",
				Title:       fmt.Sprintf("Established Domain (%d Years Old)", ageYears),
				Description: fmt.Sprintf("The domain was registered on %s, indicating a well-established online presence.", report.Infrastructure.Registered.Format("2006-01-02")),
				Priority:    4,
			})
		}
	}

	return insights
}

// generateTechInsights genera insights sobre tecnologías.
func (a *Analyzer) generateTechInsights(report *Report) []Insight {
	insights := []Insight{}

	if report.TechStack == nil {
		return insights
	}

	// Tecnologías obsoletas
	if len(report.TechStack.Deprecated) > 0 {
		var techNames []string
		for _, tech := range report.TechStack.Deprecated {
			techNames = append(techNames, tech.Name)
		}

		insights = append(insights, Insight{
			Type:        "critical",
			Category:    "technology",
			Title:       "Deprecated Technologies Detected",
			Description: fmt.Sprintf("The following deprecated technologies are in use: %s. These are no longer supported and pose security risks.", strings.Join(techNames, ", ")),
			Priority:    1,
			Evidence:    techNames,
			Action:      "Plan migration to modern alternatives",
		})
	}

	// jQuery detectado (muy común, pero info útil)
	for _, lib := range report.TechStack.JavaScript {
		if lib.Name == "jQuery" {
			insights = append(insights, Insight{
				Type:        "info",
				Category:    "technology",
				Title:       "jQuery Library Detected",
				Description: "The site uses jQuery, a popular JavaScript library. Ensure it's kept up-to-date for security patches.",
				Priority:    4,
				Action:      "Verify jQuery version is current",
			})
			break
		}
	}

	// Sin framework moderno detectado
	if len(report.TechStack.Frameworks) == 0 {
		insights = append(insights, Insight{
			Type:        "info",
			Category:    "technology",
			Title:       "No Modern Frontend Framework Detected",
			Description: "No modern frontend framework (React, Vue, Angular) was detected. The site may be using vanilla JavaScript or server-side rendering.",
			Priority:    5,
		})
	}

	return insights
}

// generateSecurityInsights genera insights de seguridad.
func (a *Analyzer) generateSecurityInsights(report *Report) []Insight {
	insights := []Insight{}

	if report.Security == nil {
		return insights
	}

	// Hallazgos críticos
	if report.Security.Critical > 0 {
		insights = append(insights, Insight{
			Type:        "critical",
			Category:    "security",
			Title:       fmt.Sprintf("%d Critical Security Findings", report.Security.Critical),
			Description: "Critical security issues were discovered that require immediate attention.",
			Priority:    1,
			Action:      "Review and remediate critical findings immediately",
		})
	}

	// Hallazgos altos
	if report.Security.High > 0 {
		insights = append(insights, Insight{
			Type:        "warning",
			Category:    "security",
			Title:       fmt.Sprintf("%d High-Severity Security Findings", report.Security.High),
			Description: "High-severity security issues were discovered that should be addressed promptly.",
			Priority:    2,
			Action:      "Review and remediate high-severity findings",
		})
	}

	// Hallazgos de GoLinkFinder
	if len(report.Security.GFFindings) > 0 {
		criticalGF := 0
		highGF := 0
		for _, gf := range report.Security.GFFindings {
			if gf.Severity == "critical" {
				criticalGF++
			} else if gf.Severity == "high" {
				highGF++
			}
		}

		if criticalGF > 0 || highGF > 0 {
			insights = append(insights, Insight{
				Type:        "warning",
				Category:    "security",
				Title:       "Sensitive Information Found in JavaScript",
				Description: fmt.Sprintf("GoLinkFinder detected %d potentially sensitive patterns in JavaScript files. Review these findings to ensure no secrets are exposed.", len(report.Security.GFFindings)),
				Priority:    2,
				Action:      "Audit JavaScript files for exposed secrets",
			})
		}
	}

	// Superficie de ataque
	if report.AttackSurface != nil {
		if report.AttackSurface.Level == "critical" || report.AttackSurface.Level == "high" {
			insights = append(insights, Insight{
				Type:        "warning",
				Category:    "security",
				Title:       fmt.Sprintf("Large Attack Surface (%s)", strings.ToUpper(report.AttackSurface.Level)),
				Description: fmt.Sprintf("The application has a %s attack surface with %d active endpoints and %d sensitive endpoints.", report.AttackSurface.Level, report.AttackSurface.ActiveEndpoints, len(report.AttackSurface.SensitiveEndpoints)),
				Priority:    2,
				Action:      "Review and minimize exposed endpoints",
			})
		}
	}

	return insights
}

// generateInfrastructureInsights genera insights de infraestructura.
func (a *Analyzer) generateInfrastructureInsights(report *Report) []Insight {
	insights := []Insight{}

	if report.Infrastructure == nil {
		return insights
	}

	// Proveedor de hosting detectado
	if report.Infrastructure.HostingProvider != "" {
		insights = append(insights, Insight{
			Type:        "info",
			Category:    "infrastructure",
			Title:       fmt.Sprintf("Hosting Provider: %s", report.Infrastructure.HostingProvider),
			Description: fmt.Sprintf("The site appears to be hosted by %s.", report.Infrastructure.HostingProvider),
			Priority:    5,
		})
	}

	// Proveedor de email detectado
	if report.Infrastructure.EmailProvider != "" {
		insights = append(insights, Insight{
			Type:        "info",
			Category:    "infrastructure",
			Title:       fmt.Sprintf("Email Provider: %s", report.Infrastructure.EmailProvider),
			Description: fmt.Sprintf("Email services are provided by %s.", report.Infrastructure.EmailProvider),
			Priority:    5,
		})
	}

	// Múltiples nameservers (buena práctica)
	if len(report.Infrastructure.Nameservers) >= 2 {
		insights = append(insights, Insight{
			Type:        "info",
			Category:    "infrastructure",
			Title:       "DNS Redundancy Configured",
			Description: fmt.Sprintf("The domain uses %d nameservers, providing redundancy for DNS resolution.", len(report.Infrastructure.Nameservers)),
			Priority:    5,
		})
	}

	return insights
}

// generateBusinessInsights genera insights de negocio.
func (a *Analyzer) generateBusinessInsights(report *Report) []Insight {
	insights := []Insight{}

	// Analizar contenido para detectar sector/negocio
	routes := a.FilterArtifacts("route")
	htmlPages := a.FilterBySubtype("resource", "html")

	businessKeywords := make(map[string]int)

	// Palabras clave por sector
	keywords := map[string][]string{
		"Gaming/Casino": {"salon", "juego", "poker", "lucky", "casino", "apuesta"},
		"E-commerce":    {"shop", "cart", "product", "checkout", "payment"},
		"Restaurant":    {"menu", "reserv", "book", "restaurant", "food"},
		"Corporate":     {"empresa", "grupo", "company", "about", "services"},
	}

	// Contar menciones
	for _, art := range append(routes, htmlPages...) {
		value := strings.ToLower(art.Value)
		for sector, keywordList := range keywords {
			for _, keyword := range keywordList {
				if strings.Contains(value, keyword) {
					businessKeywords[sector]++
					break
				}
			}
		}
	}

	// Determinar sector más probable
	maxCount := 0
	detectedSector := ""
	for sector, count := range businessKeywords {
		if count > maxCount {
			maxCount = count
			detectedSector = sector
		}
	}

	if detectedSector != "" && maxCount >= 2 {
		insights = append(insights, Insight{
			Type:        "info",
			Category:    "business",
			Title:       fmt.Sprintf("Business Sector: %s", detectedSector),
			Description: fmt.Sprintf("Based on content analysis, this appears to be a %s business.", detectedSector),
			Priority:    4,
		})
	}

	// Detectar si tiene formularios (contacto, etc.)
	hasContactForm := false
	for _, art := range routes {
		if strings.Contains(strings.ToLower(art.Value), "formulario") ||
			strings.Contains(strings.ToLower(art.Value), "form") ||
			strings.Contains(strings.ToLower(art.Value), "contacto") {
			hasContactForm = true
			break
		}
	}

	if hasContactForm {
		insights = append(insights, Insight{
			Type:        "recommendation",
			Category:    "business",
			Title:       "Contact Forms Detected",
			Description: "The site has contact forms. Ensure they are protected against spam and have proper validation.",
			Priority:    3,
			Action:      "Implement CAPTCHA and input validation on forms",
		})
	}

	return insights
}

// buildTimeline construye la línea de tiempo de eventos.
func (a *Analyzer) buildTimeline() []TimelineEvent {
	events := []TimelineEvent{}

	// Eventos de infraestructura
	if len(a.artifacts) > 0 {
		// Usar el primer artifact como referencia temporal
		if a.header.Created > 0 {
			scanTime := time.Unix(a.header.Created, 0)
			events = append(events, TimelineEvent{
				Timestamp:   scanTime,
				Type:        "scan",
				Description: "Reconnaissance scan started",
				Source:      "passive-recon",
			})
		}
	}

	// Eventos RDAP (registro, última modificación, expiración)
	rdapArtifacts := a.FilterArtifacts("rdap")
	for _, art := range rdapArtifacts {
		value := art.Value

		if strings.Contains(value, "event=registration") {
			timestamp := extractTimestamp(value)
			if !timestamp.IsZero() {
				events = append(events, TimelineEvent{
					Timestamp:   timestamp,
					Type:        "registration",
					Description: "Domain registered",
					Source:      "RDAP",
				})
			}
		}

		if strings.Contains(value, "event=last changed") {
			timestamp := extractTimestamp(value)
			if !timestamp.IsZero() {
				events = append(events, TimelineEvent{
					Timestamp:   timestamp,
					Type:        "change",
					Description: "Domain information last modified",
					Source:      "RDAP",
				})
			}
		}

		if strings.Contains(value, "event=expiration") {
			timestamp := extractTimestamp(value)
			if !timestamp.IsZero() {
				severity := "info"
				if time.Until(timestamp).Hours() < 30*24 {
					severity = "critical"
				}

				events = append(events, TimelineEvent{
					Timestamp:   timestamp,
					Type:        "expiration",
					Description: "Domain expiration date",
					Source:      "RDAP",
					Severity:    severity,
				})
			}
		}
	}

	// Ordenar eventos por timestamp
	// Bubble sort simple
	for i := 0; i < len(events); i++ {
		for j := i + 1; j < len(events); j++ {
			if events[j].Timestamp.Before(events[i].Timestamp) {
				events[i], events[j] = events[j], events[i]
			}
		}
	}

	return events
}
