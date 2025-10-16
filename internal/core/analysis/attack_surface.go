package analysis

import (
	"strings"

	"passive-rec/internal/adapters/artifacts"
)

// analyzeAttackSurface calcula y analiza la superficie de ataque.
func (a *Analyzer) analyzeAttackSurface() *AttackSurface {
	surface := &AttackSurface{
		SensitiveEndpoints: []SensitiveEndpoint{},
		APIEndpoints:       []string{},
		AdminEndpoints:     []string{},
		AuthEndpoints:      []string{},
		ExposedFiles:       []ExposedFile{},
		ExposedTech:        []string{},
		RiskFactors:        []RiskFactor{},
	}

	// Contar endpoints
	routes := a.FilterArtifacts("route")
	resources := a.FilterArtifacts("resource")
	allEndpoints := append(routes, resources...)

	surface.TotalEndpoints = len(allEndpoints)

	activeEndpoints := 0
	for _, ep := range allEndpoints {
		if ep.Active {
			activeEndpoints++
		}
	}
	surface.ActiveEndpoints = activeEndpoints

	// Detectar endpoints sensibles
	a.detectSensitiveEndpoints(surface, allEndpoints)

	// Detectar archivos expuestos
	a.detectExposedFiles(surface, allEndpoints)

	// Detectar APIs
	a.detectAPIs(surface, allEndpoints)

	// Generar factores de riesgo
	a.generateRiskFactors(surface)

	// Calcular score
	surface.Score = a.calculateAttackSurfaceScore(surface)
	surface.Level = a.classifyAttackSurfaceLevel(surface.Score)

	return surface
}

// detectSensitiveEndpoints detecta endpoints potencialmente sensibles.
func (a *Analyzer) detectSensitiveEndpoints(surface *AttackSurface, endpoints []artifacts.Artifact) {
	sensitivePaths := map[string]struct {
		category string
		risk     string
		reason   string
	}{
		"/admin":         {"admin", "high", "Admin panel access"},
		"/administrator": {"admin", "high", "Administrator interface"},
		"/wp-admin":      {"admin", "high", "WordPress admin panel"},
		"/phpmyadmin":    {"admin", "critical", "Database management interface"},
		"/cpanel":        {"admin", "critical", "cPanel access"},
		"/login":         {"auth", "medium", "Login page"},
		"/signin":        {"auth", "medium", "Sign-in page"},
		"/auth":          {"auth", "medium", "Authentication endpoint"},
		"/oauth":         {"auth", "medium", "OAuth endpoint"},
		"/api":           {"api", "medium", "API endpoint"},
		"/rest":          {"api", "medium", "REST API"},
		"/graphql":       {"api", "medium", "GraphQL endpoint"},
		"/config":        {"config", "high", "Configuration file/endpoint"},
		"/settings":      {"config", "medium", "Settings page"},
		"/.env":          {"config", "critical", "Environment configuration file"},
		"/.git":          {"exposure", "critical", "Git repository exposed"},
		"/backup":        {"backup", "high", "Backup files"},
		".sql":           {"backup", "critical", "SQL database dump"},
		".bak":           {"backup", "high", "Backup file"},
		".old":           {"backup", "medium", "Old/archived file"},
		"/test":          {"dev", "medium", "Test endpoint"},
		"/debug":         {"dev", "high", "Debug endpoint"},
		"/swagger":       {"api", "low", "API documentation"},
		"/docs":          {"api", "low", "Documentation"},
		"/email":         {"exposure", "medium", "Email-related endpoint"},
		"/upload":        {"upload", "medium", "File upload endpoint"},
		"/uploads":       {"upload", "medium", "Uploads directory"},
		"/download":      {"download", "low", "File download endpoint"},
		"/formulario":    {"form", "medium", "Form endpoint"},
		"/form":          {"form", "medium", "Form endpoint"},
		"/password":      {"auth", "high", "Password-related endpoint"},
		"/reset":         {"auth", "medium", "Password reset"},
		"/register":      {"auth", "low", "Registration page"},
		"/dashboard":     {"admin", "medium", "Dashboard interface"},
		"/console":       {"admin", "high", "Admin console"},
	}

	detected := make(map[string]bool) // Evitar duplicados

	for _, ep := range endpoints {
		value := strings.ToLower(ep.Value)

		for pattern, info := range sensitivePaths {
			if strings.Contains(value, pattern) {
				key := pattern + "_" + info.category
				if detected[key] {
					continue
				}
				detected[key] = true

				statusCode := 0
				if statusStr := GetArtifactMetadataString(ep, "status"); statusStr != "" {
					// Parsear status code si existe
					if len(statusStr) >= 3 {
						statusCode = parseInt(statusStr[:3])
					}
				}

				endpoint := SensitiveEndpoint{
					URL:        ep.Value,
					Category:   info.category,
					Risk:       info.risk,
					Reason:     info.reason,
					Active:     ep.Active,
					StatusCode: statusCode,
				}

				surface.SensitiveEndpoints = append(surface.SensitiveEndpoints, endpoint)

				// Agregar a categorías específicas
				switch info.category {
				case "admin":
					if !contains(surface.AdminEndpoints, ep.Value) {
						surface.AdminEndpoints = append(surface.AdminEndpoints, ep.Value)
					}
				case "auth":
					if !contains(surface.AuthEndpoints, ep.Value) {
						surface.AuthEndpoints = append(surface.AuthEndpoints, ep.Value)
					}
				case "api":
					if !contains(surface.APIEndpoints, ep.Value) {
						surface.APIEndpoints = append(surface.APIEndpoints, ep.Value)
					}
				}

				break // Solo matchear una vez por endpoint
			}
		}
	}
}

// detectExposedFiles detecta archivos expuestos.
func (a *Analyzer) detectExposedFiles(surface *AttackSurface, endpoints []artifacts.Artifact) {
	exposedPatterns := map[string]struct {
		typ  string
		risk string
	}{
		"robots.txt":    {"robots.txt", "low"},
		".git":          {".git", "critical"},
		".svn":          {".svn", "critical"},
		".env":          {".env", "critical"},
		".htaccess":     {".htaccess", "high"},
		"web.config":    {"web.config", "high"},
		".sql":          {"sql dump", "critical"},
		".zip":          {"archive", "medium"},
		".tar.gz":       {"archive", "medium"},
		".bak":          {"backup", "high"},
		".old":          {"backup", "medium"},
		".swp":          {"editor swap", "medium"},
		"phpinfo":       {"phpinfo", "high"},
		"server-status": {"server-status", "medium"},
	}

	detected := make(map[string]bool)

	for _, ep := range endpoints {
		value := strings.ToLower(ep.Value)

		for pattern, info := range exposedPatterns {
			if strings.Contains(value, pattern) {
				if detected[value] {
					continue
				}
				detected[value] = true

				statusCode := 0
				if statusStr := GetArtifactMetadataString(ep, "status"); statusStr != "" {
					if len(statusStr) >= 3 {
						statusCode = parseInt(statusStr[:3])
					}
				}

				file := ExposedFile{
					Path:       ep.Value,
					Type:       info.typ,
					Risk:       info.risk,
					Active:     ep.Active,
					StatusCode: statusCode,
				}

				surface.ExposedFiles = append(surface.ExposedFiles, file)
				break
			}
		}
	}
}

// detectAPIs detecta endpoints de API.
func (a *Analyzer) detectAPIs(surface *AttackSurface, endpoints []artifacts.Artifact) {
	apiPatterns := []string{
		"/api/",
		"/rest/",
		"/v1/",
		"/v2/",
		"/v3/",
		"/graphql",
		".json",
		"/endpoint/",
	}

	for _, ep := range endpoints {
		value := strings.ToLower(ep.Value)

		for _, pattern := range apiPatterns {
			if strings.Contains(value, pattern) {
				if !contains(surface.APIEndpoints, ep.Value) {
					surface.APIEndpoints = append(surface.APIEndpoints, ep.Value)
				}
				break
			}
		}
	}
}

// generateRiskFactors genera factores de riesgo basados en el análisis.
func (a *Analyzer) generateRiskFactors(surface *AttackSurface) {
	// Riesgo por tecnologías obsoletas
	if techStack := a.detectTechnology(); techStack != nil {
		for _, tech := range techStack.Deprecated {
			factor := RiskFactor{
				Category:    "technology",
				Title:       "Deprecated Technology: " + tech.Name,
				Description: "The application uses deprecated technology that is no longer supported and may contain security vulnerabilities.",
				Severity:    tech.Risk,
				Evidence:    tech.Evidence,
				Remediation: "Migrate to modern, supported technologies.",
			}
			surface.RiskFactors = append(surface.RiskFactors, factor)
		}
	}

	// Riesgo por archivos expuestos críticos
	criticalFiles := 0
	for _, file := range surface.ExposedFiles {
		if file.Risk == "critical" && file.Active {
			criticalFiles++
		}
	}
	if criticalFiles > 0 {
		factor := RiskFactor{
			Category:    "exposure",
			Title:       "Critical Files Exposed",
			Description: "Sensitive configuration files or repositories are publicly accessible.",
			Severity:    "critical",
			Remediation: "Restrict access to sensitive files and directories. Remove .git, .env, and database dumps from public access.",
		}
		surface.RiskFactors = append(surface.RiskFactors, factor)
	}

	// Riesgo por cantidad de endpoints sensibles
	if len(surface.SensitiveEndpoints) > 10 {
		factor := RiskFactor{
			Category:    "exposure",
			Title:       "Large Attack Surface",
			Description: "Multiple sensitive endpoints detected, increasing the attack surface.",
			Severity:    "medium",
			Remediation: "Review and restrict access to sensitive endpoints. Implement authentication and authorization controls.",
		}
		surface.RiskFactors = append(surface.RiskFactors, factor)
	}

	// Riesgo por endpoints admin activos
	if len(surface.AdminEndpoints) > 0 {
		activeAdmin := 0
		for _, ep := range surface.SensitiveEndpoints {
			if ep.Category == "admin" && ep.Active {
				activeAdmin++
			}
		}
		if activeAdmin > 0 {
			factor := RiskFactor{
				Category:    "exposure",
				Title:       "Admin Interfaces Accessible",
				Description: "Administrative interfaces are publicly accessible, which could be targeted by attackers.",
				Severity:    "high",
				Remediation: "Restrict admin panel access to specific IP addresses or implement strong authentication.",
			}
			surface.RiskFactors = append(surface.RiskFactors, factor)
		}
	}
}

// calculateAttackSurfaceScore calcula un score de 0-100 de la superficie de ataque.
func (a *Analyzer) calculateAttackSurfaceScore(surface *AttackSurface) float64 {
	score := 0.0

	// Base: número de endpoints activos (max 30 puntos)
	if surface.ActiveEndpoints > 0 {
		endpointScore := float64(surface.ActiveEndpoints) / 10.0
		if endpointScore > 30 {
			endpointScore = 30
		}
		score += endpointScore
	}

	// Endpoints sensibles (max 40 puntos)
	for _, ep := range surface.SensitiveEndpoints {
		if !ep.Active {
			continue
		}
		switch ep.Risk {
		case "critical":
			score += 10
		case "high":
			score += 5
		case "medium":
			score += 2
		case "low":
			score += 0.5
		}
	}

	// Archivos expuestos (max 20 puntos)
	for _, file := range surface.ExposedFiles {
		if !file.Active {
			continue
		}
		switch file.Risk {
		case "critical":
			score += 8
		case "high":
			score += 4
		case "medium":
			score += 2
		case "low":
			score += 0.5
		}
	}

	// Factores de riesgo (max 10 puntos)
	for _, factor := range surface.RiskFactors {
		switch factor.Severity {
		case "critical":
			score += 3
		case "high":
			score += 2
		case "medium":
			score += 1
		}
	}

	if score > 100 {
		score = 100
	}

	return score
}

// classifyAttackSurfaceLevel clasifica el nivel de la superficie de ataque.
func (a *Analyzer) classifyAttackSurfaceLevel(score float64) string {
	switch {
	case score >= 80:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 40:
		return "medium"
	case score >= 20:
		return "low"
	default:
		return "minimal"
	}
}

// Helper functions

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func parseInt(s string) int {
	var result int
	for _, c := range s {
		if c >= '0' && c <= '9' {
			result = result*10 + int(c-'0')
		}
	}
	return result
}
