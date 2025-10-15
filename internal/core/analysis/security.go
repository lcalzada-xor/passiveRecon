package analysis

import (
	"encoding/json"
	"strings"
)

// analyzeSecurityFindings analiza hallazgos de seguridad.
func (a *Analyzer) analyzeSecurityFindings() *SecurityFindings {
	findings := &SecurityFindings{
		Findings:   []Finding{},
		GFFindings: []GFFinding{},
	}

	// Analizar hallazgos de GoLinkFinder (gfFinding)
	a.analyzeGFFindings(findings)

	// Generar hallazgos generales
	a.generateSecurityFindings(findings)

	// Contar por severidad
	for _, f := range findings.Findings {
		switch f.Severity {
		case "critical":
			findings.Critical++
		case "high":
			findings.High++
		case "medium":
			findings.Medium++
		case "low":
			findings.Low++
		}
	}

	for _, gf := range findings.GFFindings {
		switch gf.Severity {
		case "critical":
			findings.Critical++
		case "high":
			findings.High++
		case "medium":
			findings.Medium++
		case "low":
			findings.Low++
		}
	}

	findings.TotalFindings = findings.Critical + findings.High + findings.Medium + findings.Low

	return findings
}

// analyzeGFFindings analiza hallazgos de GoLinkFinder.
func (a *Analyzer) analyzeGFFindings(findings *SecurityFindings) {
	gfArtifacts := a.FilterBySubtype("finding", "gf")

	for _, art := range gfArtifacts {
		// Parsear el value (puede ser string o objeto)
		var gfData map[string]interface{}

		// Intentar parsear como JSON desde Value
		if err := json.Unmarshal([]byte(art.Value), &gfData); err != nil {
			// Si falla, puede estar en formato compacto en Value
			// O puede estar en metadata
			if art.Metadata != nil {
				resource := GetArtifactMetadataString(art, "resource")
				evidence := GetArtifactMetadataString(art, "evidence")

				if resource != "" && evidence != "" {
					gfFinding := GFFinding{
						Resource: resource,
						Evidence: evidence,
						Category: categorizeGFFinding(evidence),
						Severity: severityFromGFFinding(evidence),
					}

					if line, ok := art.Metadata["line"].(float64); ok {
						gfFinding.Line = int(line)
					}

					if context, ok := art.Metadata["context"].(string); ok {
						gfFinding.Context = context
					}

					if rules, ok := art.Metadata["rules"].([]interface{}); ok {
						for _, rule := range rules {
							if ruleStr, ok := rule.(string); ok {
								gfFinding.Rules = append(gfFinding.Rules, ruleStr)
							}
						}
					}

					findings.GFFindings = append(findings.GFFindings, gfFinding)
				}
			}
		} else {
			// Parsear desde JSON
			resource, _ := gfData["res"].(string)
			evidence, _ := gfData["ev"].(string)

			if resource != "" && evidence != "" {
				gfFinding := GFFinding{
					Resource: resource,
					Evidence: evidence,
					Category: categorizeGFFinding(evidence),
					Severity: severityFromGFFinding(evidence),
				}

				if line, ok := gfData["l"].(float64); ok {
					gfFinding.Line = int(line)
				}

				if context, ok := gfData["ctx"].(string); ok {
					gfFinding.Context = context
				}

				if rules, ok := gfData["r"].([]interface{}); ok {
					for _, rule := range rules {
						if ruleStr, ok := rule.(string); ok {
							gfFinding.Rules = append(gfFinding.Rules, ruleStr)
						}
					}
				}

				findings.GFFindings = append(findings.GFFindings, gfFinding)
			}
		}
	}
}

// categorizeGFFinding categoriza un hallazgo de GF.
func categorizeGFFinding(evidence string) string {
	evidenceLower := strings.ToLower(evidence)

	if strings.Contains(evidenceLower, "api_key") || strings.Contains(evidenceLower, "apikey") {
		return "api-key"
	}
	if strings.Contains(evidenceLower, "secret") || strings.Contains(evidenceLower, "password") {
		return "secret"
	}
	if strings.Contains(evidenceLower, "token") || strings.Contains(evidenceLower, "jwt") {
		return "token"
	}
	if strings.Contains(evidenceLower, "key") {
		return "key"
	}
	if strings.Contains(evidenceLower, "/api/") || strings.Contains(evidenceLower, "endpoint") {
		return "api-endpoint"
	}
	if strings.Contains(evidenceLower, "path") || strings.Contains(evidenceLower, "url") {
		return "path"
	}

	return "other"
}

// severityFromGFFinding determina la severidad de un hallazgo de GF.
func severityFromGFFinding(evidence string) string {
	evidenceLower := strings.ToLower(evidence)

	// Critical: secretos obvios
	if strings.Contains(evidenceLower, "aws_secret") ||
		strings.Contains(evidenceLower, "private_key") ||
		strings.Contains(evidenceLower, "password") ||
		strings.Contains(evidenceLower, "secret_key") {
		return "critical"
	}

	// High: API keys, tokens
	if strings.Contains(evidenceLower, "api_key") ||
		strings.Contains(evidenceLower, "apikey") ||
		strings.Contains(evidenceLower, "access_token") {
		return "high"
	}

	// Medium: otros secretos potenciales
	if strings.Contains(evidenceLower, "token") ||
		strings.Contains(evidenceLower, "secret") ||
		strings.Contains(evidenceLower, "credential") {
		return "medium"
	}

	// Low: paths, endpoints
	return "low"
}

// generateSecurityFindings genera hallazgos de seguridad generales.
func (a *Analyzer) generateSecurityFindings(findings *SecurityFindings) {
	// Verificar exposición de .git
	routes := a.FilterArtifacts("route")
	for _, route := range routes {
		if strings.Contains(strings.ToLower(route.Value), ".git") && route.Active {
			finding := Finding{
				ID:          "GIT-001",
				Category:    "exposure",
				Title:       "Git Repository Exposed",
				Description: "The .git directory is publicly accessible, potentially exposing source code and sensitive information.",
				Severity:    "critical",
				Evidence:    []string{route.Value},
				Location:    route.Value,
				CWE:         "CWE-200",
				Remediation: "Remove the .git directory from the web root or configure the web server to deny access to it.",
			}
			findings.Findings = append(findings.Findings, finding)
			break
		}
	}

	// Verificar .env expuesto
	for _, route := range routes {
		if strings.Contains(strings.ToLower(route.Value), ".env") && route.Active {
			finding := Finding{
				ID:          "ENV-001",
				Category:    "exposure",
				Title:       "Environment Configuration Exposed",
				Description: ".env file is publicly accessible, potentially exposing API keys, database credentials, and other secrets.",
				Severity:    "critical",
				Evidence:    []string{route.Value},
				Location:    route.Value,
				CWE:         "CWE-312",
				Remediation: "Remove the .env file from the web root or configure the web server to deny access to it.",
			}
			findings.Findings = append(findings.Findings, finding)
			break
		}
	}

	// Verificar tecnologías obsoletas
	if techStack := a.detectTechnology(); techStack != nil {
		if len(techStack.Deprecated) > 0 {
			var evidence []string
			for _, tech := range techStack.Deprecated {
				evidence = append(evidence, tech.Name)
			}

			finding := Finding{
				ID:          "TECH-001",
				Category:    "vulnerability",
				Title:       "Deprecated Technologies in Use",
				Description: "The application uses deprecated technologies that are no longer supported and may contain security vulnerabilities.",
				Severity:    "high",
				Evidence:    evidence,
				Remediation: "Migrate to modern, supported technologies.",
			}
			findings.Findings = append(findings.Findings, finding)
		}
	}

	// Verificar páginas de email expuestas
	for _, route := range routes {
		if strings.Contains(strings.ToLower(route.Value), "email") && route.Active {
			finding := Finding{
				ID:          "PRIV-001",
				Category:    "exposure",
				Title:       "Email-Related Page Exposed",
				Description: "A page containing or referencing email addresses is publicly accessible, which could facilitate spam or phishing attacks.",
				Severity:    "low",
				Evidence:    []string{route.Value},
				Location:    route.Value,
				Remediation: "Consider protecting email-related pages or implementing CAPTCHA to prevent automated harvesting.",
			}
			findings.Findings = append(findings.Findings, finding)
			break
		}
	}
}
