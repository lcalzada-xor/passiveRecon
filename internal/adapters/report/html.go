package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strings"

	"passive-rec/internal/core/analysis"
)

// GenerateHTML genera un reporte HTML moderno y responsive.
func GenerateHTML(report *analysis.Report, reportsDir string) error {
	htmlPath := filepath.Join(reportsDir, "report.html")

	htmlContent := buildHTMLReport(report)

	if err := os.WriteFile(htmlPath, []byte(htmlContent), 0644); err != nil {
		return fmt.Errorf("write html: %w", err)
	}

	return nil
}

func buildHTMLReport(report *analysis.Report) string {
	var sb strings.Builder

	// HTML header
	sb.WriteString(`<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Passive Reconnaissance Report - `)
	sb.WriteString(html.EscapeString(report.Target))
	sb.WriteString(`</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f7fa;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        header p {
            opacity: 0.9;
            font-size: 1.1em;
        }
        .card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .card h2 {
            color: #667eea;
            margin-bottom: 20px;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        .card h3 {
            color: #555;
            margin: 20px 0 10px 0;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-box {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-box .number {
            font-size: 2.5em;
            font-weight: bold;
            display: block;
        }
        .stat-box .label {
            font-size: 0.9em;
            opacity: 0.9;
        }
        .badge {
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            margin: 5px 5px 5px 0;
        }
        .badge-critical { background: #e53e3e; color: white; }
        .badge-high { background: #dd6b20; color: white; }
        .badge-medium { background: #d69e2e; color: white; }
        .badge-low { background: #38a169; color: white; }
        .badge-minimal { background: #48bb78; color: white; }
        .badge-info { background: #4299e1; color: white; }
        .score-display {
            text-align: center;
            padding: 30px;
            background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
            border-radius: 10px;
            color: white;
            margin: 20px 0;
        }
        .score-display .score {
            font-size: 4em;
            font-weight: bold;
        }
        .score-display .level {
            font-size: 1.5em;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        .insight {
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid;
        }
        .insight-critical {
            background: #fff5f5;
            border-left-color: #e53e3e;
        }
        .insight-warning {
            background: #fffaf0;
            border-left-color: #dd6b20;
        }
        .insight-info {
            background: #ebf8ff;
            border-left-color: #4299e1;
        }
        .insight h4 {
            margin-bottom: 8px;
            color: #2d3748;
        }
        .insight p {
            color: #4a5568;
            margin-bottom: 5px;
        }
        .insight .action {
            font-weight: 600;
            color: #2c5282;
            margin-top: 8px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
        }
        table th, table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e2e8f0;
        }
        table th {
            background: #f7fafc;
            font-weight: 600;
            color: #2d3748;
        }
        table tr:hover {
            background: #f7fafc;
        }
        .tech-list {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 10px 0;
        }
        .tech-item {
            background: #edf2f7;
            padding: 8px 15px;
            border-radius: 6px;
            font-size: 0.9em;
        }
        .evidence {
            background: #f7fafc;
            padding: 10px;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.85em;
            margin: 5px 0;
            overflow-x: auto;
        }
        .risk-high { color: #e53e3e; font-weight: 600; }
        .risk-medium { color: #dd6b20; font-weight: 600; }
        .risk-low { color: #38a169; font-weight: 600; }
        footer {
            text-align: center;
            padding: 20px;
            color: #718096;
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Passive Reconnaissance Report</h1>
            <p><strong>Target:</strong> `)
	sb.WriteString(html.EscapeString(report.Target))
	sb.WriteString(`</p>
            <p><strong>Scan Date:</strong> `)
	sb.WriteString(report.ScanDate.Format("2006-01-02 15:04:05"))
	sb.WriteString(` | <strong>Report Generated:</strong> `)
	sb.WriteString(report.ReportDate.Format("2006-01-02 15:04:05"))
	sb.WriteString(`</p>
        </header>
`)

	// Executive Summary
	writeHTMLSummary(&sb, report)

	// Critical Insights
	writeHTMLInsights(&sb, report)

	// Attack Surface
	if report.AttackSurface != nil {
		writeHTMLAttackSurface(&sb, report.AttackSurface)
	}

	// Technology Stack
	if report.TechStack != nil {
		writeHTMLTechStack(&sb, report.TechStack)
	}

	// Security Findings
	if report.Security != nil && report.Security.TotalFindings > 0 {
		writeHTMLSecurity(&sb, report.Security)
	}

	// Infrastructure
	if report.Infrastructure != nil {
		writeHTMLInfrastructure(&sb, report.Infrastructure)
	}

	// Assets
	if report.Assets != nil {
		writeHTMLAssets(&sb, report.Assets)
	}

	// Footer
	sb.WriteString(`
        <footer>
            <p>Report generated by <strong>passiveRecon</strong></p>
        </footer>
    </div>
</body>
</html>`)

	return sb.String()
}

func writeHTMLSummary(sb *strings.Builder, report *analysis.Report) {
	sb.WriteString(`
        <div class="card">
            <h2>Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <span class="number">`)
	sb.WriteString(fmt.Sprintf("%d", report.Summary.TotalArtifacts))
	sb.WriteString(`</span>
                    <span class="label">Total Artifacts</span>
                </div>
                <div class="stat-box">
                    <span class="number">`)
	sb.WriteString(fmt.Sprintf("%d", report.Summary.ActiveArtifacts))
	sb.WriteString(`</span>
                    <span class="label">Active Discoveries</span>
                </div>
                <div class="stat-box">
                    <span class="number">`)
	sb.WriteString(fmt.Sprintf("%d", report.Summary.PassiveArtifacts))
	sb.WriteString(`</span>
                    <span class="label">Passive Discoveries</span>
                </div>
                <div class="stat-box">
                    <span class="number">`)
	sb.WriteString(fmt.Sprintf("%d", len(report.Summary.ToolsUsed)))
	sb.WriteString(`</span>
                    <span class="label">Tools Used</span>
                </div>
            </div>
`)

	// Top tools
	if len(report.Summary.TopTools) > 0 {
		sb.WriteString(`
            <h3>Top Tools by Discoveries</h3>
            <table>
                <thead>
                    <tr>
                        <th>Tool</th>
                        <th>Discoveries</th>
                    </tr>
                </thead>
                <tbody>`)
		for _, tool := range report.Summary.TopTools {
			sb.WriteString(`
                    <tr>
                        <td>`)
			sb.WriteString(html.EscapeString(tool.Name))
			sb.WriteString(`</td>
                        <td><strong>`)
			sb.WriteString(fmt.Sprintf("%d", tool.Count))
			sb.WriteString(`</strong></td>
                    </tr>`)
		}
		sb.WriteString(`
                </tbody>
            </table>`)
	}

	sb.WriteString(`
        </div>`)
}

func writeHTMLInsights(sb *strings.Builder, report *analysis.Report) {
	if len(report.Insights) == 0 {
		return
	}

	sb.WriteString(`
        <div class="card">
            <h2>Key Insights</h2>`)

	for _, insight := range report.Insights {
		cssClass := "insight-info"
		if insight.Type == "critical" {
			cssClass = "insight-critical"
		} else if insight.Type == "warning" {
			cssClass = "insight-warning"
		}

		sb.WriteString(`
            <div class="insight `)
		sb.WriteString(cssClass)
		sb.WriteString(`">
                <h4>`)
		sb.WriteString(html.EscapeString(insight.Title))
		sb.WriteString(`</h4>
                <p>`)
		sb.WriteString(html.EscapeString(insight.Description))
		sb.WriteString(`</p>`)

		if insight.Action != "" {
			sb.WriteString(`
                <p class="action">Action: `)
			sb.WriteString(html.EscapeString(insight.Action))
			sb.WriteString(`</p>`)
		}

		sb.WriteString(`
            </div>`)
	}

	sb.WriteString(`
        </div>`)
}

func writeHTMLAttackSurface(sb *strings.Builder, surface *analysis.AttackSurface) {
	sb.WriteString(`
        <div class="card">
            <h2>Attack Surface Analysis</h2>
            <div class="score-display">
                <div class="score">`)
	sb.WriteString(fmt.Sprintf("%.1f", surface.Score))
	sb.WriteString(`/100</div>
                <div class="level">`)
	sb.WriteString(html.EscapeString(strings.ToUpper(surface.Level)))
	sb.WriteString(`</div>
            </div>
            <div class="stats-grid">
                <div class="stat-box">
                    <span class="number">`)
	sb.WriteString(fmt.Sprintf("%d", surface.TotalEndpoints))
	sb.WriteString(`</span>
                    <span class="label">Total Endpoints</span>
                </div>
                <div class="stat-box">
                    <span class="number">`)
	sb.WriteString(fmt.Sprintf("%d", surface.ActiveEndpoints))
	sb.WriteString(`</span>
                    <span class="label">Active Endpoints</span>
                </div>
                <div class="stat-box">
                    <span class="number">`)
	sb.WriteString(fmt.Sprintf("%d", len(surface.SensitiveEndpoints)))
	sb.WriteString(`</span>
                    <span class="label">Sensitive Endpoints</span>
                </div>
                <div class="stat-box">
                    <span class="number">`)
	sb.WriteString(fmt.Sprintf("%d", len(surface.ExposedFiles)))
	sb.WriteString(`</span>
                    <span class="label">Exposed Files</span>
                </div>
            </div>`)

	// Risk Factors
	if len(surface.RiskFactors) > 0 {
		sb.WriteString(`
            <h3>Risk Factors</h3>`)
		for _, risk := range surface.RiskFactors {
			sb.WriteString(`
            <div class="insight insight-warning">
                <h4>`)
			sb.WriteString(html.EscapeString(risk.Title))
			sb.WriteString(` <span class="badge badge-`)
			sb.WriteString(risk.Severity)
			sb.WriteString(`">`)
			sb.WriteString(strings.ToUpper(risk.Severity))
			sb.WriteString(`</span></h4>
                <p>`)
			sb.WriteString(html.EscapeString(risk.Description))
			sb.WriteString(`</p>
                <p><strong>Remediation:</strong> `)
			sb.WriteString(html.EscapeString(risk.Remediation))
			sb.WriteString(`</p>`)
			if len(risk.Evidence) > 0 {
				sb.WriteString(`
                <div class="evidence">`)
				for _, ev := range risk.Evidence[:min(3, len(risk.Evidence))] {
					sb.WriteString(html.EscapeString(ev))
					sb.WriteString(`<br>`)
				}
				sb.WriteString(`</div>`)
			}
			sb.WriteString(`
            </div>`)
		}
	}

	sb.WriteString(`
        </div>`)
}

func writeHTMLTechStack(sb *strings.Builder, stack *analysis.TechStack) {
	sb.WriteString(`
        <div class="card">
            <h2>Technology Stack</h2>
            <p><strong>Detection Confidence:</strong> <span class="badge badge-info">`)
	sb.WriteString(strings.ToUpper(stack.Confidence))
	sb.WriteString(`</span></p>`)

	// Deprecated technologies (most important)
	if len(stack.Deprecated) > 0 {
		sb.WriteString(`
            <h3>Deprecated Technologies</h3>`)
		for _, tech := range stack.Deprecated {
			sb.WriteString(`
            <div class="insight insight-critical">
                <h4>`)
			sb.WriteString(html.EscapeString(tech.Name))
			sb.WriteString(` <span class="badge badge-`)
			sb.WriteString(tech.Risk)
			sb.WriteString(`">`)
			sb.WriteString(strings.ToUpper(tech.Risk))
			sb.WriteString(` RISK</span></h4>`)
			if len(tech.Evidence) > 0 {
				sb.WriteString(`
                <div class="evidence">`)
				for _, ev := range tech.Evidence[:min(3, len(tech.Evidence))] {
					sb.WriteString(html.EscapeString(ev))
					sb.WriteString(`<br>`)
				}
				sb.WriteString(`</div>`)
			}
			sb.WriteString(`
            </div>`)
		}
	}

	// JavaScript Frameworks
	if len(stack.Frameworks) > 0 {
		sb.WriteString(`
            <h3>Frameworks</h3>
            <div class="tech-list">`)
		for _, tech := range stack.Frameworks {
			sb.WriteString(`
                <div class="tech-item">`)
			sb.WriteString(html.EscapeString(tech.Name))
			if tech.Version != "" {
				sb.WriteString(` v`)
				sb.WriteString(html.EscapeString(tech.Version))
			}
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`
            </div>`)
	}

	// JavaScript Libraries
	if len(stack.JavaScript) > 0 {
		sb.WriteString(`
            <h3>JavaScript Libraries</h3>
            <div class="tech-list">`)
		for _, tech := range stack.JavaScript {
			sb.WriteString(`
                <div class="tech-item">`)
			sb.WriteString(html.EscapeString(tech.Name))
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`
            </div>`)
	}

	// CSS Frameworks
	if len(stack.CSS) > 0 {
		sb.WriteString(`
            <h3>CSS Frameworks</h3>
            <div class="tech-list">`)
		for _, tech := range stack.CSS {
			sb.WriteString(`
                <div class="tech-item">`)
			sb.WriteString(html.EscapeString(tech.Name))
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`
            </div>`)
	}

	// CMS
	if len(stack.CMS) > 0 {
		sb.WriteString(`
            <h3>CMS / Platform</h3>
            <div class="tech-list">`)
		for _, tech := range stack.CMS {
			sb.WriteString(`
                <div class="tech-item">`)
			sb.WriteString(html.EscapeString(tech.Name))
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`
            </div>`)
	}

	// Web Servers
	if len(stack.Servers) > 0 {
		sb.WriteString(`
            <h3>Web Servers</h3>
            <div class="tech-list">`)
		for _, tech := range stack.Servers {
			sb.WriteString(`
                <div class="tech-item">`)
			sb.WriteString(html.EscapeString(tech.Name))
			if tech.Version != "" {
				sb.WriteString(` v`)
				sb.WriteString(html.EscapeString(tech.Version))
			}
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`
            </div>`)
	}

	sb.WriteString(`
        </div>`)
}

func writeHTMLSecurity(sb *strings.Builder, security *analysis.SecurityFindings) {
	sb.WriteString(`
        <div class="card">
            <h2>Security Findings</h2>
            <p><strong>Total Findings:</strong> `)
	sb.WriteString(fmt.Sprintf("%d", security.TotalFindings))
	sb.WriteString(`</p>
            <div class="stats-grid">`)

	if security.Critical > 0 {
		sb.WriteString(`
                <div class="stat-box" style="background: #e53e3e;">
                    <span class="number">`)
		sb.WriteString(fmt.Sprintf("%d", security.Critical))
		sb.WriteString(`</span>
                    <span class="label">Critical</span>
                </div>`)
	}
	if security.High > 0 {
		sb.WriteString(`
                <div class="stat-box" style="background: #dd6b20;">
                    <span class="number">`)
		sb.WriteString(fmt.Sprintf("%d", security.High))
		sb.WriteString(`</span>
                    <span class="label">High</span>
                </div>`)
	}
	if security.Medium > 0 {
		sb.WriteString(`
                <div class="stat-box" style="background: #d69e2e;">
                    <span class="number">`)
		sb.WriteString(fmt.Sprintf("%d", security.Medium))
		sb.WriteString(`</span>
                    <span class="label">Medium</span>
                </div>`)
	}
	if security.Low > 0 {
		sb.WriteString(`
                <div class="stat-box" style="background: #38a169;">
                    <span class="number">`)
		sb.WriteString(fmt.Sprintf("%d", security.Low))
		sb.WriteString(`</span>
                    <span class="label">Low</span>
                </div>`)
	}

	sb.WriteString(`
            </div>`)

	// Findings list
	if len(security.Findings) > 0 {
		sb.WriteString(`
            <h3>Detailed Findings</h3>`)
		for _, finding := range security.Findings {
			cssClass := "insight-info"
			if finding.Severity == "critical" || finding.Severity == "high" {
				cssClass = "insight-critical"
			} else if finding.Severity == "medium" {
				cssClass = "insight-warning"
			}

			sb.WriteString(`
            <div class="insight `)
			sb.WriteString(cssClass)
			sb.WriteString(`">
                <h4>`)
			sb.WriteString(html.EscapeString(finding.Title))
			sb.WriteString(` <span class="badge badge-`)
			sb.WriteString(finding.Severity)
			sb.WriteString(`">`)
			sb.WriteString(strings.ToUpper(finding.Severity))
			sb.WriteString(`</span></h4>
                <p><strong>ID:</strong> `)
			sb.WriteString(html.EscapeString(finding.ID))
			sb.WriteString(` | <strong>Category:</strong> `)
			sb.WriteString(html.EscapeString(finding.Category))
			sb.WriteString(`</p>
                <p>`)
			sb.WriteString(html.EscapeString(finding.Description))
			sb.WriteString(`</p>`)

			if len(finding.Evidence) > 0 {
				sb.WriteString(`
                <p><strong>Evidence:</strong></p>
                <div class="evidence">`)
				for _, ev := range finding.Evidence[:min(5, len(finding.Evidence))] {
					evStr := ev
					if len(evStr) > 100 {
						evStr = evStr[:97] + "..."
					}
					sb.WriteString(html.EscapeString(evStr))
					sb.WriteString(`<br>`)
				}
				sb.WriteString(`</div>`)
			}

			if finding.Remediation != "" {
				sb.WriteString(`
                <p class="action">Remediation: `)
				sb.WriteString(html.EscapeString(finding.Remediation))
				sb.WriteString(`</p>`)
			}

			sb.WriteString(`
            </div>`)
		}
	}

	sb.WriteString(`
        </div>`)
}

func writeHTMLInfrastructure(sb *strings.Builder, infra *analysis.Infrastructure) {
	sb.WriteString(`
        <div class="card">
            <h2>Infrastructure</h2>`)

	// Hosting & Services
	if infra.HostingProvider != "" || infra.EmailProvider != "" {
		sb.WriteString(`
            <h3>Hosting & Services</h3>
            <table>
                <tbody>`)
		if infra.HostingProvider != "" {
			sb.WriteString(`
                    <tr>
                        <td><strong>Hosting Provider</strong></td>
                        <td>`)
			sb.WriteString(html.EscapeString(infra.HostingProvider))
			sb.WriteString(`</td>
                    </tr>`)
		}
		if infra.EmailProvider != "" {
			sb.WriteString(`
                    <tr>
                        <td><strong>Email Provider</strong></td>
                        <td>`)
			sb.WriteString(html.EscapeString(infra.EmailProvider))
			sb.WriteString(`</td>
                    </tr>`)
		}
		sb.WriteString(`
                </tbody>
            </table>`)
	}

	// DNS
	if len(infra.Nameservers) > 0 {
		sb.WriteString(`
            <h3>DNS Configuration</h3>
            <p><strong>Nameservers (`)
		sb.WriteString(fmt.Sprintf("%d", len(infra.Nameservers)))
		sb.WriteString(`):</strong></p>
            <div class="tech-list">`)
		for _, ns := range infra.Nameservers {
			sb.WriteString(`
                <div class="tech-item">`)
			sb.WriteString(html.EscapeString(ns))
			sb.WriteString(`</div>`)
		}
		sb.WriteString(`
            </div>`)
	}

	// DNS Records
	if len(infra.DNSRecords) > 0 {
		sb.WriteString(`
            <h3>DNS Records</h3>
            <table>
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Values</th>
                    </tr>
                </thead>
                <tbody>`)
		for recType, records := range infra.DNSRecords {
			sb.WriteString(`
                    <tr>
                        <td><strong>`)
			sb.WriteString(html.EscapeString(recType))
			sb.WriteString(`</strong></td>
                        <td>`)
			sb.WriteString(html.EscapeString(strings.Join(records, ", ")))
			sb.WriteString(`</td>
                    </tr>`)
		}
		sb.WriteString(`
                </tbody>
            </table>`)
	}

	// RDAP info
	if infra.Registrar != "" {
		sb.WriteString(`
            <h3>Domain Registration</h3>
            <table>
                <tbody>`)
		if infra.Registrar != "" {
			sb.WriteString(`
                    <tr>
                        <td><strong>Registrar</strong></td>
                        <td>`)
			sb.WriteString(html.EscapeString(infra.Registrar))
			sb.WriteString(`</td>
                    </tr>`)
		}
		if !infra.Registered.IsZero() && infra.Registered.Year() > 1 {
			sb.WriteString(`
                    <tr>
                        <td><strong>Registered</strong></td>
                        <td>`)
			sb.WriteString(infra.Registered.Format("2006-01-02"))
			sb.WriteString(`</td>
                    </tr>`)
		}
		if !infra.Expires.IsZero() && infra.Expires.Year() > 1 {
			sb.WriteString(`
                    <tr>
                        <td><strong>Expires</strong></td>
                        <td>`)
			sb.WriteString(infra.Expires.Format("2006-01-02"))
			sb.WriteString(`</td>
                    </tr>`)
		}
		if len(infra.Status) > 0 {
			sb.WriteString(`
                    <tr>
                        <td><strong>Status</strong></td>
                        <td>`)
			sb.WriteString(html.EscapeString(strings.Join(infra.Status, ", ")))
			sb.WriteString(`</td>
                    </tr>`)
		}
		sb.WriteString(`
                </tbody>
            </table>`)
	}

	sb.WriteString(`
        </div>`)
}

func writeHTMLAssets(sb *strings.Builder, assets *analysis.AssetInventory) {
	sb.WriteString(`
        <div class="card">
            <h2>Asset Inventory</h2>
            <div class="stats-grid">
                <div class="stat-box">
                    <span class="number">`)
	sb.WriteString(fmt.Sprintf("%d", assets.TotalDomains))
	sb.WriteString(`</span>
                    <span class="label">Total Domains</span>
                </div>
                <div class="stat-box">
                    <span class="number">`)
	sb.WriteString(fmt.Sprintf("%d", assets.ActiveDomains))
	sb.WriteString(`</span>
                    <span class="label">Active Domains</span>
                </div>
                <div class="stat-box">
                    <span class="number">`)
	sb.WriteString(fmt.Sprintf("%d", assets.TotalSubdomains))
	sb.WriteString(`</span>
                    <span class="label">Subdomains</span>
                </div>
            </div>`)

	// Web resources summary
	if assets.HTMLPages > 0 || assets.JavaScripts > 0 || assets.Stylesheets > 0 {
		sb.WriteString(`
            <h3>Web Resources</h3>
            <table>
                <tbody>
                    <tr>
                        <td>HTML Pages</td>
                        <td>`)
		sb.WriteString(fmt.Sprintf("%d", assets.HTMLPages))
		sb.WriteString(`</td>
                    </tr>
                    <tr>
                        <td>JavaScript Files</td>
                        <td>`)
		sb.WriteString(fmt.Sprintf("%d", assets.JavaScripts))
		sb.WriteString(`</td>
                    </tr>
                    <tr>
                        <td>Stylesheets</td>
                        <td>`)
		sb.WriteString(fmt.Sprintf("%d", assets.Stylesheets))
		sb.WriteString(`</td>
                    </tr>
                    <tr>
                        <td>Images</td>
                        <td>`)
		sb.WriteString(fmt.Sprintf("%d", assets.Images))
		sb.WriteString(`</td>
                    </tr>
                    <tr>
                        <td>Documents</td>
                        <td>`)
		sb.WriteString(fmt.Sprintf("%d", assets.Documents))
		sb.WriteString(`</td>
                    </tr>
                </tbody>
            </table>`)
	}

	// Domains list (if not too many)
	if len(assets.Domains) > 0 && len(assets.Domains) <= 20 {
		sb.WriteString(`
            <h3>Discovered Domains</h3>
            <table>
                <thead>
                    <tr>
                        <th>Domain</th>
                        <th>Status</th>
                        <th>Source</th>
                    </tr>
                </thead>
                <tbody>`)
		for _, domain := range assets.Domains {
			sb.WriteString(`
                    <tr>
                        <td>`)
			sb.WriteString(html.EscapeString(domain.Name))
			sb.WriteString(`</td>
                        <td>`)
			if domain.Active {
				sb.WriteString(`<span class="badge badge-low">ACTIVE</span>`)
			} else {
				sb.WriteString(`<span class="badge badge-info">PASSIVE</span>`)
			}
			sb.WriteString(`</td>
                        <td>`)
			sb.WriteString(html.EscapeString(domain.Source))
			sb.WriteString(`</td>
                    </tr>`)
		}
		sb.WriteString(`
                </tbody>
            </table>`)
	}

	sb.WriteString(`
        </div>`)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// marshalReportJSON exporta el reporte completo como JSON embebido en el HTML
func marshalReportJSON(report *analysis.Report) string {
	data, err := json.Marshal(report)
	if err != nil {
		return "{}"
	}
	return string(data)
}
