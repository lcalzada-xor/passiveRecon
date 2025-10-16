package analysis

import (
	"encoding/json"
	"strings"
	"time"
)

// analyzeInfrastructure analiza la infraestructura descubierta.
func (a *Analyzer) analyzeInfrastructure() *Infrastructure {
	infra := &Infrastructure{
		Nameservers: []string{},
		DNSRecords:  make(map[string][]string),
		IPs:         []IPInfo{},
		Status:      []string{},
	}

	// Analizar DNS
	a.analyzeDNS(infra)

	// Analizar RDAP
	a.analyzeRDAP(infra)

	// Inferir hosting provider
	a.inferHostingProvider(infra)

	return infra
}

// analyzeDNS extrae información DNS.
func (a *Analyzer) analyzeDNS(infra *Infrastructure) {
	dnsArtifacts := a.FilterArtifacts("dns")

	recordTypes := make(map[string]map[string]bool) // type -> values

	for _, art := range dnsArtifacts {
		// Parsear el value que viene como JSON
		var dnsData map[string]interface{}
		if err := json.Unmarshal([]byte(art.Value), &dnsData); err == nil {
			// Extraer tipo y valor
			dnsType, _ := dnsData["type"].(string)
			dnsValue, _ := dnsData["value"].(string)

			if dnsType != "" && dnsValue != "" {
				if recordTypes[dnsType] == nil {
					recordTypes[dnsType] = make(map[string]bool)
				}
				recordTypes[dnsType][dnsValue] = true

				// Guardar nameservers
				if dnsType == "NS" && !contains(infra.Nameservers, dnsValue) {
					infra.Nameservers = append(infra.Nameservers, dnsValue)
				}

				// Guardar IPs
				if dnsType == "A" {
					found := false
					for _, ip := range infra.IPs {
						if ip.Address == dnsValue {
							found = true
							break
						}
					}
					if !found {
						infra.IPs = append(infra.IPs, IPInfo{
							Address:  dnsValue,
							Type:     "IPv4",
							Resolved: true,
						})
					}
				}

				if dnsType == "AAAA" {
					found := false
					for _, ip := range infra.IPs {
						if ip.Address == dnsValue {
							found = true
							break
						}
					}
					if !found {
						infra.IPs = append(infra.IPs, IPInfo{
							Address:  dnsValue,
							Type:     "IPv6",
							Resolved: true,
						})
					}
				}
			}
		}
	}

	// Convertir map a slice
	for recordType, values := range recordTypes {
		var valueSlice []string
		for value := range values {
			valueSlice = append(valueSlice, value)
		}
		infra.DNSRecords[recordType] = valueSlice
	}

	// También buscar en metadata de dnsx
	dnsxArtifacts := a.artifacts
	for _, art := range dnsxArtifacts {
		if art.Tool == "dnsx" || contains(art.Tools, "dnsx") {
			// Puede contener información de resolución
			if resolver := GetArtifactMetadataString(art, "resolver"); resolver != "" {
				// dnsx resolvió el dominio
			}
		}
	}
}

// analyzeRDAP extrae información RDAP.
func (a *Analyzer) analyzeRDAP(infra *Infrastructure) {
	rdapArtifacts := a.FilterArtifacts("rdap")

	for _, art := range rdapArtifacts {
		value := strings.ToLower(art.Value)

		// Registrar
		if strings.Contains(value, "registrar=") {
			parts := strings.SplitN(value, "=", 2)
			if len(parts) == 2 {
				infra.Registrar = strings.TrimSpace(parts[1])
			}
		}

		// Eventos (registration, expiration, last changed)
		if strings.Contains(value, "event=registration") {
			timestamp := extractTimestamp(value)
			if !timestamp.IsZero() {
				infra.Registered = &timestamp
			}
		}

		if strings.Contains(value, "event=expiration") {
			timestamp := extractTimestamp(value)
			if !timestamp.IsZero() {
				infra.Expires = &timestamp
			}
		}

		if strings.Contains(value, "event=last changed") {
			timestamp := extractTimestamp(value)
			if !timestamp.IsZero() {
				infra.LastChanged = &timestamp
			}
		}

		// Status
		if strings.Contains(value, "status=") {
			parts := strings.SplitN(value, "=", 2)
			if len(parts) == 2 {
				status := strings.TrimSpace(parts[1])
				if !contains(infra.Status, status) {
					infra.Status = append(infra.Status, status)
				}
			}
		}
	}

	// También buscar en metadata de artefactos
	for _, art := range a.artifacts {
		if registrar := GetArtifactMetadataString(art, "registrar"); registrar != "" && infra.Registrar == "" {
			infra.Registrar = registrar
		}
	}
}

// inferHostingProvider infiere el proveedor de hosting.
func (a *Analyzer) inferHostingProvider(infra *Infrastructure) {
	// Basado en registrar
	if strings.Contains(strings.ToLower(infra.Registrar), "ionos") {
		infra.HostingProvider = "IONOS"
	} else if strings.Contains(strings.ToLower(infra.Registrar), "godaddy") {
		infra.HostingProvider = "GoDaddy"
	} else if strings.Contains(strings.ToLower(infra.Registrar), "namecheap") {
		infra.HostingProvider = "Namecheap"
	} else if strings.Contains(strings.ToLower(infra.Registrar), "cloudflare") {
		infra.HostingProvider = "Cloudflare"
	}

	// Basado en MX records
	if mxRecords, ok := infra.DNSRecords["MX"]; ok {
		for _, mx := range mxRecords {
			mxLower := strings.ToLower(mx)
			if strings.Contains(mxLower, "google") || strings.Contains(mxLower, "gmail") {
				infra.EmailProvider = "Google Workspace"
				break
			} else if strings.Contains(mxLower, "outlook") || strings.Contains(mxLower, "microsoft") {
				infra.EmailProvider = "Microsoft 365"
				break
			} else if strings.Contains(mxLower, "ionos") {
				infra.EmailProvider = "IONOS"
				break
			} else if strings.Contains(mxLower, "protonmail") {
				infra.EmailProvider = "ProtonMail"
				break
			}
		}
	}

	// Basado en nameservers
	if len(infra.Nameservers) > 0 {
		nsLower := strings.ToLower(infra.Nameservers[0])
		if strings.Contains(nsLower, "cloudflare") {
			if infra.HostingProvider == "" {
				infra.HostingProvider = "Cloudflare"
			}
		} else if strings.Contains(nsLower, "amazonaws") || strings.Contains(nsLower, "awsdns") {
			if infra.HostingProvider == "" {
				infra.HostingProvider = "Amazon AWS"
			}
		} else if strings.Contains(nsLower, "googledomains") {
			if infra.HostingProvider == "" {
				infra.HostingProvider = "Google Domains"
			}
		}
	}
}

// extractTimestamp extrae un timestamp de un string RDAP.
func extractTimestamp(input string) time.Time {
	// Formato típico: "event=expiration 2025-10-15T09:51:00Z"
	parts := strings.Fields(input)
	if len(parts) >= 2 {
		timestampStr := parts[len(parts)-1]
		t, err := time.Parse(time.RFC3339, timestampStr)
		if err == nil {
			return t
		}
		// Intentar formato de solo fecha
		t, err = time.Parse("2006-01-02", timestampStr)
		if err == nil {
			return t
		}
	}
	return time.Time{}
}
