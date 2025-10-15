package handlers

import (
	"strings"

	"passive-rec/internal/platform/certs"
	"passive-rec/internal/platform/netutil"
)

const (
	keyspaceCertPassive = "cert:passive"
	keyspaceCertActive  = "cert:active"
)

// CertificateHandler procesa artifacts de tipo certificate.
type CertificateHandler struct {
	BaseHandler
}

// NewCertificateHandler crea un nuevo handler de certificados.
func NewCertificateHandler() *CertificateHandler {
	return &CertificateHandler{
		BaseHandler: NewBaseHandler("certificate", "cert:"),
	}
}

// CanHandle determina si la línea es un certificado.
func (h *CertificateHandler) CanHandle(line string, isActive bool) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	return h.HasPrefix(trimmed)
}

// Handle procesa una línea de certificado y crea los artifacts correspondientes.
func (h *CertificateHandler) Handle(ctx *HandlerContext, line string, isActive bool, tool string) bool {
	if ctx == nil || ctx.Store == nil {
		return true
	}

	// Remover prefijo y limpiar
	payload := strings.TrimSpace(h.StripPrefix(line))
	if payload == "" {
		return true
	}

	// Parsear el certificado
	record, err := certs.Parse(payload)
	if err != nil {
		return true // No es un error, simplemente no es parseable
	}

	// Filtrar dominios según scope
	filtered := h.filterCertificateByScope(ctx, record)

	// Obtener todos los nombres del certificado
	names := filtered.AllNames()
	if len(names) == 0 {
		return true
	}

	// Crear artifacts de dominio para cada nombre en el certificado
	h.createDomainArtifacts(ctx, names, isActive, tool)

	// Crear el artifact de certificado
	h.createCertificateArtifact(ctx, filtered, names, isActive, tool)

	return true
}

// filterCertificateByScope filtra los dominios del certificado según el scope.
func (h *CertificateHandler) filterCertificateByScope(ctx *HandlerContext, record certs.Record) certs.Record {
	filtered := record

	// Filtrar CommonName
	if filtered.CommonName != "" {
		domain := netutil.NormalizeDomain(filtered.CommonName)
		if domain == "" || (ctx.Scope != nil && !ctx.Scope.AllowsDomain(domain)) {
			filtered.CommonName = ""
		}
	}

	// Filtrar DNSNames
	if len(filtered.DNSNames) > 0 {
		names := make([]string, 0, len(filtered.DNSNames))
		for _, name := range filtered.DNSNames {
			domain := netutil.NormalizeDomain(name)
			if domain == "" {
				continue
			}
			if ctx.Scope != nil && !ctx.Scope.AllowsDomain(domain) {
				continue
			}
			names = append(names, name)
		}
		filtered.DNSNames = names
	}

	return filtered
}

// createDomainArtifacts crea artifacts de dominio para cada nombre en el certificado.
func (h *CertificateHandler) createDomainArtifacts(ctx *HandlerContext, names []string, isActive bool, tool string) {
	for _, name := range names {
		domain := netutil.NormalizeDomain(name)
		if domain == "" {
			continue
		}

		metadata := map[string]any{"source": "certificate"}
		trimmed := strings.TrimSpace(name)
		if trimmed != "" && trimmed != domain {
			metadata["raw"] = trimmed
		}

		// Marcar como visto
		MarkSeen(ctx, keyspaceDomainPassive, domain)
		if ctx.ActiveMode {
			MarkSeen(ctx, keyspaceDomainActive, domain)
		}

		// Crear artifact de dominio pasivo
		RecordArtifact(ctx, tool, ArtifactRequest{
			Type:     "domain",
			Value:    domain,
			Active:   false,
			Up:       true,
			Metadata: metadata,
		})

		// Si está en modo activo, crear también artifact activo
		if ctx.ActiveMode {
			RecordArtifact(ctx, tool, ArtifactRequest{
				Type:     "domain",
				Value:    domain,
				Active:   true,
				Up:       true,
				Metadata: metadata,
			})
		}
	}
}

// createCertificateArtifact crea el artifact de certificado.
func (h *CertificateHandler) createCertificateArtifact(ctx *HandlerContext, record certs.Record, names []string, isActive bool, tool string) {
	// Serializar el certificado
	serialized, err := record.Marshal()
	if err != nil {
		return
	}

	// Generar key de deduplicación
	key := record.Key()
	if key == "" {
		key = strings.ToLower(serialized)
	}

	// Marcar como visto
	keyspace := keyspaceCertPassive
	if isActive {
		keyspace = keyspaceCertActive
	}
	MarkSeen(ctx, keyspace, key)

	// Crear metadata
	meta := map[string]any{"names": names}
	if key != "" {
		meta["key"] = key
	}

	// Crear artifact
	RecordArtifact(ctx, tool, ArtifactRequest{
		Type:     "certificate",
		Value:    serialized,
		Active:   isActive,
		Up:       true,
		Tool:     record.Source,
		Metadata: meta,
	})
}
