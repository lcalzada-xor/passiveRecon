package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"passive-rec/internal/platform/certs"
	"passive-rec/internal/platform/logx"
)

const (
	// censysRequestTimeout defines the maximum time allowed for a single Censys API request
	censysRequestTimeout = 30 * time.Second
)

var (
	censysBaseURL = "https://search.censys.io/api/v2/certificates/search"
	// censysHTTPClient is initialized with reasonable timeouts to prevent hanging requests
	censysHTTPClient = &http.Client{
		Timeout: censysRequestTimeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}
)

func censysMeta(out chan<- string, format string, args ...interface{}) {
	if out == nil {
		return
	}
	msg := fmt.Sprintf(format, args...)
	if strings.TrimSpace(msg) == "" {
		return
	}
	out <- "meta: censys " + msg
}

type censysResponse struct {
	Result struct {
		Hits []struct {
			Name              string `json:"name"`
			FingerprintSHA256 string `json:"fingerprint_sha256"`
			FingerprintSHA1   string `json:"fingerprint_sha1"`
			FingerprintMD5    string `json:"fingerprint_md5"`
			Parsed            struct {
				Names   []string `json:"names"`
				Subject struct {
					CommonName string `json:"common_name"`
					DN         string `json:"dn"`
				} `json:"subject"`
				Issuer struct {
					CommonName string `json:"common_name"`
					DN         string `json:"dn"`
				} `json:"issuer"`
				SubjectDN string `json:"subject_dn"`
				IssuerDN  string `json:"issuer_dn"`
				Validity  struct {
					Start string `json:"start"`
					End   string `json:"end"`
				} `json:"validity"`
				SerialNumber string `json:"serial_number"`
			} `json:"parsed"`
		} `json:"hits"`
		Links struct {
			Next string `json:"next"`
		} `json:"links"`
	} `json:"result"`
}

// Censys consulta la Search API de certificados y emite posibles subdominios.
func Censys(ctx context.Context, domain, apiID, apiSecret string, out chan<- string) error {
	if strings.TrimSpace(domain) == "" {
		censysMeta(out, "skipped empty domain")
		return errors.New("censys: empty domain")
	}
	if apiID == "" || apiSecret == "" {
		censysMeta(out, "missing API credentials")
		return errors.New("censys: missing API credentials")
	}

	// Construcción de la query: certificados cuyo SAN incluya el dominio.
	query := fmt.Sprintf("parsed.names: %s", domain)
	values := url.Values{}
	values.Set("per_page", "100")
	values.Set("q", query)

	seen := make(map[string]struct{})

	baseURL, err := url.Parse(censysBaseURL)
	if err != nil {
		censysMeta(out, "invalid base URL")
		return fmt.Errorf("censys: invalid base url: %w", err)
	}

	nextURL := fmt.Sprintf("%s?%s", censysBaseURL, values.Encode())

	for nextURL != "" {
		// Cancelación rápida por contexto
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Preparar petición
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			censysMeta(out, "failed creating request: %v", err)
			return err
		}
		req.SetBasicAuth(apiID, apiSecret)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "passive-rec/1.0 (+https://github.com/llvch/passiveRecon)")

		// Hacer petición
		resp, err := censysHTTPClient.Do(req)
		if err != nil {
			censysMeta(out, "request failed: %v", err)
			return err
		}
		// Cierre seguro del body
		func() {
			if resp != nil && resp.Body != nil {
				defer resp.Body.Close()
			}

			if resp.StatusCode != http.StatusOK {
				censysMeta(out, "unexpected HTTP status %d", resp.StatusCode)
				err = fmt.Errorf("censys: unexpected status %d", resp.StatusCode)
				return
			}

			var decoded censysResponse
			if decErr := json.NewDecoder(resp.Body).Decode(&decoded); decErr != nil {
				censysMeta(out, "failed decoding response: %v", decErr)
				err = decErr
				return
			}

			// Procesar resultados
			for _, hit := range decoded.Result.Hits {
				record := certs.Record{Source: "censys"}

				// CommonName preferente, con fallback al nombre bruto
				record.CommonName = strings.TrimSpace(hit.Parsed.Subject.CommonName)
				if record.CommonName == "" {
					record.CommonName = hit.Name
				}

				// DNSNames: mantenemos el orden original (no deduplicamos para no alterar Marshal()).
				record.DNSNames = append(record.DNSNames, hit.Name)
				record.DNSNames = append(record.DNSNames, hit.Parsed.Names...)

				// Subject / Issuer DN
				subjectDN := strings.TrimSpace(hit.Parsed.SubjectDN)
				if subjectDN == "" {
					subjectDN = strings.TrimSpace(hit.Parsed.Subject.DN)
				}
				issuerDN := strings.TrimSpace(hit.Parsed.IssuerDN)
				if issuerDN == "" {
					issuerDN = strings.TrimSpace(hit.Parsed.Issuer.DN)
				}
				if subjectDN != "" {
					record.Subject = subjectDN
				}
				if issuerDN != "" {
					record.Issuer = issuerDN
				} else if cn := strings.TrimSpace(hit.Parsed.Issuer.CommonName); cn != "" {
					record.Issuer = cn
				}

				// Validez y fingerprints
				record.NotBefore = hit.Parsed.Validity.Start
				record.NotAfter = hit.Parsed.Validity.End
				record.SerialNumber = hit.Parsed.SerialNumber
				record.FingerprintSHA256 = hit.FingerprintSHA256
				record.FingerprintSHA1 = hit.FingerprintSHA1
				record.FingerprintMD5 = hit.FingerprintMD5

				record.Normalize()

				// Deduplicación por clave de certificado
				key := record.Key()
				if key == "" {
					continue
				}
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}

				encoded, encErr := record.Marshal()
				if encErr != nil {
					// Silencioso, igual que tu versión
					continue
				}
				out <- "cert: " + encoded
			}

			// Paginación
			next := strings.TrimSpace(decoded.Result.Links.Next)
			if next == "" {
				nextURL = ""
				return
			}

			parsedNext, parseErr := url.Parse(next)
			if parseErr != nil {
				censysMeta(out, "failed parsing next link: %v", parseErr)
				err = fmt.Errorf("censys: parse next link: %w", parseErr)
				return
			}
			if !parsedNext.IsAbs() {
				// Resolver contra la URL de la petición actual o la base
				parsedNext = req.URL.ResolveReference(parsedNext)
				if parsedNext == nil {
					parsedNext = baseURL.ResolveReference(parsedNext)
				}
			}
			nextURL = parsedNext.String()
		}()
		if err != nil { // recoge errores del bloque anterior
			return err
		}
	}

	logx.Debugf("censys query %s: %d resultados", domain, len(seen))
	return nil
}
