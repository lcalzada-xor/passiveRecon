package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"passive-rec/internal/certs"
	"passive-rec/internal/logx"
)

var (
	censysBaseURL    = "https://search.censys.io/api/v2/certificates/search"
	censysHTTPClient = http.DefaultClient
)

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
		return errors.New("censys: empty domain")
	}
	if apiID == "" || apiSecret == "" {
		return errors.New("censys: missing API credentials")
	}

	query := fmt.Sprintf("parsed.names: %s", domain)
	values := url.Values{}
	values.Set("per_page", "100")
	values.Set("q", query)

	seen := map[string]struct{}{}

	baseURL, err := url.Parse(censysBaseURL)
	if err != nil {
		return fmt.Errorf("censys: invalid base url: %w", err)
	}

	nextURL := fmt.Sprintf("%s?%s", censysBaseURL, values.Encode())
	for nextURL != "" {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, nextURL, nil)
		if err != nil {
			return err
		}
		req.SetBasicAuth(apiID, apiSecret)
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "passive-rec/1.0 (+https://github.com/llvch/passiveRecon)")

		resp, err := censysHTTPClient.Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			if resp.Body != nil {
				resp.Body.Close()
			}
			return fmt.Errorf("censys: unexpected status %d", resp.StatusCode)
		}

		var decoded censysResponse
		if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
			resp.Body.Close()
			return err
		}
		resp.Body.Close()

		for _, hit := range decoded.Result.Hits {
			record := certs.Record{Source: "censys"}
			record.CommonName = hit.Parsed.Subject.CommonName
			if record.CommonName == "" {
				record.CommonName = hit.Name
			}
			record.DNSNames = append(record.DNSNames, hit.Name)
			record.DNSNames = append(record.DNSNames, hit.Parsed.Names...)
			subjectDN := strings.TrimSpace(hit.Parsed.SubjectDN)
			if subjectDN == "" {
				subjectDN = hit.Parsed.Subject.DN
			}
			issuerDN := strings.TrimSpace(hit.Parsed.IssuerDN)
			if issuerDN == "" {
				issuerDN = hit.Parsed.Issuer.DN
			}
			if subjectDN != "" {
				record.Subject = subjectDN
			}
			if issuerDN != "" {
				record.Issuer = issuerDN
			} else if hit.Parsed.Issuer.CommonName != "" {
				record.Issuer = hit.Parsed.Issuer.CommonName
			}
			record.NotBefore = hit.Parsed.Validity.Start
			record.NotAfter = hit.Parsed.Validity.End
			record.SerialNumber = hit.Parsed.SerialNumber
			record.FingerprintSHA256 = hit.FingerprintSHA256
			record.FingerprintSHA1 = hit.FingerprintSHA1
			record.FingerprintMD5 = hit.FingerprintMD5
			record.Normalize()

			key := record.Key()
			if key == "" {
				continue
			}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}

			encoded, err := record.Marshal()
			if err != nil {
				continue
			}
			out <- "cert: " + encoded
		}

		next := strings.TrimSpace(decoded.Result.Links.Next)
		if next == "" {
			nextURL = ""
			continue
		}

		parsedNext, err := url.Parse(next)
		if err != nil {
			return fmt.Errorf("censys: parse next link: %w", err)
		}
		if !parsedNext.IsAbs() {
			// Resolve relative links against either the last requested URL or the
			// configured base URL when pagination uses relative references.
			if req != nil && req.URL != nil {
				parsedNext = req.URL.ResolveReference(parsedNext)
			} else {
				parsedNext = baseURL.ResolveReference(parsedNext)
			}
		}
		nextURL = parsedNext.String()
	}

	logx.Debugf("censys query %s: %d resultados", domain, len(seen))
	return nil
}
