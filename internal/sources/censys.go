package sources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"passive-rec/internal/logx"
)

var (
	censysBaseURL    = "https://search.censys.io/api/v2/certificates/search"
	censysHTTPClient = http.DefaultClient
)

type censysResponse struct {
	Result struct {
		Hits []struct {
			Name   string `json:"name"`
			Parsed struct {
				Names   []string `json:"names"`
				Subject struct {
					CommonName string `json:"common_name"`
				} `json:"subject"`
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
	send := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out <- key
	}

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
			if hit.Name != "" {
				send(hit.Name)
			}
			if cn := hit.Parsed.Subject.CommonName; cn != "" {
				send(cn)
			}
			for _, name := range hit.Parsed.Names {
				send(name)
			}
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
