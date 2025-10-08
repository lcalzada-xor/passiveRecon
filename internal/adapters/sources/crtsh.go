package sources

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"passive-rec/internal/platform/certs"
	"passive-rec/internal/platform/logx"
)

type crtshEntry struct {
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"`
	IssuerName   string `json:"issuer_name"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	SerialNumber string `json:"serial_number"`
}

func CRTSH(ctx context.Context, domain string, out chan<- string) (err error) {
	logx.Debugf("crtsh query %s", domain)

	u, _ := url.Parse("https://crt.sh/")
	q := url.Values{}
	// buscamos SAN que contenga subdominios del dominio objetivo: %.example.com
	q.Set("q", "%."+domain)
	q.Set("output", "json")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "passive-rec/1.0 (+https://github.com/llvch/passiveRecon)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logx.Errorf("crtsh http: %v", err)
		return err
	}
	defer func() {
		if closeErr := resp.Body.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()

	if resp.StatusCode != http.StatusOK {
		logx.Errorf("crtsh non-200: %d", resp.StatusCode)
		return errors.New("crt.sh non-200")
	}

	var arr []crtshEntry
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&arr); err != nil {
		logx.Errorf("crtsh json: %v", err)
		return err
	}

	seen := make(map[string]struct{})
	for _, entry := range arr {
		record := certs.Record{
			Source:       "crt.sh",
			CommonName:   entry.CommonName,
			DNSNames:     strings.Split(entry.NameValue, "\n"),
			Issuer:       entry.IssuerName,
			NotBefore:    entry.NotBefore,
			NotAfter:     entry.NotAfter,
			SerialNumber: entry.SerialNumber,
		}
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

	logx.Tracef("crtsh %s: %d certificados únicos", domain, len(seen))
	return nil
}
