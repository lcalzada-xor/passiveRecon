package sources

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"passive-rec/internal/certs"
	"passive-rec/internal/logx"
)

type crtshEntry struct {
	CommonName   string `json:"common_name"`
	NameValue    string `json:"name_value"`
	IssuerName   string `json:"issuer_name"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	SerialNumber string `json:"serial_number"`
}

func CRTSH(ctx context.Context, domain string, out chan<- string) error {
	logx.Debugf("crtsh query %s", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://crt.sh/?q=%25."+domain+"&output=json", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "passive-rec/1.0 (+https://github.com/llvch/passiveRecon)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logx.Errorf("crtsh http: %v", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logx.Errorf("crtsh non-200: %d", resp.StatusCode)
		return errors.New("crt.sh non-200")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var arr []crtshEntry
	if err := json.Unmarshal(body, &arr); err != nil {
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
	return nil
}
