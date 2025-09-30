package sources

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"passive-rec/internal/logx"
)

func CRTSH(ctx context.Context, domain string, out chan<- string) error {
	logx.V(2, "crtsh query %s", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://crt.sh/?q=%25."+domain+"&output=json", nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "passive-rec/1.0 (+https://github.com/llvch/passiveRecon)")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		logx.V(1, "crtsh http: %v", err)
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logx.V(1, "crtsh non-200: %d", resp.StatusCode)
		return errors.New("crt.sh non-200")
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var arr []map[string]any
	if err := json.Unmarshal(body, &arr); err != nil {
		logx.V(1, "crtsh json: %v", err)
		return err
	}
	for _, o := range arr {
		if v, ok := o["name_value"].(string); ok {
			for _, p := range strings.Split(v, "\n") {
				p = strings.TrimSpace(p)
				if p != "" {
					out <- p
				}
			}
		}
	}
	return nil
}
