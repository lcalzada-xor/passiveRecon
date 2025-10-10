package linkfinderevo

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

func accumulateResults(jsonPath string, agg *aggregate) error {
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read results json: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}

	var p payload
	if err := json.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("unmarshal results: %w", err)
	}

	for _, r := range p.Resources {
		for _, ep := range r.Endpoints {
			agg.add(r.Resource, ep)
		}
	}
	return nil
}

func accumulateGFFindings(jsonPath string, agg *gfAggregate) error {
	if agg == nil {
		return nil
	}
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read gf json: %w", err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}

	type gfReport struct {
		Findings []struct {
			Resource string   `json:"resource"`
			Line     int      `json:"line"`
			Evidence string   `json:"evidence"`
			Context  string   `json:"context"`
			Rules    []string `json:"rules"`
		} `json:"findings"`
	}

	var report gfReport
	if err := json.Unmarshal(data, &report); err != nil {
		return fmt.Errorf("unmarshal gf: %w", err)
	}

	for _, f := range report.Findings {
		agg.add(f.Resource, f.Line, f.Evidence, f.Context, f.Rules)
	}
	return nil
}
