package linkfinderevo

import (
	"fmt"

	"passive-rec/internal/platform/urlutil"
)

func normalizeScope(target string) string {
	return urlutil.NormalizeScope(target)
}

func buildArgs(inputPath, target, rawPath, htmlPath, jsonPath string) []string {
	args := []string{"-i", inputPath, "-d", "-max-depth", "2", "--insecure"}
	if scope := normalizeScope(target); scope != "" {
		args = append(args, "-scope", scope, "--scope-include-subdomains")
	}
	output := fmt.Sprintf("cli,raw=%s,html=%s,json=%s", rawPath, htmlPath, jsonPath)
	args = append(args, "--output", output, "--gf", "all")
	return args
}

func recordError(first *error, candidate error) {
	if candidate == nil {
		return
	}
	if *first == nil {
		*first = candidate
	}
}
