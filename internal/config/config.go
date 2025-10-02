package config

import (
	"flag"
	"os"
	"strings"
)

type Config struct {
	Target          string
	OutDir          string
	Workers         int
	Active          bool
	Tools           []string
	TimeoutS        int
	Verbosity       int
	Report          bool
	CensysAPIID     string
	CensysAPISecret string
}

func ParseFlags() *Config {
	target := flag.String("target", "", "Target domain (ej: example.com)")
	outdir := flag.String("outdir", ".", "Directorio de salida (default: .)")
	workers := flag.Int("workers", 6, "Número de workers")
	active := flag.Bool("active", false, "Comprobaciones superficiales activas (httpx)")
	tools := flag.String("tools", "subfinder,assetfinder,amass,waybackurls,gau,crtsh,httpx,subjs", "Herramientas, CSV")
	timeout := flag.Int("timeout", 120, "Timeout por herramienta (segundos)")
	verbosity := flag.Int("v", 0, "Verbosity (0=silent,1=info,2=debug,3=trace)")
	report := flag.Bool("report", false, "Generar un informe HTML al finalizar")
	censysID := flag.String("censys-api-id", os.Getenv("CENSYS_API_ID"), "Censys API ID (o exporta CENSYS_API_ID)")
	censysSecret := flag.String("censys-api-secret", os.Getenv("CENSYS_API_SECRET"), "Censys API secret (o exporta CENSYS_API_SECRET)")

	flag.Parse()

	list := []string{}
	for _, t := range strings.Split(*tools, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			list = append(list, t)
		}
	}

	if *outdir == "" {
		*outdir = "."
	}

	return &Config{

		Target:          *target,
		OutDir:          *outdir,
		Workers:         *workers,
		Active:          *active,
		Tools:           list,
		TimeoutS:        *timeout,
		Verbosity:       *verbosity,
		Report:          *report,
		CensysAPIID:     strings.TrimSpace(*censysID),
		CensysAPISecret: strings.TrimSpace(*censysSecret),
	}
}
