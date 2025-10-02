package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
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

type fileConfig struct {
	Target          *string     `json:"target" yaml:"target"`
	OutDir          *string     `json:"outdir" yaml:"outdir"`
	Workers         *int        `json:"workers" yaml:"workers"`
	Active          *bool       `json:"active" yaml:"active"`
	Tools           *stringList `json:"tools" yaml:"tools"`
	TimeoutS        *int        `json:"timeout" yaml:"timeout"`
	Verbosity       *int        `json:"verbosity" yaml:"verbosity"`
	Report          *bool       `json:"report" yaml:"report"`
	CensysAPIID     *string     `json:"censys_api_id" yaml:"censys_api_id"`
	CensysAPISecret *string     `json:"censys_api_secret" yaml:"censys_api_secret"`
}

type stringList []string

func (s *stringList) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		*s = nil
		return nil
	}

	switch trimmed[0] {
	case '[':
		var aux []string
		if err := json.Unmarshal(trimmed, &aux); err != nil {
			return err
		}
		*s = cleanStringSlice(aux)
		return nil
	case '"':
		var single string
		if err := json.Unmarshal(trimmed, &single); err != nil {
			return err
		}
		*s = cleanStringSlice(strings.Split(single, ","))
		return nil
	default:
		return errors.New("tools debe ser un string o una lista")
	}
}

func (s *stringList) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.SequenceNode:
		aux := make([]string, 0, len(value.Content))
		for _, node := range value.Content {
			aux = append(aux, node.Value)
		}
		*s = cleanStringSlice(aux)
		return nil
	case yaml.ScalarNode:
		*s = cleanStringSlice(strings.Split(value.Value, ","))
		return nil
	case yaml.MappingNode, yaml.DocumentNode:
		return errors.New("tools debe ser un string o una lista")
	default:
		*s = nil
		return nil
	}
}

func ParseFlags() *Config {
	configPath := flag.String("config", "", "Ruta a un archivo de configuración (YAML o JSON)")
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

	setFlags := map[string]bool{}
	flag.Visit(func(f *flag.Flag) {
		setFlags[f.Name] = true
	})

	list := cleanStringSlice(strings.Split(*tools, ","))

	cfg := &Config{
		Target:          strings.TrimSpace(*target),
		OutDir:          strings.TrimSpace(*outdir),
		Workers:         *workers,
		Active:          *active,
		Tools:           list,
		TimeoutS:        *timeout,
		Verbosity:       *verbosity,
		Report:          *report,
		CensysAPIID:     strings.TrimSpace(*censysID),
		CensysAPISecret: strings.TrimSpace(*censysSecret),
	}

	var fileCfg *fileConfig
	if *configPath != "" {
		info, err := os.Stat(*configPath)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Fatalf("no se pudo acceder al archivo de configuración %q: %v", *configPath, err)
			}
		} else if info.IsDir() {
			log.Fatalf("la ruta de configuración %q apunta a un directorio", *configPath)
		} else {
			fc, err := loadConfigFile(*configPath)
			if err != nil {
				log.Fatalf("no se pudo leer la configuración desde %q: %v", *configPath, err)
			}
			fileCfg = fc
		}
	}

	if fileCfg != nil {
		if fileCfg.Target != nil && !setFlags["target"] {
			cfg.Target = strings.TrimSpace(*fileCfg.Target)
		}
		if fileCfg.OutDir != nil && !setFlags["outdir"] {
			cfg.OutDir = strings.TrimSpace(*fileCfg.OutDir)
		}
		if fileCfg.Workers != nil && !setFlags["workers"] {
			cfg.Workers = *fileCfg.Workers
		}
		if fileCfg.Active != nil && !setFlags["active"] {
			cfg.Active = *fileCfg.Active
		}
		if fileCfg.Tools != nil && !setFlags["tools"] {
			cfg.Tools = cleanStringSlice([]string(*fileCfg.Tools))
		}
		if fileCfg.TimeoutS != nil && !setFlags["timeout"] {
			cfg.TimeoutS = *fileCfg.TimeoutS
		}
		if fileCfg.Verbosity != nil && !setFlags["v"] {
			cfg.Verbosity = *fileCfg.Verbosity
		}
		if fileCfg.Report != nil && !setFlags["report"] {
			cfg.Report = *fileCfg.Report
		}
		if fileCfg.CensysAPIID != nil && !setFlags["censys-api-id"] {
			cfg.CensysAPIID = strings.TrimSpace(*fileCfg.CensysAPIID)
		}
		if fileCfg.CensysAPISecret != nil && !setFlags["censys-api-secret"] {
			cfg.CensysAPISecret = strings.TrimSpace(*fileCfg.CensysAPISecret)
		}
	}

	if cfg.OutDir == "" {
		cfg.OutDir = "."
	}

	return cfg
}

func loadConfigFile(path string) (*fileConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg fileConfig
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			return nil, err
		}
	case ".json":
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, err
		}
	default:
		if err := yaml.Unmarshal(raw, &cfg); err != nil {
			if err := json.Unmarshal(raw, &cfg); err != nil {
				return nil, err
			}
		}
	}

	return &cfg, nil
}

func cleanStringSlice(values []string) []string {
	list := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			list = append(list, v)
		}
	}
	return list
}
