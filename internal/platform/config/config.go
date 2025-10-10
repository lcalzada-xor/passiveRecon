package config

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

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
	Proxy           string
	ProxyCACert     string
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
	Proxy           *string     `json:"proxy" yaml:"proxy"`
	ProxyCACert     *string     `json:"proxy_ca" yaml:"proxy_ca"`
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
	active := flag.Bool("active", false, "Comprobaciones activas adicionales (amass/httpx)")
	tools := flag.String("tools", "amass,subfinder,assetfinder,rdap,crtsh,dedupe,dnsx,waybackurls,gau,httpx,subjs,linkfinderevo", "Herramientas, CSV")
	timeout := flag.Int("timeout", 120, "Timeout por herramienta (segundos)")
	verbosity := flag.Int("v", 0, "Verbosity (0=silent,1=info,2=debug,3=trace)")
	report := flag.Bool("report", false, "Generar un informe HTML al finalizar")
	proxy := flag.String("proxy", "", "Proxy HTTP/HTTPS (ej: http://127.0.0.1:8080)")
	proxyCA := flag.String("proxy-ca", "", "Ruta a un certificado CA adicional para mitm proxies")
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
		Proxy:           strings.TrimSpace(*proxy),
		ProxyCACert:     strings.TrimSpace(*proxyCA),
		CensysAPIID:     strings.TrimSpace(*censysID),
		CensysAPISecret: strings.TrimSpace(*censysSecret),
	}

	var fileCfg *fileConfig
	if *configPath != "" {
		info, err := os.Stat(*configPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				log.Fatalf("el archivo de configuración %q no existe", *configPath)
			}
			log.Fatalf("no se pudo acceder al archivo de configuración %q: %v", *configPath, err)
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
		if fileCfg.Proxy != nil && !setFlags["proxy"] {
			cfg.Proxy = strings.TrimSpace(*fileCfg.Proxy)
		}
		if fileCfg.ProxyCACert != nil && !setFlags["proxy-ca"] {
			cfg.ProxyCACert = strings.TrimSpace(*fileCfg.ProxyCACert)
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

// ApplyProxy configures the standard HTTP proxy environment variables when a
// proxy URL is provided. The proxy string must include a scheme and host (for
// example, http://127.0.0.1:8080). The function updates both uppercase and
// lowercase variants so that external tools and Go's HTTP clients honor the
// configuration. It also performs basic validation of the proxy format and
// warns if the proxy appears unreachable.
func ApplyProxy(proxy string) error {
	proxy = strings.TrimSpace(proxy)
	if proxy == "" {
		return nil
	}

	parsed, err := url.Parse(proxy)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("proxy inválido: %q (debe incluir esquema y host, ej: http://127.0.0.1:8080)", proxy)
	}

	// Validar que el esquema sea HTTP o HTTPS
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("proxy inválido: esquema %q no soportado (solo http/https)", parsed.Scheme)
	}

	// Validar que el host tenga un formato válido
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("proxy inválido: host vacío en %q", proxy)
	}

	// Intentar verificar conectividad básica (sin bloquear si falla)
	if err := validateProxyConnectivity(parsed); err != nil {
		log.Printf("advertencia: no se pudo verificar conectividad del proxy %s: %v", proxy, err)
		log.Printf("continuando de todos modos, pero las peticiones pueden fallar si el proxy no está disponible")
	}

	envVars := []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"}
	for _, key := range envVars {
		if err := os.Setenv(key, proxy); err != nil {
			return fmt.Errorf("no se pudo configurar %s: %w", key, err)
		}
	}
	return nil
}

// validateProxyConnectivity performs a basic connectivity check to the proxy.
// Returns an error if the proxy is unreachable, but this is non-fatal.
func validateProxyConnectivity(proxyURL *url.URL) error {
	// Timeout corto para no retrasar el inicio
	timeout := 3 * time.Second

	// Intentar conectar al host del proxy
	host := proxyURL.Host
	if proxyURL.Port() == "" {
		// Añadir puerto por defecto si no está especificado
		if proxyURL.Scheme == "https" {
			host = net.JoinHostPort(proxyURL.Hostname(), "443")
		} else {
			host = net.JoinHostPort(proxyURL.Hostname(), "80")
		}
	}

	conn, err := net.DialTimeout("tcp", host, timeout)
	if err != nil {
		return fmt.Errorf("no se pudo conectar al proxy en %s: %w", host, err)
	}
	conn.Close()
	return nil
}

var (
	customRootCAs   *x509.CertPool
	customRootCAsMu sync.RWMutex
)

// ConfigureRootCAs loads an additional certificate authority bundle from the
// provided path and wires it into the default HTTP transport. When successful,
// the certificates are also exposed through CustomRootCAs so that other
// components can reuse the pool when creating bespoke http.Client instances.
// Passing an empty path clears the cached pool and leaves the default
// transport untouched.
func ConfigureRootCAs(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		customRootCAsMu.Lock()
		customRootCAs = nil
		customRootCAsMu.Unlock()
		return nil
	}

	pool, err := loadRootCAs(path)
	if err != nil {
		return err
	}
	if err := applyRootCAsToDefaultTransport(pool); err != nil {
		return err
	}

	customRootCAsMu.Lock()
	customRootCAs = pool
	customRootCAsMu.Unlock()
	return nil
}

// CustomRootCAs returns the additional certificate authorities configured via
// ConfigureRootCAs, if any. Callers must treat the returned pool as read-only.
func CustomRootCAs() *x509.CertPool {
	customRootCAsMu.RLock()
	defer customRootCAsMu.RUnlock()
	return customRootCAs
}

func loadRootCAs(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("no se pudo leer el certificado CA %q: %w", path, err)
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if pool == nil {
		pool = x509.NewCertPool()
	}
	if ok := pool.AppendCertsFromPEM(data); !ok {
		return nil, fmt.Errorf("no se pudieron parsear certificados en %q", path)
	}
	return pool, nil
}

func applyRootCAsToDefaultTransport(pool *x509.CertPool) error {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return errors.New("http.DefaultTransport no es *http.Transport")
	}

	clone := base.Clone()
	var tlsConfig *tls.Config
	if clone.TLSClientConfig != nil {
		tlsConfig = clone.TLSClientConfig.Clone()
	} else {
		tlsConfig = &tls.Config{}
	}
	tlsConfig.RootCAs = pool
	clone.TLSClientConfig = tlsConfig
	http.DefaultTransport = clone
	return nil
}
