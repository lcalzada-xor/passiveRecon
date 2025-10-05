package config

import (
	"flag"
	"os"
	"reflect"
	"testing"
)

func prepareFlags(t *testing.T) {
	t.Helper()
	oldCommandLine := flag.CommandLine
	oldArgs := os.Args

	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{oldArgs[0]}

	t.Cleanup(func() {
		flag.CommandLine = oldCommandLine
		os.Args = oldArgs
	})
}

func TestParseFlagsDefaults(t *testing.T) {
	prepareFlags(t)

	cfg := ParseFlags()

	if cfg.Workers != 6 {
		t.Fatalf("expected default workers 6, got %d", cfg.Workers)
	}

	if cfg.OutDir != "." {
		t.Fatalf("expected default outdir '.', got %q", cfg.OutDir)
	}

	expectedTools := []string{"amass", "subfinder", "assetfinder", "crtsh", "dedupe", "waybackurls", "gau", "httpx", "subjs", "linkfinderevo"}
	if !reflect.DeepEqual(cfg.Tools, expectedTools) {
		t.Fatalf("expected default tools %v, got %v", expectedTools, cfg.Tools)
	}

	if cfg.TimeoutS != 120 {
		t.Fatalf("expected default timeout 120, got %d", cfg.TimeoutS)
	}

	if cfg.Active {
		t.Fatalf("expected default active false, got true")
	}

	if cfg.Verbosity != 0 {
		t.Fatalf("expected default verbosity 0, got %d", cfg.Verbosity)
	}

	if cfg.Proxy != "" {
		t.Fatalf("expected default proxy empty, got %q", cfg.Proxy)
	}
}

func TestParseFlagsCustom(t *testing.T) {
	prepareFlags(t)

	os.Args = append(os.Args, []string{
		"-target", "example.com",
		"-tools", "foo, bar , ,baz",
		"-outdir", "",
		"-workers", "3",
		"-timeout", "30",
		"-active=true",
		"-v", "2",
		"-proxy", "http://127.0.0.1:8080",
	}...)

	cfg := ParseFlags()

	expectedTools := []string{"foo", "bar", "baz"}
	if !reflect.DeepEqual(cfg.Tools, expectedTools) {
		t.Fatalf("expected tools %v, got %v", expectedTools, cfg.Tools)
	}

	if cfg.OutDir != "." {
		t.Fatalf("expected outdir '.' when empty string provided, got %q", cfg.OutDir)
	}

	if !cfg.Active {
		t.Fatalf("expected active true, got false")
	}

	if cfg.Workers != 3 {
		t.Fatalf("expected workers 3, got %d", cfg.Workers)
	}

	if cfg.TimeoutS != 30 {
		t.Fatalf("expected timeout 30, got %d", cfg.TimeoutS)
	}

	if cfg.Verbosity != 2 {
		t.Fatalf("expected verbosity 2, got %d", cfg.Verbosity)
	}

	if cfg.Proxy != "http://127.0.0.1:8080" {
		t.Fatalf("expected proxy http://127.0.0.1:8080, got %q", cfg.Proxy)
	}
}

func TestParseFlagsTraceVerbosity(t *testing.T) {
	prepareFlags(t)

	os.Args = append(os.Args, []string{
		"-v", "3",
	}...)

	cfg := ParseFlags()

	if cfg.Verbosity != 3 {
		t.Fatalf("expected verbosity 3, got %d", cfg.Verbosity)
	}
}

func TestApplyProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "")
	t.Setenv("http_proxy", "")
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("https_proxy", "")
	t.Setenv("ALL_PROXY", "")
	t.Setenv("all_proxy", "")

	if err := ApplyProxy("http://127.0.0.1:8080"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := "http://127.0.0.1:8080"
	keys := []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"}
	for _, key := range keys {
		if value := os.Getenv(key); value != expected {
			t.Fatalf("expected %s to be %q, got %q", key, expected, value)
		}
	}
}

func TestApplyProxyInvalid(t *testing.T) {
	if err := ApplyProxy("invalid"); err == nil {
		t.Fatalf("expected error for invalid proxy")
	}
}
