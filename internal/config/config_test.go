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

        if len(cfg.Tools) != 8 {
                t.Fatalf("expected 8 default tools, got %d", len(cfg.Tools))
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
