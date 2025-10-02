package sources

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"passive-rec/internal/runner"
)

func TestSubJSBinaryMissing(t *testing.T) {
	originalFind := subjsFindBin
	defer func() { subjsFindBin = originalFind }()

	subjsFindBin = func(names ...string) (string, bool) {
		return "", false
	}

	out := make(chan string, 1)
	err := SubJS(context.Background(), filepath.Join("routes", "routes.active"), t.TempDir(), out)
	if !errors.Is(err, runner.ErrMissingBinary) {
		t.Fatalf("expected ErrMissingBinary, got %v", err)
	}
	select {
	case line := <-out:
		expected := "active: meta: subjs not found in PATH"
		if line != expected {
			t.Fatalf("unexpected output: %q", line)
		}
	default:
		t.Fatalf("expected meta output when binary missing")
	}
}

func TestSubJSMissingInputFile(t *testing.T) {
	dir := t.TempDir()
	originalFind := subjsFindBin
	subjsFindBin = func(names ...string) (string, bool) { return "subjs", true }
	originalRun := subjsRunCmd
	subjsRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		t.Fatalf("RunCommand should not be invoked when input is missing")
		return nil
	}
	originalValidator := subjsValidator
	subjsValidator = func(ctx context.Context, urls []string) ([]string, error) { return nil, nil }
	t.Cleanup(func() {
		subjsFindBin = originalFind
		subjsRunCmd = originalRun
		subjsValidator = originalValidator
	})

	out := make(chan string, 1)
	if err := SubJS(context.Background(), filepath.Join("routes", "routes.active"), dir, out); err != nil {
		t.Fatalf("SubJS returned error: %v", err)
	}
	select {
	case line := <-out:
		expected := "active: meta: subjs skipped missing input routes/routes.active"
		if line != expected {
			t.Fatalf("unexpected output: %q", line)
		}
	default:
		t.Fatalf("expected meta output for missing input")
	}
}

func TestSubJSSuccess(t *testing.T) {
	dir := t.TempDir()
	routesDir := filepath.Join(dir, "routes")
	if err := os.MkdirAll(routesDir, 0o755); err != nil {
		t.Fatalf("MkdirAll routes: %v", err)
	}
	routesActive := filepath.Join(routesDir, "routes.active")
	if err := os.WriteFile(routesActive, []byte("https://app.example.com/login [200]\nhttps://app.example.com/login\n"), 0o644); err != nil {
		t.Fatalf("write routes.active: %v", err)
	}

	var (
		mu          sync.Mutex
		receivedCmd []string
		validatorIn []string
	)

	originalFind := subjsFindBin
	originalRun := subjsRunCmd
	originalValidator := subjsValidator
	subjsFindBin = func(names ...string) (string, bool) { return "/usr/bin/subjs", true }
	subjsRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		mu.Lock()
		receivedCmd = append([]string{name}, args...)
		mu.Unlock()
		if len(args) != 2 || args[0] != "-i" {
			t.Fatalf("unexpected args: %v", args)
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			t.Fatalf("expected temp input file readable: %v", err)
		}
		expectedInput := "https://app.example.com/login\n"
		if string(data) != expectedInput {
			t.Fatalf("unexpected input contents: %q", string(data))
		}
		out <- "https://app.example.com/static/app.js"
		out <- "https://app.example.com/static/app.js"
		out <- "https://cdn.example.com/lib.js"
		return nil
	}
	subjsValidator = func(ctx context.Context, urls []string) ([]string, error) {
		mu.Lock()
		defer mu.Unlock()
		validatorIn = append([]string{}, urls...)
		return []string{"https://cdn.example.com/lib.js"}, nil
	}
	t.Cleanup(func() {
		subjsFindBin = originalFind
		subjsRunCmd = originalRun
		subjsValidator = originalValidator
	})

	out := make(chan string, 5)
	if err := SubJS(context.Background(), filepath.Join("routes", "routes.active"), dir, out); err != nil {
		t.Fatalf("SubJS returned error: %v", err)
	}

	mu.Lock()
	cmd := append([]string{}, receivedCmd...)
	mu.Unlock()
	if len(cmd) != 3 {
		t.Fatalf("unexpected command invocation: %v", cmd)
	}
	if cmd[0] != "/usr/bin/subjs" || cmd[1] != "-i" {
		t.Fatalf("unexpected command args: %v", cmd)
	}

	mu.Lock()
	validatorArgs := append([]string{}, validatorIn...)
	mu.Unlock()
	if len(validatorArgs) != 2 {
		t.Fatalf("expected deduplicated output, got %v", validatorArgs)
	}

	select {
	case line := <-out:
		if line != "active: js: https://cdn.example.com/lib.js" {
			t.Fatalf("unexpected sink output: %q", line)
		}
	case <-time.After(time.Second):
		t.Fatalf("expected sink output")
	}
}
