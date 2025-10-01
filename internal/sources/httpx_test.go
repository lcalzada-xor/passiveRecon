package sources

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestHTTPXCombinesAllLists(t *testing.T) {
	tmp := t.TempDir()
	mustWrite := func(name, contents string) {
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(contents), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	mustWrite("domains.passive", "example.com\nsub.example.com\n")
	mustWrite("routes.passive", "https://app.example.com/login\n")

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }

	var mu sync.Mutex
	var gotArgs [][]string
	var inputs [][]string
	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		mu.Lock()
		defer mu.Unlock()
		cp := append([]string{}, args...)
		gotArgs = append(gotArgs, cp)

		if len(args) != 5 {
			t.Fatalf("unexpected arg count %d", len(args))
		}

		data, err := os.ReadFile(args[4])
		if err != nil {
			t.Fatalf("read httpx input: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		inputs = append(inputs, lines)
		return nil
	}

	if err := HTTPX(context.Background(), []string{"domains.passive", "routes.passive"}, tmp, make(chan string, 10)); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	if len(gotArgs) != 1 {
		t.Fatalf("expected 1 call to httpxRunCmd, got %d", len(gotArgs))
	}

	if len(inputs) != 1 {
		t.Fatalf("expected to capture a single input slice, got %d", len(inputs))
	}

	want := []string{"example.com", "sub.example.com", "https://app.example.com/login"}
	if diff := cmp.Diff(want, inputs[0]); diff != "" {
		t.Fatalf("unexpected httpx input (-want +got):\n%s", diff)
	}
}

func TestHTTPXSkipsMissingLists(t *testing.T) {
	tmp := t.TempDir()
	mustWrite := func(name, contents string) {
		if err := os.WriteFile(filepath.Join(tmp, name), []byte(contents), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	mustWrite("routes.passive", "https://app.example.com/login\n")

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }

	var mu sync.Mutex
	var captured [][]string
	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		mu.Lock()
		defer mu.Unlock()
		data, err := os.ReadFile(args[4])
		if err != nil {
			t.Fatalf("read httpx input: %v", err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		captured = append(captured, lines)
		return nil
	}

	outCh := make(chan string, 5)
	if err := HTTPX(context.Background(), []string{"domains.passive", "routes.passive"}, tmp, outCh); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	if len(captured) != 1 {
		t.Fatalf("expected httpxRunCmd to be invoked once, got %d", len(captured))
	}

	wantInput := []string{"https://app.example.com/login"}
	if diff := cmp.Diff(wantInput, captured[0]); diff != "" {
		t.Fatalf("unexpected httpx input (-want +got):\n%s", diff)
	}

	var meta []string
	for len(outCh) > 0 {
		meta = append(meta, <-outCh)
	}
	sort.Strings(meta)

	wantMeta := []string{"meta: httpx skipped missing input domains.passive"}
	if diff := cmp.Diff(wantMeta, meta); diff != "" {
		t.Fatalf("unexpected meta lines (-want +got):\n%s", diff)
	}
}
