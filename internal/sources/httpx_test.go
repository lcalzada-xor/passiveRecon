package sources

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestHTTPXIteratesAllLists(t *testing.T) {
	tmp := t.TempDir()
	mustWrite := func(name string) {
		if err := os.WriteFile(filepath.Join(tmp, name), []byte("example.com"), 0644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	mustWrite("domains.passive")
	mustWrite("routes.passive")

	originalBinFinder := httpxBinFinder
	originalRunCmd := httpxRunCmd
	t.Cleanup(func() {
		httpxBinFinder = originalBinFinder
		httpxRunCmd = originalRunCmd
	})

	httpxBinFinder = func() (string, error) { return "httpx", nil }

	var mu sync.Mutex
	var got [][]string
	httpxRunCmd = func(ctx context.Context, name string, args []string, out chan<- string) error {
		mu.Lock()
		defer mu.Unlock()
		cp := append([]string{}, args...)
		got = append(got, cp)
		return nil
	}

	if err := HTTPX(context.Background(), []string{"domains.passive", "routes.passive"}, tmp, make(chan string, 10)); err != nil {
		t.Fatalf("HTTPX returned error: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 calls to httpxRunCmd, got %d", len(got))
	}

	wantPaths := []string{
		filepath.Join(tmp, "domains.passive"),
		filepath.Join(tmp, "routes.passive"),
	}
	for i, args := range got {
		if len(args) != 5 {
			t.Fatalf("call %d: unexpected arg count %d", i, len(args))
		}
		if args[4] != wantPaths[i] {
			t.Fatalf("call %d: expected path %s, got %s", i, wantPaths[i], args[4])
		}
	}
}
