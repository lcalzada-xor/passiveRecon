package runner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFindBin(t *testing.T) {
	tmpDir := t.TempDir()
	toolPath := filepath.Join(tmpDir, "toolB")
	if err := os.WriteFile(toolPath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("failed to create executable: %v", err)
	}

	t.Setenv("PATH", tmpDir)

	if name, ok := FindBin("missing", "toolB"); !ok || name != "toolB" {
		t.Fatalf("expected to find toolB, got %q, %v", name, ok)
	}

	if name, ok := FindBin("missing", "another"); ok || name != "" {
		t.Fatalf("expected no binary, got %q, %v", name, ok)
	}
}

func TestWithTimeout(t *testing.T) {
	const tolerance = time.Second

	ctx, cancel := WithTimeout(context.Background(), 0)
	defer cancel()

	deadline, ok := ctx.Deadline()
	if !ok {
		t.Fatal("expected deadline for default timeout")
	}

	remaining := time.Until(deadline)
	if diff := time.Duration(absDuration(remaining - 120*time.Second)); diff > tolerance {
		t.Fatalf("expected default timeout near 120s, got %v (diff %v)", remaining, diff)
	}

	ctxExplicit, cancelExplicit := WithTimeout(context.Background(), 5)
	defer cancelExplicit()

	explicitDeadline, ok := ctxExplicit.Deadline()
	if !ok {
		t.Fatal("expected deadline for explicit timeout")
	}

	explicitRemaining := time.Until(explicitDeadline)
	if diff := time.Duration(absDuration(explicitRemaining - 5*time.Second)); diff > tolerance {
		t.Fatalf("expected explicit timeout near 5s, got %v (diff %v)", explicitRemaining, diff)
	}
}

func TestRunCommandCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "block.sh")
	script := "#!/bin/sh\n\necho $$\nwhile true; do sleep 1; done\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("failed to create script: %v", err)
	}

	out := make(chan string, 1)
	done := make(chan error, 1)

	go func() {
		done <- RunCommand(ctx, scriptPath, nil, out)
	}()

	var pidLine string
	select {
	case pidLine = <-out:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for process pid")
	}
	if pidLine == "" {
		t.Fatal("empty pid line from process")
	}

	cancel()

	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}

	procPath := filepath.Join("/proc", pidLine)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(procPath); os.IsNotExist(err) {
			break
		} else if err != nil {
			t.Fatalf("stat %s: %v", procPath, err)
		}

		if time.Now().After(deadline) {
			t.Fatalf("process %s still running after cancellation", pidLine)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
