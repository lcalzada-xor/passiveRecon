package runner

import (
	"context"
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

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
