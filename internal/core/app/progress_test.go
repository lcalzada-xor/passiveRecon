package app

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"passive-rec/internal/core/runner"
)

func TestProgressBarWrapAndMissingTools(t *testing.T) {
	var buf bytes.Buffer
	pb := newProgressBar(5, &buf)

	if pb == nil {
		t.Fatal("expected progress bar instance")
	}

	if err := pb.Wrap("ToolOk", func() error { return nil })(); err != nil {
		t.Fatalf("wrap ok returned error: %v", err)
	}
	if !strings.Contains(buf.String(), "ToolOk (ok") {
		t.Fatalf("expected ok status in buffer, got: %q", buf.String())
	}

	if err := pb.Wrap("ToolMissing", func() error { return runner.ErrMissingBinary })(); err == nil {
		t.Fatalf("expected missing binary error")
	}
	if !strings.Contains(buf.String(), "ToolMissing (faltante") {
		t.Fatalf("expected missing status in buffer, got: %q", buf.String())
	}

	if err := pb.Wrap("ToolTimeout", func() error { return context.DeadlineExceeded })(); err == nil {
		t.Fatalf("expected deadline exceeded error")
	}
	if !strings.Contains(buf.String(), "ToolTimeout (timeout") {
		t.Fatalf("expected timeout status in buffer, got: %q", buf.String())
	}

	if !strings.Contains(buf.String(), "ETA") {
		t.Fatalf("expected ETA information in buffer, got: %q", buf.String())
	}

	pb.StepDone("toolmissing", "faltante")
	pb.StepDone("TOOLMISSING", "faltante")

	missing := pb.MissingTools()
	if len(missing) != 1 || missing[0] != "ToolMissing" {
		t.Fatalf("expected deduplicated missing tools, got: %#v", missing)
	}

	if !strings.HasSuffix(buf.String(), "\n") {
		t.Fatalf("expected buffer to end with newline after completing steps, got: %q", buf.String())
	}
}

func TestProgressBarStepRunning(t *testing.T) {
	var buf bytes.Buffer
	pb := newProgressBar(2, &buf)

	pb.StepRunning("ToolRun")

	if !strings.Contains(buf.String(), "ToolRun (inicio") {
		t.Fatalf("expected running status with inicio label in buffer, got: %q", buf.String())
	}
}
