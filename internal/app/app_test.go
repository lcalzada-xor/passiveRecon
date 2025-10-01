package app

import (
	"context"
	"testing"
	"time"
)

func TestRunWithTimeoutDefault(t *testing.T) {
	parent := context.Background()
	invoked := false

	err := runWithTimeout(parent, 0, func(ctx context.Context) error {
		invoked = true

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}

		deadline, ok := ctx.Deadline()
		if !ok {
			t.Fatalf("expected deadline to be set when timeout is zero")
		}
		if remaining := time.Until(deadline); remaining < time.Second {
			t.Fatalf("expected generous timeout, got remaining=%s", remaining)
		}
		return nil
	})()

	if err != nil {
		t.Fatalf("runWithTimeout returned error: %v", err)
	}
	if !invoked {
		t.Fatalf("expected function to be invoked")
	}
}
