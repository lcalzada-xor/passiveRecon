package app

import (
	"context"
	"errors"

	"passive-rec/internal/core/runner"
)

func classifyStepError(err error) string {
	if err == nil {
		return "ok"
	}
	switch {
	case errors.Is(err, runner.ErrMissingBinary):
		return "faltante"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "error"
	}
}
