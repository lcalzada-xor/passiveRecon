package sources

import (
	"context"
	"errors"

	"passive-rec/internal/runner"
)

func Amass(ctx context.Context, target string, out chan<- string, active bool) error {
	if !runner.HasBin("amass") {
		out <- "meta: amass not found in PATH"
		return runner.ErrMissingBinary
	}

	passiveArgs := []string{"enum", "-passive", "-d", target}
	passiveErr := runner.RunCommand(ctx, "amass", passiveArgs, out)
	if !active {
		return passiveErr
	}

	activeArgs := []string{"enum", "-d", target}
	activeErr := runner.RunCommand(ctx, "amass", activeArgs, out)

	switch {
	case passiveErr == nil:
		return activeErr
	case activeErr == nil:
		return passiveErr
	default:
		return errors.Join(passiveErr, activeErr)
	}
}
