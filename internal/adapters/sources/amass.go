package sources

import (
	"context"
	"errors"

	"passive-rec/internal/core/runner"
)

func Amass(ctx context.Context, target string, out chan<- string, active bool) error {
	bin, ok := runner.FindBin("amass")
	if !ok {
		out <- "meta: amass not found in PATH"
		return runner.ErrMissingBinary
	}

	run := func(args []string) error {
		return runner.RunCommand(ctx, bin, args, out)
	}

	passiveArgs := []string{"enum", "-passive", "-d", target}
	passiveErr := run(passiveArgs)
	if !active {
		return passiveErr
	}

	activeArgs := []string{"enum", "-d", target}
	activeErr := run(activeArgs)

	switch {
	case passiveErr == nil:
		return activeErr
	case activeErr == nil:
		return passiveErr
	default:
		return errors.Join(passiveErr, activeErr)
	}
}
