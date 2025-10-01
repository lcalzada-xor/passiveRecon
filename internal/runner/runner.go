package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"passive-rec/internal/logx"
)

var ErrMissingBinary = errors.New("missing binary")

// findBinaryMatchingVersion iterates over candidate binary names and returns the
// first one whose `-version` output contains the provided substring. The
// comparison is performed using a case-insensitive match. If no binary matches
// the search criteria ErrMissingBinary is returned.
func findBinaryMatchingVersion(match string, candidates ...string) (string, error) {
	match = strings.ToLower(match)
	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}

		cmd := exec.Command(path, "-version")
		output, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}

		if strings.Contains(strings.ToLower(string(output)), match) {
			return path, nil
		}
	}

	return "", ErrMissingBinary
}

// HTTPXBin attempts to locate the ProjectDiscovery httpx binary. This avoids
// accidentally picking the Python `httpx` CLI, which is incompatible with the
// flags used by passive-rec.
func HTTPXBin() (string, error) {
	return findBinaryMatchingVersion("projectdiscovery", "httpx", "httpx-toolkit")
}

func HasBin(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// FindBin returns the first binary name from the provided list that is available
// on the current PATH. If none of the binaries are found the returned string is
// empty and the second boolean value is false.
func FindBin(names ...string) (string, bool) {
	for _, name := range names {
		if HasBin(name) {
			return name, true
		}
	}
	return "", false
}

func RunCommand(ctx context.Context, name string, args []string, out chan<- string) error {
	resolvedPath, lookErr := exec.LookPath(name)
	if lookErr != nil {
		logx.Tracef("lookup %s: %v", name, lookErr)
	}

	cmd := exec.CommandContext(ctx, name, args...)

	if resolvedPath != "" {
		cmd.Path = resolvedPath
	}

	argsJoined := strings.Join(args, " ")
	if argsJoined == "" {
		argsJoined = "<none>"
	}

	deadline, hasDeadline := ctx.Deadline()
	deadlineInfo := "none"
	if hasDeadline {
		remaining := time.Until(deadline)
		deadlineInfo = fmt.Sprintf("%s (~%s)", deadline.Format(time.RFC3339), remaining.Round(time.Millisecond))
	}

	envInfo := "inherit"
	if cmd.Env != nil {
		envInfo = fmt.Sprintf("custom (%d vars)", len(cmd.Env))
	}

	logx.Debugf("run: %s %s", name, argsJoined)
	logx.Tracef("command details name=%s path=%q args=%q dir=%q deadline=%s env=%s", name, cmd.Path, args, cmd.Dir, deadlineInfo, envInfo)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logx.Errorf("stdout pipe %s: %v", name, err)
		return err
	}
	stderr, _ := cmd.StderrPipe()

	start := time.Now()

	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return ErrMissingBinary
		}
		logx.Errorf("start %s: %v", name, err)
		return err
	}

	// stderr debug
	go func() {
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			logx.Debugf("%s stderr: %s", name, s.Text())
		}
	}()

	s := bufio.NewScanner(stdout)
	lines := 0
	var ctxErr error
loop:
	for s.Scan() {
		select {
		case <-ctx.Done():
			logx.Warnf("ctx cancel %s", name)
			ctxErr = ctx.Err()
			break loop
		default:
			lines++
			out <- s.Text()
		}
	}
	if ctxErr == nil {
		select {
		case <-ctx.Done():
			logx.Warnf("ctx cancel %s", name)
			ctxErr = ctx.Err()
		default:
		}
	}
	if err := s.Err(); err != nil && ctxErr == nil {
		logx.Errorf("scan %s: %v", name, err)
		return err
	}
	if err := cmd.Wait(); err != nil {
		if ctxErr != nil {
			logx.Debugf("wait after ctx cancel %s: %v", name, err)
		} else {
			logx.Errorf("wait %s: %v", name, err)
			return err
		}
	}
	if ctxErr != nil {
		return ctxErr
	}
	duration := time.Since(start)
	exitCode := 0
	if state := cmd.ProcessState; state != nil {
		exitCode = state.ExitCode()
	}
	logx.Debugf("done: %s", name)
	logx.Tracef("command finished name=%s exit=%d duration=%s lines=%d", name, exitCode, duration.Round(time.Millisecond), lines)
	return nil
}

func WithTimeout(parent context.Context, seconds int) (context.Context, context.CancelFunc) {
	if seconds <= 0 {
		seconds = 120
	}
	return context.WithTimeout(parent, time.Duration(seconds)*time.Second)
}
