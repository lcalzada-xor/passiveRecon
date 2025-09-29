package runner

import (
	"bufio"
	"context"
	"os/exec"
	"strings"
	"time"

	"passive-rec/internal/logx"
)

func HasBin(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func RunCommand(ctx context.Context, name string, args []string, out chan<- string) error {
	logx.V(2, "run: %s %s", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logx.V(1, "stdout pipe %s: %v", name, err)
		return err
	}
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		logx.V(1, "start %s: %v", name, err)
		return err
	}

	// stderr debug
	go func() {
		s := bufio.NewScanner(stderr)
		for s.Scan() {
			logx.V(2, "%s stderr: %s", name, s.Text())
		}
	}()

	s := bufio.NewScanner(stdout)
	for s.Scan() {
		select {
		case <-ctx.Done():
			logx.V(1, "ctx cancel %s", name)
			return ctx.Err()
		default:
			out <- s.Text()
		}
	}
	if err := s.Err(); err != nil {
		logx.V(1, "scan %s: %v", name, err)
		return err
	}
	if err := cmd.Wait(); err != nil {
		logx.V(1, "wait %s: %v", name, err)
		return err
	}
	logx.V(2, "done: %s", name)
	return nil
}

func WithTimeout(parent context.Context, seconds int) (context.Context, context.CancelFunc) {
	if seconds <= 0 {
		seconds = 120
	}
	return context.WithTimeout(parent, time.Duration(seconds)*time.Second)
}
