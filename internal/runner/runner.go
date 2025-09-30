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
	logx.Debugf("run: %s %s", name, strings.Join(args, " "))
	cmd := exec.CommandContext(ctx, name, args...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logx.Errorf("stdout pipe %s: %v", name, err)
		return err
	}
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
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
	for s.Scan() {
		select {
		case <-ctx.Done():
			logx.Warnf("ctx cancel %s", name)
			return ctx.Err()
		default:
			out <- s.Text()
		}
	}
	if err := s.Err(); err != nil {
		logx.Errorf("scan %s: %v", name, err)
		return err
	}
	if err := cmd.Wait(); err != nil {
		logx.Errorf("wait %s: %v", name, err)
		return err
	}
	logx.Debugf("done: %s", name)
	return nil
}

func WithTimeout(parent context.Context, seconds int) (context.Context, context.CancelFunc) {
	if seconds <= 0 {
		seconds = 120
	}
	return context.WithTimeout(parent, time.Duration(seconds)*time.Second)
}
