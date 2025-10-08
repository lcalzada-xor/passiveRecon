package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"passive-rec/internal/platform/logx"
)

var ErrMissingBinary = errors.New("missing binary")

// findBinaryMatchingVersion recorre binarios candidatos y devuelve el primero cuyo
// `-version` contenga la subcadena indicada (case-insensitive). Añadimos un timeout
// corto por binario para evitar bloqueos.
func findBinaryMatchingVersion(match string, candidates ...string) (string, error) {
	match = strings.ToLower(match)
	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate)
		if err != nil {
			continue
		}
		// Timeout defensivo para comandos colgados en -version.
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		cmd := exec.CommandContext(ctx, path, "-version")
		output, execErr := cmd.CombinedOutput()
		cancel()
		if execErr != nil {
			continue
		}
		if strings.Contains(strings.ToLower(string(output)), match) {
			return path, nil
		}
	}
	return "", ErrMissingBinary
}

// HTTPXBin intenta localizar el binario httpx de ProjectDiscovery.
// Evita confundirlo con el CLI de Python llamado "httpx".
func HTTPXBin() (string, error) {
	return findBinaryMatchingVersion("projectdiscovery", "httpx", "httpx-toolkit")
}

// DNSXBin intenta localizar el binario dnsx de ProjectDiscovery.
func DNSXBin() (string, error) {
	return findBinaryMatchingVersion("projectdiscovery", "dnsx")
}

func HasBin(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// FindBin devuelve el primer binario disponible en PATH de la lista.
func FindBin(names ...string) (string, bool) {
	for _, name := range names {
		if HasBin(name) {
			return name, true
		}
	}
	return "", false
}

func RunCommand(ctx context.Context, name string, args []string, out chan<- string) error {
	return runCommand(ctx, name, args, out, "")
}

// RunCommandWithDir ejecuta el comando en el directorio indicado.
// Redirige stdout línea a línea al canal out. Si dir está vacío,
// equivale a RunCommand.
func RunCommandWithDir(ctx context.Context, dir string, name string, args []string, out chan<- string) error {
	return runCommand(ctx, name, args, out, dir)
}

func runCommand(ctx context.Context, name string, args []string, out chan<- string, dir string) error {
	resolvedPath, lookErr := exec.LookPath(name)
	if lookErr != nil {
		logx.Tracef("lookup %s: %v", name, lookErr)
	}

	cmd := exec.CommandContext(ctx, name, args...)

	if resolvedPath != "" {
		cmd.Path = resolvedPath
	}
	if dir != "" {
		cmd.Dir = dir
	}

	argsJoined := strings.Join(args, " ")
	if argsJoined == "" {
		argsJoined = "<none>"
	}

	deadlineInfo := "none"
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		deadlineInfo = fmt.Sprintf("%s (~%s)", deadline.Format(time.RFC3339), remaining.Round(time.Millisecond))
	}

	envInfo := "inherit"
	if cmd.Env != nil {
		envInfo = fmt.Sprintf("custom (%d vars)", len(cmd.Env))
	}

	logx.Debugf("run: %s %s", name, argsJoined)
	logx.Tracef("command details name=%s path=%q args=%q dir=%q deadline=%s env=%s",
		name, cmd.Path, args, cmd.Dir, deadlineInfo, envInfo)

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

	// Escucha de stderr (debug), con buffer ampliado.
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for sc.Scan() {
			logx.Debugf("%s stderr: %s", name, sc.Text())
		}
		if e := sc.Err(); e != nil {
			logx.Tracef("%s stderr scan error: %v", name, e)
		}
	}()

	// Lectura de stdout con buffer ampliado para líneas largas.
	sc := bufio.NewScanner(stdout)
	// Algunos programas (httpx, gau, etc.) pueden emitir líneas >64KiB.
	sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)

	lines := 0
readLoop:
	for sc.Scan() {
		line := sc.Text()
		// Envío "context-aware" para no quedar bloqueados si out no lee y el ctx se cancela.
		select {
		case <-ctx.Done():
			logx.Warnf("ctx cancel %s", name)
			break readLoop
		case out <- line:
			lines++
		}
	}
	// Error del scanner (solo si no es por ctx cancel).
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		logx.Errorf("scan %s: %v", name, err)
		_ = cmd.Wait() // asegurar recolección
		return err
	}

	// Espera de finalización del proceso.
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			logx.Debugf("wait after ctx cancel %s: %v", name, err)
		} else {
			logx.Errorf("wait %s: %v", name, err)
			return err
		}
	}

	// Si el contexto se canceló, devolvemos su error.
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}

	duration := time.Since(start)
	exitCode := 0
	if state := cmd.ProcessState; state != nil {
		exitCode = state.ExitCode()
	}
	logx.Debugf("done: %s", name)
	logx.Tracef("command finished name=%s exit=%d duration=%s lines=%d",
		name, exitCode, duration.Round(time.Millisecond), lines)

	return nil
}

// WithTimeout retorna un ctx con timeout (por defecto 120s).
func WithTimeout(parent context.Context, seconds int) (context.Context, context.CancelFunc) {
	if seconds <= 0 {
		seconds = 120
	}
	return context.WithTimeout(parent, time.Duration(seconds)*time.Second)
}
