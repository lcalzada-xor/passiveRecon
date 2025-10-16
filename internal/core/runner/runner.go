package runner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	apperrors "passive-rec/internal/platform/errors"
	"passive-rec/internal/platform/logx"
)

var ErrMissingBinary = errors.New("missing binary")

// findBinaryMatchingVersion recorre binarios candidatos y devuelve el primero cuyo
// `-version` contenga la subcadena indicada (case-insensitive). Añadimos un timeout
// corto por binario para evitar bloqueos.
func findBinaryMatchingVersion(match string, candidates ...string) (string, error) {
	match = strings.ToLower(match)
	searchPaths := os.Getenv("PATH")

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

	// Retornar error mejorado si no se encuentra
	if len(candidates) > 0 {
		return "", apperrors.NewMissingBinaryError(candidates[0], strings.Split(searchPaths, ":")...)
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

// HasBin checks if a binary with the given name is available in the system PATH.
// Returns true if the binary exists and is executable, false otherwise.
func HasBin(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// FindBin searches for the first available binary from the provided list of names.
// It returns the name of the first binary found in PATH and true, or empty string
// and false if none of the binaries are available.
func FindBin(names ...string) (string, bool) {
	for _, name := range names {
		if HasBin(name) {
			return name, true
		}
	}
	return "", false
}

// RunCommand executes an external command and streams its stdout line-by-line to the
// provided channel. The command respects context cancellation and will be terminated
// if the context is cancelled. Returns ErrMissingBinary if the binary is not found,
// or any other error encountered during execution.
func RunCommand(ctx context.Context, name string, args []string, out chan<- string) error {
	return runCommand(ctx, name, args, out, "")
}

// RunCommandWithDir executes an external command in the specified working directory.
// It behaves identically to RunCommand but sets the working directory before execution.
// If dir is empty, it behaves exactly like RunCommand (uses the current directory).
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

	logx.Debug("Ejecutando comando", logx.Fields{"name": name, "args": argsJoined})
	logx.Trace("Detalles del comando", logx.Fields{
		"path": cmd.Path,
		"dir": cmd.Dir,
		"deadline": deadlineInfo,
		"env": envInfo,
	})

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		logx.Error("Error stdout pipe", logx.Fields{"command": name, "error": err.Error()})
		return err
	}
	stderr, _ := cmd.StderrPipe()

	start := time.Now()

	if err := cmd.Start(); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			searchPaths := os.Getenv("PATH")
			return apperrors.NewMissingBinaryError(name, strings.Split(searchPaths, ":")...)
		}
		logx.Error("Error iniciar comando", logx.Fields{"command": name, "error": err.Error()})
		return err
	}

	// Escucha de stderr (debug), con buffer ampliado.
	go func() {
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
		for sc.Scan() {
			logx.Debug("Stderr", logx.Fields{"command": name, "output": sc.Text()})
		}
		if e := sc.Err(); e != nil {
			logx.Trace("Stderr scan error", logx.Fields{"command": name, "error": e.Error()})
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
			logx.Warn("Context cancelado", logx.Fields{"command": name})
			break readLoop
		case out <- line:
			lines++
		}
	}
	// Error del scanner (solo si no es por ctx cancel).
	if err := sc.Err(); err != nil && ctx.Err() == nil {
		logx.Error("Error scan", logx.Fields{"command": name, "error": err.Error()})
		_ = cmd.Wait() // asegurar recolección
		return err
	}

	// Espera de finalización del proceso.
	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			logx.Debug("Wait after context cancel", logx.Fields{"command": name, "error": err.Error()})
		} else {
			logx.Error("Error wait", logx.Fields{"command": name, "error": err.Error()})
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
	logx.Debug("Comando completado", logx.Fields{"command": name})
	logx.Trace("Detalles del comando finalizado", logx.Fields{
		"exit_code": exitCode,
		"duration_ms": duration.Milliseconds(),
		"lines": lines,
	})

	return nil
}

// WithTimeout creates a new context with a timeout derived from the parent context.
// If seconds is less than or equal to 0, a default timeout of 120 seconds is used.
// Returns the new context and a cancel function that should be called to release resources.
func WithTimeout(parent context.Context, seconds int) (context.Context, context.CancelFunc) {
	if seconds <= 0 {
		seconds = 120
	}
	return context.WithTimeout(parent, time.Duration(seconds)*time.Second)
}
