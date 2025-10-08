package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type installMethod int

const (
	methodGoModule installMethod = iota
	methodGit
)

type requirement struct {
	binary string
	spec   string
	method installMethod
	repo   string
	ref    string
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if _, err := exec.LookPath("go"); err != nil {
		return errors.New("go binary not found in PATH; install Go to proceed")
	}

	reqPath, err := locateRequirements()
	if err != nil {
		return err
	}

	reqs, err := parseRequirements(reqPath)
	if err != nil {
		return err
	}

	if len(reqs) == 0 {
		fmt.Println("No requirements found.")
		return nil
	}

	for _, req := range reqs {
		if path, err := exec.LookPath(req.binary); err == nil {
			fmt.Printf("Updating %s (currently at %s) from %s...\n", req.binary, path, req.spec)
		} else {
			fmt.Printf("Installing %s from %s...\n", req.binary, req.spec)
		}

		if err := installRequirement(req); err != nil {
			return fmt.Errorf("failed to install %s: %w", req.binary, err)
		}
	}

	fmt.Println("All requirements satisfied.")
	return nil
}

func locateRequirements() (string, error) {
	start, err := os.Getwd()
	if err != nil {
		return "", err
	}

	dir := start
	for {
		candidate := filepath.Join(dir, "requirements.txt")
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("requirements.txt not found starting from %s", start)
}

func parseRequirements(path string) ([]requirement, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	var reqs []requirement
	scanner := bufio.NewScanner(file)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("invalid format in %s at line %d: expected '<binary> <module[@version]>'", path, lineNumber)
		}

		req := requirement{
			binary: fields[0],
			spec:   fields[1],
			method: methodGoModule,
		}

		if strings.HasPrefix(fields[1], "git+") {
			repo := strings.TrimPrefix(fields[1], "git+")
			ref := ""
			if at := strings.LastIndex(repo, "@"); at != -1 {
				ref = repo[at+1:]
				repo = repo[:at]
			}

			req.method = methodGit
			req.repo = repo
			req.ref = ref
		}

		reqs = append(reqs, req)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return reqs, nil
}

func installRequirement(req requirement) error {
	switch req.method {
	case methodGit:
		return installFromGit(req)
	default:
		return installGoModule(req.spec)
	}
}

func installGoModule(module string) error {
	cmd := exec.Command("go", "install", module)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}

func installFromGit(req requirement) error {
	if req.repo == "" {
		return errors.New("git repository URL not provided")
	}

	if _, err := exec.LookPath("git"); err != nil {
		return errors.New("git binary not found in PATH; install Git to proceed")
	}

	tempDir, err := os.MkdirTemp("", "passive-recon-install-")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(tempDir)
	}()

	clone := exec.Command("git", "clone", req.repo, tempDir)
	clone.Stdout = os.Stdout
	clone.Stderr = os.Stderr
	if err := clone.Run(); err != nil {
		return err
	}

	if req.ref != "" {
		checkout := exec.Command("git", "-C", tempDir, "checkout", req.ref)
		checkout.Stdout = os.Stdout
		checkout.Stderr = os.Stderr
		if err := checkout.Run(); err != nil {
			return err
		}
	}

	binDir, err := determineGoBin()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return err
	}

	dest := filepath.Join(binDir, req.binary)
	build := exec.Command("go", "build", "-o", dest)
	build.Dir = tempDir
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	build.Env = os.Environ()
	return build.Run()
}

func determineGoBin() (string, error) {
	if bin := os.Getenv("GOBIN"); bin != "" {
		return bin, nil
	}

	gobinCmd := exec.Command("go", "env", "GOBIN")
	out, err := gobinCmd.Output()
	if err != nil {
		return "", err
	}

	if bin := strings.TrimSpace(string(out)); bin != "" {
		return bin, nil
	}

	gopathCmd := exec.Command("go", "env", "GOPATH")
	gopathOut, err := gopathCmd.Output()
	if err != nil {
		return "", err
	}

	gopath := strings.TrimSpace(string(gopathOut))
	if gopath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		gopath = filepath.Join(home, "go")
	}

	return filepath.Join(gopath, "bin"), nil
}
