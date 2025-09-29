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

type requirement struct {
	binary string
	module string
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
			fmt.Printf("%s already installed at %s\n", req.binary, path)
			continue
		}

		fmt.Printf("Installing %s from %s...\n", req.binary, req.module)
		if err := installModule(req.module); err != nil {
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
	defer file.Close()

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

		reqs = append(reqs, requirement{
			binary: fields[0],
			module: fields[1],
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return reqs, nil
}

func installModule(module string) error {
	cmd := exec.Command("go", "install", module)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	return cmd.Run()
}
