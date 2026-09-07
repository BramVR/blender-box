package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	executable, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	python := filepath.Join(filepath.Dir(executable), "python", "Scripts", "python.exe")
	directory, err := systemDirectory()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	command := exec.Command(python, append([]string{"-I", "-B", "-m", "blendersessiond"}, os.Args[1:]...)...)
	command.Dir = filepath.Dir(python)
	command.Stdin = os.Stdin
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Env = pythonEnvironment(os.Environ(), directory)
	if err := command.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func pythonEnvironment(environment []string, systemDirectory string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, value := range environment {
		key, _, _ := strings.Cut(value, "=")
		switch strings.ToUpper(key) {
		case "PYTHONPATH", "PYTHONHOME", "PYTHONDONTWRITEBYTECODE", "PYTHONEXECUTABLE", "__PYVENV_LAUNCHER__", "_PYTHON_PROJECT_BASE", "PATH", "SYSTEMROOT", "WINDIR":
			continue
		}
		result = append(result, value)
	}
	return append(result, "PYTHONDONTWRITEBYTECODE=1", "PATH="+systemDirectory, "SystemRoot="+filepath.Dir(systemDirectory), "WINDIR="+filepath.Dir(systemDirectory))
}
