package windowsinstall

import (
	"path/filepath"
	"strings"
)

func pythonEnvironment(environment []string, systemDirectory string) []string {
	result := make([]string, 0, len(environment)+1)
	for _, value := range environment {
		key, _, _ := strings.Cut(value, "=")
		switch strings.ToUpper(key) {
		case "PYTHONHOME", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE", "PYTHONEXECUTABLE", "__PYVENV_LAUNCHER__", "_PYTHON_PROJECT_BASE", "PATH", "SYSTEMROOT", "WINDIR":
			continue
		}
		result = append(result, value)
	}
	return append(result, "PYTHONDONTWRITEBYTECODE=1", "PATH="+systemDirectory, "SystemRoot="+filepath.Dir(systemDirectory), "WINDIR="+filepath.Dir(systemDirectory))
}

func powerShellEnvironment(environment []string, systemDirectory string) []string {
	result := []string{}
	for _, value := range pythonEnvironment(environment, systemDirectory) {
		key, _, _ := strings.Cut(value, "=")
		if !strings.EqualFold(key, "PSModulePath") {
			result = append(result, value)
		}
	}
	return append(result, "PSModulePath="+filepath.Join(systemDirectory, "WindowsPowerShell", "v1.0", "Modules"))
}
