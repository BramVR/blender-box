package main

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestPythonEnvironmentKeepsRunStateWithoutStartupOverrides(t *testing.T) {
	input := []string{"PATH=system", "PYTHONPATH=outside", "pythonhome=outside", "PYTHONDONTWRITEBYTECODE=0", "PythonExecutable=outside", "__PyVenv_Launcher__=outside", "_PYTHON_PROJECT_BASE=outside", "pAtH=second-outside", "SystemRoot=outside", "WINDIR=outside", "BLENDERSESSIOND_STATE_ROOT=owned"}
	system := filepath.Join(t.TempDir(), "Windows", "System32")
	want := []string{"BLENDERSESSIOND_STATE_ROOT=owned", "PYTHONDONTWRITEBYTECODE=1", "PATH=" + system, "SystemRoot=" + filepath.Dir(system), "WINDIR=" + filepath.Dir(system)}
	if got := pythonEnvironment(input, system); !reflect.DeepEqual(got, want) {
		t.Fatalf("environment=%v", got)
	}
}
