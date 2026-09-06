package windowsinstall

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestPythonEnvironmentRemovesStartupOverrides(t *testing.T) {
	input := []string{"Path=system", "PYTHONHOME=outside", "pythonpath=outside", "PYTHONDONTWRITEBYTECODE=0", "PythonExecutable=outside", "__PyVenv_Launcher__=outside", "_PYTHON_PROJECT_BASE=outside", "pAtH=second-outside", "SystemRoot=outside", "WINDIR=outside", "BLENDERSESSIOND_STATE_ROOT=owned"}
	system := filepath.Join(t.TempDir(), "Windows", "System32")
	want := []string{"BLENDERSESSIOND_STATE_ROOT=owned", "PYTHONDONTWRITEBYTECODE=1", "PATH=" + system, "SystemRoot=" + filepath.Dir(system), "WINDIR=" + filepath.Dir(system)}
	if got := pythonEnvironment(input, system); !reflect.DeepEqual(got, want) {
		t.Fatalf("environment=%v", got)
	}
}

func TestPowerShellEnvironmentRestrictsModuleDiscovery(t *testing.T) {
	system := filepath.Join(t.TempDir(), "Windows", "System32")
	input := []string{"PSModulePath=outside", "psmodulepath=second-outside", "BLENDERSESSIOND_STATE_DIR=owned"}
	want := append(pythonEnvironment([]string{"BLENDERSESSIOND_STATE_DIR=owned"}, system), "PSModulePath="+filepath.Join(system, "WindowsPowerShell", "v1.0", "Modules"))
	if got := powerShellEnvironment(input, system); !reflect.DeepEqual(got, want) {
		t.Fatalf("PowerShell environment=%v", got)
	}
}
