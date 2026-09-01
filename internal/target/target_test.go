package target

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkRootRejectsTrailingSeparator(t *testing.T) {
	value := Target{
		SchemaVersion:           1,
		SSHAlias:                "windows-test",
		WorkRoot:                `C:\BlenderBoxTest\`,
		InteractiveUser:         "test-user",
		TaskName:                "BlenderBoxTest",
		BlenderExecutable:       `C:\Program Files\Blender Foundation\Blender 5.2\blender.exe`,
		SessionBrokerExecutable: `C:\BlenderBoxTest\bin\blendersessiond.exe`,
		HostExecutable:          `C:\BlenderBoxTest\bin\blender-box.exe`,
	}

	if err := value.Validate(); err == nil {
		t.Fatal("trailing work-root separator was accepted")
	}
}

func TestLoadRejectsTrailingJSONValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target.json")
	content := `{
  "schema_version": 1,
  "ssh_alias": "windows-test",
  "work_root": "C:\\BlenderBoxTest",
  "interactive_user": "test-user",
  "task_name": "BlenderBoxTest",
  "blender_executable": "C:\\Program Files\\Blender Foundation\\Blender 5.2\\blender.exe",
  "session_broker_executable": "C:\\BlenderBoxTest\\bin\\blendersessiond.exe",
  "host_executable": "C:\\BlenderBoxTest\\bin\\blender-box.exe"
}
{}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path); err == nil {
		t.Fatal("target with a trailing JSON value was accepted")
	}
}
