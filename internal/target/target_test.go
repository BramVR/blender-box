package target

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkRootRejectsTrailingSeparator(t *testing.T) {
	value := Target{
		SchemaVersion:           1,
		SSHAlias:                "windows-test",
		SSHUser:                 "test-user",
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

func TestWorkRootRejectsLegacySCPShellCharacters(t *testing.T) {
	base := Target{
		SchemaVersion:           1,
		SSHAlias:                "windows-test",
		SSHUser:                 "test-user",
		WorkRoot:                `C:\BlenderBoxTest`,
		InteractiveUser:         "test-user",
		TaskName:                "BlenderBoxTest",
		BlenderExecutable:       `C:\Program Files\Blender Foundation\Blender\blender.exe`,
		SessionBrokerExecutable: `C:\BlenderBoxTest\bin\blendersessiond.exe`,
		HostExecutable:          `C:\BlenderBoxTest\bin\blender-box.exe`,
	}
	for _, root := range []string{`C:\Blender Box`, `C:\Blender&Box`, `C:\Blender(Box)`} {
		value := base
		value.WorkRoot = root
		value.SessionBrokerExecutable = root + `\bin\blendersessiond.exe`
		value.HostExecutable = root + `\bin\blender-box.exe`
		if err := value.Validate(); err == nil || !strings.Contains(err.Error(), "SCP") {
			t.Fatalf("legacy-SCP-unsafe work root %q error = %v", root, err)
		}
	}
}

func TestTargetRejectsNonCanonicalWindowsPaths(t *testing.T) {
	base := Target{
		SchemaVersion:           1,
		SSHAlias:                "windows-test",
		SSHUser:                 "test-user",
		WorkRoot:                `C:\BlenderBoxTest`,
		InteractiveUser:         "test-user",
		TaskName:                "BlenderBoxTest",
		BlenderExecutable:       `C:\Program Files\Blender Foundation\Blender\blender.exe`,
		SessionBrokerExecutable: `C:\BlenderBoxTest\bin\blendersessiond.exe`,
		HostExecutable:          `C:\BlenderBoxTest\bin\blender-box.exe`,
	}

	for name, path := range map[string]string{
		"alternate data stream": `C:\BlenderBoxTest\host.exe:payload`,
		"forward slash":         `C:\BlenderBoxTest/bin/host.exe`,
		"empty segment":         `C:\BlenderBoxTest\\bin\host.exe`,
		"trailing dot":          `C:\BlenderBoxTest\bin.\host.exe`,
		"trailing space":        `C:\BlenderBoxTest\bin \host.exe`,
		"reserved device":       `C:\BlenderBoxTest\CON\host.exe`,
		"control character":     "C:\\BlenderBoxTest\\bin\\host\x00.exe",
		"environment expansion": `C:\BlenderBoxTest\%USERNAME%\host.exe`,
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			value.HostExecutable = path
			if err := value.Validate(); err == nil {
				t.Fatalf("unsafe Windows path was accepted: %q", path)
			}
		})
	}
}

func TestLoadRejectsTrailingJSONValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "target.json")
	content := `{
  "schema_version": 1,
  "ssh_alias": "windows-test",
  "ssh_user": "test-user",
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

func TestManagedExecutablesMustStayUnderWorkRoot(t *testing.T) {
	base := Target{
		SchemaVersion:           1,
		SSHAlias:                "windows-test",
		SSHUser:                 "test-user",
		WorkRoot:                `C:\BlenderBoxTest`,
		InteractiveUser:         "test-user",
		TaskName:                "BlenderBoxTest",
		BlenderExecutable:       `C:\Program Files\Blender Foundation\Blender\blender.exe`,
		SessionBrokerExecutable: `C:\BlenderBoxTest\bin\blendersessiond.exe`,
		HostExecutable:          `C:\BlenderBoxTest\bin\blender-box.exe`,
	}
	for name, mutate := range map[string]func(*Target){
		"host outside root": func(value *Target) { value.HostExecutable = `C:\Other\blender-box.exe` },
		"daemon outside root": func(value *Target) {
			value.SessionBrokerExecutable = `D:\Other\blendersessiond.exe`
		},
		"host directly in root": func(value *Target) { value.HostExecutable = `C:\BlenderBoxTest\blender-box.exe` },
		"daemon directly in root": func(value *Target) {
			value.SessionBrokerExecutable = `C:\BlenderBoxTest\blendersessiond.exe`
		},
		"host under runs": func(value *Target) {
			value.HostExecutable = `C:\BlenderBoxTest\RUNS\bin\blender-box.exe`
		},
		"daemon under receipts": func(value *Target) {
			value.SessionBrokerExecutable = `C:\BlenderBoxTest\Receipts\bin\blendersessiond.exe`
		},
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("managed executable outside work root was accepted")
			}
		})
	}
}

func TestTargetRejectsExecutablePathCollisions(t *testing.T) {
	base := Target{
		SchemaVersion:           1,
		SSHAlias:                "windows-test",
		SSHUser:                 "test-user",
		WorkRoot:                `C:\BlenderBoxTest`,
		InteractiveUser:         "test-user",
		TaskName:                "BlenderBoxTest",
		BlenderExecutable:       `C:\BlenderBoxTest\apps\blender.exe`,
		SessionBrokerExecutable: `C:\BlenderBoxTest\bin\blendersessiond.exe`,
		HostExecutable:          `C:\BlenderBoxTest\bin\blender-box.exe`,
	}
	for name, mutate := range map[string]func(*Target){
		"host and daemon":    func(value *Target) { value.HostExecutable = strings.ToUpper(value.SessionBrokerExecutable) },
		"host and Blender":   func(value *Target) { value.HostExecutable = strings.ToUpper(value.BlenderExecutable) },
		"daemon and Blender": func(value *Target) { value.SessionBrokerExecutable = strings.ToUpper(value.BlenderExecutable) },
	} {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("colliding executable paths were accepted")
			}
		})
	}
}
