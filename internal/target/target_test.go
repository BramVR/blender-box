package target

import "testing"

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
