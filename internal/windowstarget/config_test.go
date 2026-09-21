package windowstarget

import (
	"strings"
	"testing"
)

func TestWorkRootRejectsTrailingSeparator(t *testing.T) {
	value := Config{
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
	base := Config{
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

func TestWorkRootReservesSetupOwnerAttemptPath(t *testing.T) {
	attemptID := "bbsa_" + strings.Repeat("A", 43)
	setupOwnerSuffix := `\setup-owner\setup-attempts\` + attemptID + `\` + attemptID + `.ps1`
	maximumRootTail := maxWindowsPathTail - len(setupOwnerSuffix)
	value := Config{
		SSHUser:           "test-user",
		WorkRoot:          `C:\` + strings.Repeat("a", maximumRootTail+1),
		InteractiveUser:   "test-user",
		TaskName:          "BlenderBoxTest",
		BlenderExecutable: `C:\Program Files\Blender Foundation\Blender\blender.exe`,
	}
	value.SessionBrokerExecutable = value.WorkRoot + `\bin\blendersessiond.exe`
	value.HostExecutable = value.WorkRoot + `\bin\blender-box.exe`
	if err := value.Validate(); err == nil || !strings.Contains(err.Error(), "staging") {
		t.Fatalf("unstageable root error = %v", err)
	}
	maximumStageable := `C:\` + strings.Repeat("a", maximumRootTail) + setupOwnerSuffix
	if !ValidateLegacySCPWindowsPath(maximumStageable) {
		t.Fatal("documented staging boundary is not accepted by the upload grammar")
	}
}

func TestHostExecutableReservesLongestReplacementSuffix(t *testing.T) {
	base := Config{
		SSHUser:                 "test-user",
		WorkRoot:                `C:\B`,
		InteractiveUser:         "test-user",
		TaskName:                "BlenderBoxTest",
		BlenderExecutable:       `C:\Program Files\Blender Foundation\Blender\blender.exe`,
		SessionBrokerExecutable: `C:\B\bin\blendersessiond.exe`,
	}
	for _, test := range []struct {
		name    string
		tailLen int
		valid   bool
	}{
		{name: "maximum replaceable host path", tailLen: 192, valid: true},
		{name: "one byte too long", tailLen: 193, valid: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := base
			value.HostExecutable = `C:\B\d\` + strings.Repeat("a", test.tailLen-len(`B\d\`))
			err := value.Validate()
			if test.valid && err != nil {
				t.Fatalf("replaceable host path rejected: %v", err)
			}
			if !test.valid && (err == nil || !strings.Contains(err.Error(), "replacement")) {
				t.Fatalf("unreplaceable host path error = %v", err)
			}
			if test.valid && !ValidateWindowsPath(value.HostExecutable+`.setup-backup-`+strings.Repeat("0", 32)) {
				t.Fatal("maximum accepted host path cannot carry its longest replacement suffix")
			}
		})
	}
}

func TestConfigRejectsNonCanonicalWindowsPaths(t *testing.T) {
	base := Config{
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

func TestManagedExecutablesMustStayUnderWorkRoot(t *testing.T) {
	base := Config{
		SSHUser:                 "test-user",
		WorkRoot:                `C:\BlenderBoxTest`,
		InteractiveUser:         "test-user",
		TaskName:                "BlenderBoxTest",
		BlenderExecutable:       `C:\Program Files\Blender Foundation\Blender\blender.exe`,
		SessionBrokerExecutable: `C:\BlenderBoxTest\bin\blendersessiond.exe`,
		HostExecutable:          `C:\BlenderBoxTest\bin\blender-box.exe`,
	}
	for name, mutate := range map[string]func(*Config){
		"host outside root": func(value *Config) { value.HostExecutable = `C:\Other\blender-box.exe` },
		"daemon outside root": func(value *Config) {
			value.SessionBrokerExecutable = `D:\Other\blendersessiond.exe`
		},
		"host directly in root": func(value *Config) { value.HostExecutable = `C:\BlenderBoxTest\blender-box.exe` },
		"daemon directly in root": func(value *Config) {
			value.SessionBrokerExecutable = `C:\BlenderBoxTest\blendersessiond.exe`
		},
		"host under setup owner": func(value *Config) { value.HostExecutable = `C:\BlenderBoxTest\setup-owner\bin\blender-box.exe` },
		"daemon under setup owner": func(value *Config) {
			value.SessionBrokerExecutable = `C:\BlenderBoxTest\SETUP-OWNER\bin\blendersessiond.exe`
		},
		"host under runs": func(value *Config) {
			value.HostExecutable = `C:\BlenderBoxTest\RUNS\bin\blender-box.exe`
		},
		"daemon under receipts": func(value *Config) {
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

func TestConfigRejectsExecutablePathCollisions(t *testing.T) {
	base := Config{
		SSHUser:                 "test-user",
		WorkRoot:                `C:\BlenderBoxTest`,
		InteractiveUser:         "test-user",
		TaskName:                "BlenderBoxTest",
		BlenderExecutable:       `C:\BlenderBoxTest\apps\blender.exe`,
		SessionBrokerExecutable: `C:\BlenderBoxTest\bin\blendersessiond.exe`,
		HostExecutable:          `C:\BlenderBoxTest\bin\blender-box.exe`,
	}
	for name, mutate := range map[string]func(*Config){
		"host and daemon":    func(value *Config) { value.HostExecutable = strings.ToUpper(value.SessionBrokerExecutable) },
		"host and Blender":   func(value *Config) { value.HostExecutable = strings.ToUpper(value.BlenderExecutable) },
		"daemon and Blender": func(value *Config) { value.SessionBrokerExecutable = strings.ToUpper(value.BlenderExecutable) },
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
