package target

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/linuxtarget"
)

func linuxTarget(t *testing.T) Target {
	t.Helper()
	value, err := NewLinux("fake-linux", linuxtarget.Config{Distribution: linuxtarget.Distribution, UID: 1000, Home: "/home/operator", WorkRoot: "/home/operator/box", HostExecutable: "/home/operator/box/bin/blender-box", BlenderExecutable: "/opt/blender/blender", UnitName: "blender-box.service", Desktop: linuxtarget.Desktop{Display: ":0", XAuthority: "/run/user/1000/gdm/Xauthority"}, Daemon: linuxtarget.DaemonRuntime{VenvRoot: "/home/operator/daemon", PythonExecutable: "/home/operator/daemon/bin/python3", ProvenanceID: linuxtarget.ProvenanceID}})
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func TestLinuxTargetStrictRoundTripAndFingerprint(t *testing.T) {
	original := linuxTarget(t)
	data, err := original.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Platform() != "linux" || decoded.Linux() != original.Linux() || decoded.Fingerprint() != original.Fingerprint() {
		t.Fatal("Linux target round trip changed identity")
	}
	for _, bad := range []string{strings.Replace(string(data), `"linux":`, `"windows":{},"linux":`, 1), strings.Replace(string(data), `"uid":1000`, `"uid":1000,"uid":1001`, 1), strings.Replace(string(data), `"home":"/home/operator",`, "", 1), strings.Replace(string(data), `"schema_version":2`, `"schema_version":1`, 1), strings.Replace(string(data), `"daemon":{`, `"daemon":{"arbitrary":true,`, 1)} {
		if _, err := Decode([]byte(bad)); err == nil {
			t.Fatalf("accepted ambiguous Linux document %s", bad)
		}
	}
	changed := original.Linux()
	changed.Desktop.Display = ":1"
	replacement, err := NewLinux(original.SSHAlias(), changed)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Fingerprint() == original.Fingerprint() {
		t.Fatal("desktop drift did not change authority fingerprint")
	}
}
func TestWindowsCanonicalBytesAndFingerprintRemainFrozen(t *testing.T) {
	contents, err := os.ReadFile("testdata/windows-compatibility.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Target      json.RawMessage `json:"target"`
		Canonical   string          `json:"canonical_json"`
		Fingerprint string          `json:"fingerprint"`
	}
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	selected, err := Decode(fixture.Target)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := selected.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != fixture.Canonical || selected.Fingerprint() != fixture.Fingerprint {
		t.Fatalf("Windows encoding/fingerprint changed: %s %s", encoded, selected.Fingerprint())
	}
}
