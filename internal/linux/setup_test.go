package linux

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/linuxtarget"
	"github.com/BramVR/blender-box/internal/target"
)

type recordingSSH struct {
	calls     int
	arguments []string
	input     []byte
	output    []byte
	hook      func([]byte) []byte
}

func (fake *recordingSSH) Run(_ context.Context, _ string, arguments []string, input []byte) ([]byte, error) {
	fake.calls++
	fake.arguments = arguments
	fake.input = append([]byte(nil), input...)
	if fake.hook != nil {
		return fake.hook(input), nil
	}
	return fake.output, nil
}
func linuxTarget(t *testing.T) target.Target {
	t.Helper()
	selected, err := target.NewLinux("fake-linux", linuxtarget.Config{Distribution: linuxtarget.Distribution, UID: 1000, Home: "/home/operator", WorkRoot: "/home/operator/box", HostExecutable: "/home/operator/box/bin/blender-box", BlenderExecutable: "/opt/blender/blender", UnitName: "blender-box.service", Desktop: linuxtarget.Desktop{Display: ":0", XAuthority: "/run/user/1000/gdm/Xauthority"}, Daemon: linuxtarget.DaemonRuntime{VenvRoot: "/home/operator/daemon", PythonExecutable: "/home/operator/daemon/bin/python3", ProvenanceID: linuxtarget.ProvenanceID}})
	if err != nil {
		t.Fatal(err)
	}
	return selected
}
func TestLinuxSetupPlanNeverContactsHostAndApplyBindsExactBytes(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "host")
	contents := []byte("Linux host bytes")
	if err := os.WriteFile(binary, contents, 0600); err != nil {
		t.Fatal(err)
	}
	ssh := &recordingSSH{}
	selected := linuxTarget(t)
	plan, err := Setup(context.Background(), ssh, selected, binary, false)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(contents)
	unitHash := sha256.Sum256([]byte(plan.UnitBytes))
	if ssh.calls != 0 || plan.Applied || plan.Status != "plan" || plan.HostSize != int64(len(contents)) || plan.HostSHA256 != hex.EncodeToString(hash[:]) || plan.UnitSHA256 != hex.EncodeToString(unitHash[:]) || plan.UnitDestination != "/home/operator/.config/systemd/user/blender-box.service" || len(plan.Prerequisites) == 0 {
		t.Fatalf("plan %+v, contacts %d", plan, ssh.calls)
	}
	ssh.hook = func(input []byte) []byte {
		var request struct {
			Plan   SetupResult `json:"plan"`
			Binary []byte      `json:"binary"`
		}
		if err := json.Unmarshal(input, &request); err != nil {
			t.Fatal(err)
		}
		if string(request.Binary) != string(contents) || request.Plan.UnitBytes != plan.UnitBytes {
			t.Fatal("setup changed snapshotted bytes")
		}
		output, _ := json.Marshal(map[string]any{"schema_version": 1, "status": "applied", "host_sha256": request.Plan.HostSHA256, "unit_sha256": request.Plan.UnitSHA256})
		return output
	}
	applied, err := Setup(context.Background(), ssh, selected, binary, true)
	if err != nil {
		t.Fatal(err)
	}
	if !applied.Applied || applied.UnitBytes != plan.UnitBytes || len(ssh.arguments) != 1 || !strings.HasPrefix(ssh.arguments[0], "/usr/bin/python3 -I -S -B -c '") {
		t.Fatalf("apply %+v argv %v", applied, ssh.arguments)
	}
}
func TestLinuxBootstrapBoundaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX bootstrap; Go wire tests remain platform-neutral")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python unavailable")
	}
	command := exec.Command(python, "-I", "-B", "-m", "unittest", "discover", "-s", ".", "-p", "setup_test.py")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("bootstrap boundary tests: %v\n%s", err, output)
	}
}
