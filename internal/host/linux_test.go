package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/orchestrator"
)

type unitLifecycleFake struct {
	active             bool
	prepares, launches int
}

func (unit *unitLifecycleFake) Prepare(context.Context, LaunchRequest) error {
	unit.prepares++
	if unit.active {
		return errors.New("prior service is active")
	}
	return nil
}
func (unit *unitLifecycleFake) Launch(context.Context, LaunchRequest) error {
	unit.launches++
	unit.active = true
	return nil
}

func TestLinuxFreshRunRequiresInactiveUnitBeforePublication(t *testing.T) {
	root := privateTempDir(t)
	unit := &unitLifecycleFake{active: true}
	service := NewService(Dependencies{Platform: "linux", Tasks: unit, Daemon: &fakeDaemon{}})
	request := stageHostTestRun(t, service, root, time.Now().UTC(), false)
	if _, err := service.Start(context.Background(), root, request); err == nil {
		t.Fatal("fresh Run adopted an active prior service")
	}
	for _, path := range []string{filepath.Join(root, "pending-request.json"), filepath.Join(runPath(root, request.Claim.RunID), "request.json")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("refused preparation published %s", path)
		}
	}
	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil || receipt.State != orchestrator.StateStaged {
		t.Fatalf("refused preparation receipt %+v %v", receipt, err)
	}
	unit.active = false
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatalf("identical accepted replay: %v", err)
	}
	if unit.prepares != 2 || unit.launches != 2 {
		t.Fatalf("prepares=%d launches=%d", unit.prepares, unit.launches)
	}
}
func TestLinuxServiceRunsCollectsAndSettlesWithExactRuntime(t *testing.T) {
	root := privateTempDir(t)
	unit := &unitLifecycleFake{}
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Platform: "linux", Tasks: unit, Daemon: daemon})
	request := stageHostTestRun(t, service, root, time.Now().UTC(), true)
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	if err := service.ExecutePending(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != orchestrator.StateComplete || len(receipt.Evidence.Files) != 2 {
		t.Fatalf("Run result %+v", receipt)
	}
	for _, file := range receipt.Evidence.Files {
		contents, err := service.Fetch(root, FetchRequest{SchemaVersion: 1, Receipt: receipt, File: file})
		if err != nil || len(contents) != int(file.Size) {
			t.Fatalf("evidence fetch %v %d", err, len(contents))
		}
	}
	settle := linuxSettlement(receipt, request)
	cleanup, err := service.Settle(context.Background(), root, settle)
	if err != nil || !cleanup.Known() {
		t.Fatalf("settlement %+v %v", cleanup, err)
	}
	again, err := service.Settle(context.Background(), root, settle)
	if err != nil || again != cleanup {
		t.Fatalf("repeated settlement %+v %v", again, err)
	}
	want := request.Body.Linux.Runtime
	if len(daemon.starts) != 1 || len(daemon.readies) != 1 || len(daemon.stops) != 1 {
		t.Fatalf("daemon lifecycle %+v", daemon)
	}
	for _, binding := range []DaemonBinding{daemon.starts[0].Runtime, daemon.readies[0].Runtime, daemon.calls[0].Runtime, daemon.calls[1].Runtime, daemon.stops[0].Runtime} {
		if binding.Linux == nil || *binding.Linux != want || binding.Executable != want.PythonExecutable {
			t.Fatalf("daemon runtime changed %+v", binding)
		}
	}
	if daemon.starts[0].Desktop == nil || *daemon.starts[0].Desktop != request.Body.Linux.Desktop || daemon.starts[0].UID != 1000 {
		t.Fatal("desktop contract lost before daemon Start")
	}
	if unit.prepares != 1 {
		t.Fatal("settlement required desktop readiness after logout")
	}
}
func TestLinuxStartupCrashRecoveryUsesOriginalSettlementRuntime(t *testing.T) {
	root := privateTempDir(t)
	daemon := &fakeDaemon{recovered: "bss_linux-unpublished-session-12345678"}
	service := NewService(Dependencies{Platform: "linux", Tasks: &unitLifecycleFake{}, Daemon: daemon})
	request := stageHostTestRun(t, service, root, time.Now().UTC(), false)
	receipt, err := service.Start(context.Background(), root, request)
	if err != nil {
		t.Fatal(err)
	}
	tampered := request
	copyLaunch := *request.Body.Linux
	copyLaunch.Runtime.VenvRoot = "/home/operator/foreign"
	copyLaunch.Runtime.PythonExecutable = copyLaunch.Runtime.VenvRoot + "/bin/python3"
	tampered.Body.Linux = &copyLaunch
	tampered.Body.SessionBrokerExecutable = copyLaunch.Runtime.PythonExecutable
	if err := writeJSONAtomic(filepath.Join(runPath(root, request.Claim.RunID), "request.json"), tampered); err != nil {
		t.Fatal(err)
	}
	cleanup, err := service.Settle(context.Background(), root, linuxSettlement(receipt, request))
	if err != nil || !cleanup.Known() {
		t.Fatalf("crash recovery %+v %v", cleanup, err)
	}
	if len(daemon.stops) != 1 || daemon.stops[0].SessionID != daemon.recovered || *daemon.stops[0].Runtime.Linux != request.Body.Linux.Runtime {
		t.Fatalf("settlement changed original authority %+v", daemon.stops)
	}
}
func TestOppositePlatformRefusesBeforeMutation(t *testing.T) {
	for _, platform := range []string{"linux", "windows"} {
		t.Run(platform, func(t *testing.T) {
			root := privateTempDir(t)
			source := NewService(Dependencies{Platform: platform, Tasks: &unitLifecycleFake{}})
			request := stageHostTestRun(t, source, root, time.Now().UTC(), false)
			other := "linux"
			if platform == "linux" {
				other = "windows"
			}
			service := NewService(Dependencies{Platform: other, Tasks: &unitLifecycleFake{}, Daemon: &fakeDaemon{}})
			before := mustRead(t, lockPath(root))
			if _, err := service.Start(context.Background(), root, request); err == nil {
				t.Fatal("opposite-platform Start accepted")
			}
			receipt, err := source.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
			if err != nil {
				t.Fatal(err)
			}
			settle := settleHostRequest(receipt)
			if platform == "linux" {
				settle = linuxSettlement(receipt, request)
			}
			if _, err := service.Settle(context.Background(), root, settle); err == nil {
				t.Fatal("opposite-platform settlement accepted")
			}
			if string(before) != string(mustRead(t, lockPath(root))) {
				t.Fatal("opposite-platform command changed Host Lock")
			}
			pending := filepath.Join(root, "pending-request.json")
			encoded, _ := json.Marshal(request)
			if err := os.WriteFile(pending, encoded, 0600); err != nil {
				t.Fatal(err)
			}
			if err := service.ExecutePending(context.Background(), root); err == nil {
				t.Fatal("opposite-platform task accepted")
			}
			if string(before) != string(mustRead(t, lockPath(root))) {
				t.Fatal("opposite-platform task changed Host Lock")
			}
		})
	}
}
func linuxSettlement(receipt orchestrator.RunReceipt, request orchestrator.RunRequest) SettleRequest {
	runtime := request.Body.Linux.Runtime
	return SettleRequest{SchemaVersion: 2, Receipt: receipt, SessionName: request.Body.SessionName, SessionBrokerExecutable: runtime.PythonExecutable, Linux: &runtime}
}
