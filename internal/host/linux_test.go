package host

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/capture"
	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/payload"
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
	temporary := filepath.Join(runPath(root, request.Claim.RunID), "tmp")
	info, err := os.Lstat(temporary)
	if err != nil || !info.IsDir() {
		t.Fatalf("staged Run temporary directory: %v %v", info, err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
		t.Fatalf("Run temporary directory is not private: %v", info.Mode())
	}
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
	leftover := filepath.Join(temporary, "addon-download.glb")
	if err := os.WriteFile(leftover, []byte("temporary asset"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanup, err := service.Settle(context.Background(), root, settle)
	if err != nil || !cleanup.Known() {
		t.Fatalf("settlement %+v %v", cleanup, err)
	}
	if _, err := os.Lstat(leftover); !os.IsNotExist(err) {
		t.Fatalf("settlement left Run temporary asset: %v", err)
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
	for _, environment := range []map[string]string{daemon.starts[0].Environment, daemon.readies[0].Environment, daemon.calls[0].Environment, daemon.calls[1].Environment, daemon.stops[0].Environment} {
		if environment["TMPDIR"] != temporary {
			t.Fatalf("daemon operation lost Run temporary directory: %v", environment)
		}
	}
	if daemon.starts[0].Desktop == nil || *daemon.starts[0].Desktop != request.Body.Linux.Desktop || daemon.starts[0].UID != 1000 {
		t.Fatal("desktop contract lost before daemon Start")
	}
	if unit.prepares != 1 {
		t.Fatal("settlement required desktop readiness after logout")
	}
}

type recoveringEnvironmentDaemon struct {
	fakeDaemon
	recovers []DaemonRecover
}

func (daemon *recoveringEnvironmentDaemon) Recover(ctx context.Context, request DaemonRecover) (orchestrator.SessionID, bool, error) {
	daemon.recovers = append(daemon.recovers, request)
	return daemon.fakeDaemon.Recover(ctx, request)
}

func TestLinuxStartupCrashRecoveryUsesOriginalSettlementRuntime(t *testing.T) {
	root := privateTempDir(t)
	daemon := &recoveringEnvironmentDaemon{fakeDaemon: fakeDaemon{recovered: "bss_linux-unpublished-session-12345678"}}
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
	temporary := filepath.Join(runPath(root, request.Claim.RunID), "tmp")
	if err := os.Remove(temporary); err != nil {
		t.Fatal(err)
	}
	cleanup, err := service.Settle(context.Background(), root, linuxSettlement(receipt, request))
	if err != nil || !cleanup.Known() {
		t.Fatalf("crash recovery %+v %v", cleanup, err)
	}
	if len(daemon.stops) != 1 || daemon.stops[0].SessionID != daemon.recovered || *daemon.stops[0].Runtime.Linux != request.Body.Linux.Runtime {
		t.Fatalf("settlement changed original authority %+v", daemon.stops)
	}
	if len(daemon.recovers) != 1 || daemon.recovers[0].Environment["TMPDIR"] != temporary || daemon.stops[0].Environment["TMPDIR"] != temporary {
		t.Fatal("recovery or stop lost Run temporary directory after its removal")
	}
}

func TestLinuxRefusesUnavailableTemporaryDirectoryBeforeDaemonLaunch(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "file"} {
		t.Run(kind, func(t *testing.T) {
			root := privateTempDir(t)
			daemon := &fakeDaemon{}
			service := NewService(Dependencies{Platform: "linux", Tasks: &unitLifecycleFake{}, Daemon: daemon})
			request := stageHostTestRun(t, service, root, time.Now().UTC(), false)
			if _, err := service.Start(context.Background(), root, request); err != nil {
				t.Fatal(err)
			}
			temporary := filepath.Join(runPath(root, request.Claim.RunID), "tmp")
			if err := os.Remove(temporary); err != nil {
				t.Fatal(err)
			}
			if kind == "symlink" {
				if err := os.Symlink(privateTempDir(t), temporary); err != nil {
					if runtime.GOOS == "windows" {
						t.Skip(err)
					}
					t.Fatal(err)
				}
			} else if kind == "file" {
				if err := os.WriteFile(temporary, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := service.ExecutePending(context.Background(), root); err == nil || !strings.Contains(err.Error(), "Run temporary directory") {
				t.Fatalf("unavailable temporary directory accepted: %v", err)
			}
			if len(daemon.starts) != 0 {
				t.Fatal("daemon launched with unavailable temporary directory")
			}
		})
	}
}

func TestWindowsRunDoesNotOverrideTemporaryEnvironment(t *testing.T) {
	root := privateTempDir(t)
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Platform: "windows", Tasks: &fakeTaskLauncher{}, Daemon: daemon})
	request := stageHostTestRun(t, service, root, time.Now().UTC(), false)
	if _, err := os.Lstat(filepath.Join(runPath(root, request.Claim.RunID), "tmp")); !os.IsNotExist(err) {
		t.Fatalf("Windows staging gained a temporary directory: %v", err)
	}
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
	if cleanup, err := service.Settle(context.Background(), root, settleHostRequest(receipt)); err != nil || !cleanup.Known() {
		t.Fatalf("Windows settlement: %+v %v", cleanup, err)
	}
	for _, environment := range []map[string]string{daemon.starts[0].Environment, daemon.readies[0].Environment, daemon.calls[0].Environment, daemon.stops[0].Environment} {
		for _, key := range []string{"TMPDIR", "TMP", "TEMP"} {
			if _, exists := environment[key]; exists {
				t.Fatalf("Windows Run overrides %s", key)
			}
		}
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

func TestLinuxUnsupportedRequestsRefuseBeforePublicationAndDaemonLaunch(t *testing.T) {
	for _, kind := range []string{"blender-window", "desktop", "ui-actions"} {
		t.Run(kind, func(t *testing.T) {
			root := privateTempDir(t)
			unit := &unitLifecycleFake{}
			daemon := &fakeDaemon{}
			service := NewService(Dependencies{Platform: "linux", Tasks: unit, Daemon: daemon})
			scenario := payload.Scenario{Script: "scenario.py", ReadTimeoutSeconds: 600}
			schema := 2
			switch kind {
			case "blender-window":
				scenario.CaptureBlenderWindow = true
			case "desktop":
				scenario.CaptureDesktop = true
			case "ui-actions":
				schema = 3
				scenario.UIActions = uiTestBatch(t)
			}
			request := stageHostScenarioTestRun(t, service, root, time.Now().UTC(), schema, scenario)
			if err := request.Validate(); err == nil || !strings.Contains(err.Error(), "Linux targets do not support") {
				t.Fatalf("unsupported request passed direct validation: %v", err)
			}
			before := mustRead(t, lockPath(root))
			if _, err := service.Start(context.Background(), root, request); err == nil || !strings.Contains(err.Error(), "Linux targets do not support") {
				t.Fatalf("unsupported direct Start: %v", err)
			}
			pending := filepath.Join(root, "pending-request.json")
			if _, err := os.Lstat(pending); !os.IsNotExist(err) {
				t.Fatalf("unsupported Start published pending request: %v", err)
			}
			if err := writeJSONAtomic(pending, request); err != nil {
				t.Fatal(err)
			}
			if err := service.ExecutePending(context.Background(), root); err == nil || !strings.Contains(err.Error(), "Linux targets do not support") {
				t.Fatalf("unsupported pending request: %v", err)
			}
			if unit.prepares != 0 || unit.launches != 0 || len(daemon.starts) != 0 || string(before) != string(mustRead(t, lockPath(root))) {
				t.Fatal("unsupported request mutated authority or started runtime")
			}
			receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
			if err != nil || receipt.State != orchestrator.StateStaged || receipt.SessionID != "" {
				t.Fatalf("unsupported request changed receipt: %+v %v", receipt, err)
			}
		})
	}
}

func TestLinuxCapabilitiesAdvertiseOnlyViewport(t *testing.T) {
	desktop := &fakeDesktopCapturer{}
	service := NewService(Dependencies{Platform: "linux", Desktop: desktop})
	result, err := service.Capabilities(context.Background(), CapabilitiesRequest{SchemaVersion: 1})
	if err != nil || len(result.Captures) != len(capture.Definitions()) {
		t.Fatalf("capabilities: %+v %v", result, err)
	}
	for _, support := range result.Captures {
		if support.Supported != (support.Kind == capture.Viewport) {
			t.Fatalf("Linux advertised unsupported capture: %+v", support)
		}
	}
	if _, err := service.Capabilities(context.Background(), CapabilitiesRequest{SchemaVersion: 1, UIActions: true}); err == nil {
		t.Fatal("Linux advertised UI actions")
	}
}
