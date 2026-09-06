package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/capture"
	"github.com/BramVR/blender-box/internal/linuxruntime"
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
	home := filepath.Join(runPath(root, request.Claim.RunID), "home")
	for _, path := range []string{temporary, home} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			t.Fatalf("staged Run directory %s: %v %v", path, info, err)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
			t.Fatalf("Run directory %s is not private: %v", path, info.Mode())
		}
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
	cache := filepath.Join(home, ".cache", "addon-download.glb")
	if err := os.Mkdir(filepath.Dir(cache), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache, []byte("cached asset"), 0o600); err != nil {
		t.Fatal(err)
	}
	cleanup, err := service.Settle(context.Background(), root, settle)
	if err != nil || !cleanup.Known() {
		t.Fatalf("settlement %+v %v", cleanup, err)
	}
	for _, path := range []string{leftover, cache, runPath(root, request.Claim.RunID)} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("settlement left Run path %s: %v", path, err)
		}
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
		if environment["HOME"] != home {
			t.Fatalf("daemon operation lost Run HOME: %v", environment)
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

func TestLinuxRunHomeCaches(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Linux/POSIX environment contract")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python is unavailable")
	}
	root := privateTempDir(t)
	foreign := privateTempDir(t)
	sentinel := filepath.Join(foreign, "operator.txt")
	if err := os.WriteFile(sentinel, []byte("operator home untouched"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", foreign)
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Platform: "linux", Tasks: &unitLifecycleFake{}, Daemon: daemon})
	request := stageHostTestRun(t, service, root, time.Now().UTC(), false)
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	if err := service.ExecutePending(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	runRoot := runPath(root, request.Claim.RunID)
	home := filepath.Join(runRoot, "home")
	code := `import datetime,json,os,pathlib,subprocess,sys
home=pathlib.Path(os.environ["HOME"])
assert home==pathlib.Path(sys.argv[3]) and pathlib.Path.home()==home
cache=home/".cache"
cache.mkdir(mode=0o700,exist_ok=True)
file=cache/(sys.argv[1]+".txt")
file.write_text(sys.argv[1]+" cache")
items=[]
receipt=None
if sys.argv[1]=="parent":
    argv=[sys.executable,"-I","-B","-c",sys.argv[2],"child",sys.argv[2],sys.argv[3]]
    spawned=datetime.datetime.now(datetime.timezone.utc).isoformat()
    child=subprocess.Popen(argv,stdout=subprocess.PIPE)
    receipt={"pid":child.pid,"parent":os.getpid(),"spawn":spawned,"argv":argv,"signals":0}
    print(json.dumps(receipt),file=sys.stderr,flush=True)
    try:
        output,_=child.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        child.kill()
        child.communicate()
        receipt.update(signals=1,returncode=child.returncode,reaped=True)
        print(json.dumps(receipt),file=sys.stderr,flush=True)
        raise
    receipt.update(returncode=child.returncode,reaped=True)
    assert child.returncode==0,receipt
    items=json.loads(output)
items.append({"home":str(home),"resolved":str(pathlib.Path.home()),"file":str(file),"name":sys.argv[1],"child":receipt})
print(json.dumps(items))
`
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, python, "-I", "-B", "-c", code, "parent", code, home)
	command.Env = linuxruntime.CleanEnvironment(daemon.starts[0].Environment)
	var output, stderr bytes.Buffer
	command.Stdout, command.Stderr = &output, &stderr
	started := time.Now().UTC()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Logf("owned HOME probe pid=%d parent=%d spawn=%s command=%q", command.Process.Pid, os.Getpid(), started.Format(time.RFC3339Nano), command.Args)
	if err := command.Wait(); err != nil {
		t.Fatalf("HOME cache probe: %v %s %s", err, output.String(), stderr.String())
	}
	t.Logf("owned HOME child spawn receipt: %s", stderr.String())
	var results []struct {
		Home, Resolved, File, Name string
		Child                      *struct {
			PID, Parent, Returncode, Signals int
			Spawn                            string
			Argv                             []string
			Reaped                           bool
		}
	}
	if err := json.Unmarshal(output.Bytes(), &results); err != nil || len(results) != 2 {
		t.Fatalf("HOME cache results: %s %v", output.String(), err)
	}
	for index, name := range []string{"child", "parent"} {
		result := results[index]
		if result.Name != name || result.Home != home || result.Resolved != home || result.File != filepath.Join(home, ".cache", name+".txt") {
			t.Fatalf("cache escaped Run HOME: %+v", result)
		}
		if contents := mustRead(t, result.File); string(contents) != name+" cache" {
			t.Fatalf("unexpected %s cache contents: %q", name, contents)
		}
	}
	child := results[1].Child
	if results[0].Child != nil || child == nil || child.PID <= 0 || child.Parent != command.Process.Pid || child.Spawn == "" || len(child.Argv) == 0 || child.Returncode != 0 || child.Signals != 0 || !child.Reaped {
		t.Fatalf("HOME child lifecycle was not clean: %+v", child)
	}
	t.Logf("owned HOME child completion: %+v", child)
	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if cleanup, err := service.Settle(context.Background(), root, linuxSettlement(receipt, request)); err != nil || !cleanup.Known() {
		t.Fatalf("HOME cache settlement: %+v %v", cleanup, err)
	}
	for _, path := range []string{results[0].File, results[1].File, runRoot} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("settlement left %s: %v", path, err)
		}
	}
	if contents := mustRead(t, sentinel); string(contents) != "operator home untouched" {
		t.Fatalf("Run changed operator home: %q", contents)
	}
	if entries, err := os.ReadDir(foreign); err != nil || len(entries) != 1 || entries[0].Name() != "operator.txt" {
		t.Fatalf("Run wrote into operator home: %v %v", entries, err)
	}
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
	home := filepath.Join(runPath(root, request.Claim.RunID), "home")
	for _, path := range []string{temporary, home} {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
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
	if daemon.recovers[0].Environment["HOME"] != home || daemon.stops[0].Environment["HOME"] != home {
		t.Fatal("recovery or stop lost Run HOME after its removal")
	}
}

func TestLinuxRefusesUnavailableRunDirectoriesBeforeDaemonLaunch(t *testing.T) {
	for _, directory := range []struct{ name, message string }{{"tmp", "Run temporary directory"}, {"home", "Run HOME directory"}} {
		for _, kind := range []string{"missing", "symlink", "file", "non-private"} {
			t.Run(directory.name+"/"+kind, func(t *testing.T) {
				if kind == "non-private" && runtime.GOOS != "linux" {
					t.Skip("native Linux private-path validation")
				}
				root := privateTempDir(t)
				daemon := &fakeDaemon{}
				service := NewService(Dependencies{Platform: "linux", Tasks: &unitLifecycleFake{}, Daemon: daemon})
				request := stageHostTestRun(t, service, root, time.Now().UTC(), false)
				if _, err := service.Start(context.Background(), root, request); err != nil {
					t.Fatal(err)
				}
				temporary := filepath.Join(runPath(root, request.Claim.RunID), directory.name)
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
				} else if kind == "non-private" {
					if err := os.Mkdir(temporary, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(temporary, 0o750); err != nil {
						t.Fatal(err)
					}
				}
				if err := service.ExecutePending(context.Background(), root); err == nil || !strings.Contains(err.Error(), directory.message) {
					t.Fatalf("unavailable %s directory accepted: %v", directory.name, err)
				}
				if len(daemon.starts) != 0 {
					t.Fatalf("daemon launched with unavailable %s directory", directory.name)
				}
			})
		}
	}
}

func TestWindowsRunDoesNotOverrideLinuxEnvironment(t *testing.T) {
	root := privateTempDir(t)
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Platform: "windows", Tasks: &fakeTaskLauncher{}, Daemon: daemon})
	request := stageHostTestRun(t, service, root, time.Now().UTC(), false)
	for _, name := range []string{"tmp", "home"} {
		if _, err := os.Lstat(filepath.Join(runPath(root, request.Claim.RunID), name)); !os.IsNotExist(err) {
			t.Fatalf("Windows staging gained a %s directory: %v", name, err)
		}
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
		for _, key := range []string{"TMPDIR", "TMP", "TEMP", "HOME"} {
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
