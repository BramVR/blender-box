package windowsinstall

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windowstarget"
)

type fakeMachine struct {
	inspection      Inspection
	current         taskObservation
	taskSpec        taskSpec
	taskCalls       []string
	probes          int
	probeErr        error
	taskHook        func()
	taskMutationErr error
	inspectionErr   error
}

func (m *fakeMachine) inspect(_ context.Context, r Request) (Inspection, error) {
	result := m.inspection
	result.RootIdentity = ""
	if _, err := os.Lstat(r.StateRoot); err == nil {
		result.RootIdentity, _ = fileIdentity(r.StateRoot)
	}
	return result, m.inspectionErr
}
func (m *fakeMachine) securePath(_ context.Context, path, _ string, missing bool) error {
	return checkPath(path, missing)
}
func (m *fakeMachine) createDirectory(_ context.Context, path, _ string) error {
	return os.Mkdir(path, 0700)
}
func (m *fakeMachine) task(_ context.Context, action string, spec taskSpec) (taskObservation, error) {
	m.taskCalls = append(m.taskCalls, action)
	if m.taskHook != nil {
		m.taskHook()
	}
	if action == "create" {
		if m.current.Exists {
			return m.current, fmt.Errorf("task collision")
		}
		m.taskSpec = spec
		m.current = taskObservation{Exists: true, Matches: true, Fingerprint: objectDigest(spec)}
	}
	if action == "delete" {
		if !m.current.Exists || !m.current.Matches || m.current.Running {
			return m.current, fmt.Errorf("task conflict")
		}
		m.current = taskObservation{}
	}
	if action == "create" || action == "delete" {
		return m.current, m.taskMutationErr
	}
	return m.current, nil
}
func (m *fakeMachine) probe(_ context.Context, broker, _ string) error {
	m.probes++
	for _, relative := range []string{"blendersessiond.exe", "python/Scripts/python.exe", "python/pyvenv.cfg", "python/Lib/site-packages/blendersessiond/__main__.py", "python/Lib/site-packages/blendersessiond/windows_job.py"} {
		if _, err := os.Stat(filepath.Join(filepath.Dir(broker), filepath.FromSlash(relative))); err != nil {
			return fmt.Errorf("broker prerequisite unavailable: %w", err)
		}
	}
	return m.probeErr
}
func (m *fakeMachine) target(i installIntent) (target.Target, error) {
	return target.NewWindows(i.SSHAlias, windowstarget.Config{SSHUser: i.WindowsUser, InteractiveUser: i.WindowsUser, WorkRoot: `C:\Box`, TaskName: i.Task.Name, BlenderExecutable: `C:\Blender\blender.exe`, SessionBrokerExecutable: `C:\Box\runtime\blendersessiond.exe`, HostExecutable: `C:\Box\runtime\blender-box.exe`})
}
func tempRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}
func peFixture() []byte {
	data := make([]byte, 256)
	copy(data, "MZ")
	binary.LittleEndian.PutUint32(data[0x3c:], 128)
	copy(data[128:], "PE\x00\x00")
	binary.LittleEndian.PutUint16(data[132:], 0x8664)
	binary.LittleEndian.PutUint16(data[150:], 2)
	return data
}
func wheelFixture(t *testing.T, extra map[string]string) []byte {
	t.Helper()
	files := map[string]string{"blendersessiond/__main__.py": "print('daemon')\n", "blendersessiond/__init__.py": "", "blendersessiond/windows_job.py": "", "blendersessiond-1.0.dist-info/METADATA": "Metadata-Version: 2.1\nName: blendersessiond\nVersion: 1.0\nRequires-Python: >=3.11\n", "blendersessiond-1.0.dist-info/WHEEL": "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"}
	for path, data := range extra {
		files[path] = data
	}
	var bytes bytes.Buffer
	writer := zip.NewWriter(&bytes)
	for _, path := range sortedKeys(files) {
		file, err := writer.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = file.Write([]byte(files[path])); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return bytes.Bytes()
}
func installFixture(t *testing.T) (*installer, *fakeMachine, Request) {
	t.Helper()
	root := tempRoot(t)
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	paths := []string{filepath.Join(source, "host.exe"), filepath.Join(source, "broker.exe"), filepath.Join(source, "daemon.whl"), filepath.Join(source, "template.exe")}
	for i, path := range paths {
		data := peFixture()
		if i == 2 {
			data = wheelFixture(t, nil)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	sourceInfo := SourceProvenance{Repository: "test/runtime", SourceCommit: strings.Repeat("a", 40), PatchSHA256: SHA256(strings.Repeat("0", 64)), BuildRecipeSHA256: SHA256(strings.Repeat("b", 64))}
	manifest, err := BuildManifest(paths[0], paths[1], paths[2], sourceInfo, sourceInfo)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(source, "runtime.json")
	data, _ := json.Marshal(manifest)
	if err = os.WriteFile(manifestPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	templateID, _ := fileIdentity(paths[3])
	candidate := Candidate{Path: paths[0], SHA256: digest(peFixture()), Identity: "source-id", Version: "3.11.15"}
	machine := &fakeMachine{inspection: Inspection{OwnerSID: "S-1-5-21-test", BlenderCandidates: []Candidate{{Path: paths[0], SHA256: digest(peFixture()), Identity: "blender-id"}}, Python: &PythonPrerequisite{Candidate: candidate, Home: source, Template: Candidate{Path: paths[3], SHA256: digest(peFixture()), Identity: templateID}}}}
	request := Request{Operation: "install", Platform: "windows", StateRoot: filepath.Join(root, "state"), RuntimePath: manifestPath, BlenderPath: paths[0], PythonPath: paths[0], SSHAlias: "test-host", WindowsUser: "test-user", TaskName: "test-task"}
	return &installer{machine: machine}, machine, request
}
func TestPreviewInstallRepeatRemovePreservesAuthority(t *testing.T) {
	e, m, r := installFixture(t)
	planned, err := e.Execute(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if planned.State != "planned" || planned.InstallationID == "" || planned.Plan.PlanSHA256 == "" {
		t.Fatalf("plan=%+v", planned)
	}
	if _, err := os.Lstat(r.StateRoot); !os.IsNotExist(err) {
		t.Fatal("preview created state")
	}
	r.InstallationID = planned.InstallationID
	r.OperationID = planned.OperationID
	r.ExpectedPlan = planned.Plan.PlanSHA256
	r.Apply = true
	installed, err := e.Execute(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if installed.State != "installed" || installed.Target == nil || m.probes != 1 {
		t.Fatalf("installed=%+v", installed)
	}
	operationIdentity, _ := fileIdentity(filepath.Join(r.StateRoot, ".operation.lock"))
	launchIdentity, _ := fileIdentity(filepath.Join(r.StateRoot, ".launch.lock"))
	again, err := e.Execute(context.Background(), r)
	if err != nil || again.InstallationID != installed.InstallationID || again.OperationID != installed.OperationID || again.State != "installed" {
		t.Fatalf("repeat=%+v %v", again, err)
	}
	r.InstallationID = ""
	r.OperationID = ""
	r.ExpectedPlan = ""
	automatic, err := e.Execute(context.Background(), r)
	if err != nil || automatic.InstallationID != installed.InstallationID || automatic.OperationID != installed.OperationID {
		t.Fatalf("automatic repeat=%+v %v", automatic, err)
	}
	remove := Request{Operation: "remove", Platform: "windows", StateRoot: r.StateRoot, InstallationID: installed.InstallationID, Apply: true}
	removed, err := e.Execute(context.Background(), remove)
	if err != nil || removed.State != "removed" || m.current.Exists {
		t.Fatalf("remove=%+v %v", removed, err)
	}
	removed, err = e.Execute(context.Background(), remove)
	if err != nil || removed.State != "removed" {
		t.Fatalf("repeat remove=%+v %v", removed, err)
	}
	operationAfter, _ := fileIdentity(filepath.Join(r.StateRoot, ".operation.lock"))
	launchAfter, _ := fileIdentity(filepath.Join(r.StateRoot, ".launch.lock"))
	if operationIdentity != operationAfter || launchIdentity != launchAfter {
		t.Fatal("authority lock identity changed")
	}
	if _, err := os.Stat(filepath.Join(r.StateRoot, "installations", string(installed.InstallationID), "receipt.json")); err != nil {
		t.Fatal("missing tombstone")
	}
}

func TestMissingOwnedTaskIsAConflictBeforePreviewOrApply(t *testing.T) {
	for _, operation := range []string{"inspect", "install", "remove"} {
		for _, apply := range []bool{false, true} {
			if operation == "inspect" && apply {
				continue
			}
			t.Run(fmt.Sprintf("%s/apply=%t", operation, apply), func(t *testing.T) {
				e, m, request := installFixture(t)
				request.Apply = true
				installed, err := e.Execute(context.Background(), request)
				if err != nil {
					t.Fatal(err)
				}
				request.InstallationID = installed.InstallationID
				request.Operation = operation
				request.Apply = apply
				m.current = taskObservation{}
				m.taskCalls = nil
				receiptPath := filepath.Join(request.StateRoot, "installations", string(request.InstallationID), "receipt.json")
				before, err := os.ReadFile(receiptPath)
				if err != nil {
					t.Fatal(err)
				}
				result, err := e.Execute(context.Background(), request)
				if err == nil || !strings.Contains(err.Error(), "owned task missing") {
					t.Fatalf("state=%s error=%v", result.State, err)
				}
				after, readErr := os.ReadFile(receiptPath)
				if readErr != nil || !bytes.Equal(before, after) || strings.Join(m.taskCalls, ",") != "inspect" {
					t.Fatalf("receipt/task mutation calls=%v error=%v", m.taskCalls, readErr)
				}
			})
		}
	}
}
func TestInterruptedPublicationAndRemovalConverge(t *testing.T) {
	for _, point := range []string{"prepared", "before-create:runtime", "after-create:runtime", "before-create:runtime/blender-box.exe", "after-create:runtime/blender-box.exe", "before-create:task", "after-create:task", "before-delete:task", "after-delete:task", "before-delete:runtime/blender-box.exe", "after-delete:runtime/blender-box.exe", "before-delete:runtime", "after-delete:runtime"} {
		t.Run(point, func(t *testing.T) {
			e, _, r := installFixture(t)
			r.Apply = true
			id, _ := newID("bbxi_")
			r.InstallationID = InstallationID(id)
			remove := strings.Contains(point, "delete")
			if remove {
				if _, err := e.Execute(context.Background(), r); err != nil {
					t.Fatal(err)
				}
				r = Request{Operation: "remove", Platform: "windows", StateRoot: r.StateRoot, InstallationID: r.InstallationID, Apply: true}
			}
			fired := false
			e.checkpoint = func(at string) error {
				if at == point {
					fired = true
					return fmt.Errorf("simulated interruption")
				}
				return nil
			}
			partial, err := e.Execute(context.Background(), r)
			if err == nil || !fired || partial.InstallationID != r.InstallationID {
				t.Fatalf("interruption=%+v %v fired=%v", partial, err, fired)
			}
			e.checkpoint = nil
			final, err := e.Execute(context.Background(), r)
			want := "installed"
			if remove {
				want = "removed"
			}
			if err != nil || final.State != want || final.OperationID != partial.OperationID {
				t.Fatalf("resume=%+v %v", final, err)
			}
		})
	}
}
func TestOperationIDConflictPreservesInstallation(t *testing.T) {
	for _, phase := range []string{"installed", "removing", "removed"} {
		for _, apply := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/apply=%t", phase, apply), func(t *testing.T) {
				e, m, request := installFixture(t)
				request.Apply = true
				request.OperationID = "bbxo_11111111111111111111111111111111"
				current, err := e.Execute(context.Background(), request)
				if err != nil {
					t.Fatal(err)
				}
				request.InstallationID = current.InstallationID
				if phase != "installed" {
					request = Request{Operation: "remove", Platform: "windows", StateRoot: request.StateRoot, InstallationID: current.InstallationID, OperationID: "bbxo_22222222222222222222222222222222", Apply: true}
					if phase == "removing" {
						e.checkpoint = func(point string) error {
							if point == "before-delete:task" {
								return fmt.Errorf("simulated interruption")
							}
							return nil
						}
					}
					current, err = e.Execute(context.Background(), request)
					if phase == "removing" && err == nil || phase == "removed" && err != nil {
						t.Fatalf("prepare %s: %v", phase, err)
					}
					e.checkpoint = nil
				}
				path := filepath.Join(request.StateRoot, "installations", string(current.InstallationID), "receipt.json")
				before, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				request.Apply = apply
				request.OperationID = "bbxo_33333333333333333333333333333333"
				taskBefore := m.current
				result, err := e.Execute(context.Background(), request)
				if err == nil || !strings.Contains(err.Error(), "operation-conflict") {
					t.Fatalf("changed operation state=%s error=%v", result.State, err)
				}
				if result.OperationID != current.OperationID {
					t.Fatalf("operation=%s want durable %s", result.OperationID, current.OperationID)
				}
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(before, after) || m.current != taskBefore {
					t.Fatalf("conflict changed receipt or task: %v", err)
				}
			})
		}
	}
}

func TestRemovalStartsDistinctOperationAndRetainsPreviewIdentity(t *testing.T) {
	for _, apply := range []bool{false, true} {
		t.Run(fmt.Sprintf("apply=%t", apply), func(t *testing.T) {
			e, _, install := installFixture(t)
			install.Apply = true
			installed, err := e.Execute(context.Background(), install)
			if err != nil {
				t.Fatal(err)
			}
			remove := Request{Operation: "remove", Platform: "windows", StateRoot: install.StateRoot, InstallationID: installed.InstallationID, OperationID: installed.OperationID, Apply: apply}
			if _, err := e.Execute(context.Background(), remove); err == nil || !strings.Contains(err.Error(), "operation-conflict") {
				t.Fatalf("remove reused installation operation: %v", err)
			}
			remove.Apply = false
			remove.OperationID = ""
			preview, err := e.Execute(context.Background(), remove)
			if err != nil || preview.OperationID == "" || preview.OperationID == installed.OperationID {
				t.Fatalf("remove preview operation=%s error=%v", preview.OperationID, err)
			}
			install.InstallationID = installed.InstallationID
			install.Apply = false
			unchanged, err := e.Execute(context.Background(), install)
			if err != nil || unchanged.OperationID != installed.OperationID || unchanged.State != "installed" {
				t.Fatalf("preview changed installation: %+v %v", unchanged, err)
			}
			remove.Apply = true
			remove.OperationID = preview.OperationID
			remove.ExpectedPlan = preview.Plan.PlanSHA256
			removed, err := e.Execute(context.Background(), remove)
			if err != nil || removed.State != "removed" || removed.OperationID != preview.OperationID {
				t.Fatalf("remove operation=%s state=%s error=%v", removed.OperationID, removed.State, err)
			}
			remove.OperationID = ""
			repeated, err := e.Execute(context.Background(), remove)
			if err != nil || repeated.State != "removed" || repeated.OperationID != removed.OperationID {
				t.Fatalf("repeat operation=%s state=%s error=%v", repeated.OperationID, repeated.State, err)
			}
		})
	}
}

func TestInstalledTaskUsesExecutableParentAsWorkingDirectory(t *testing.T) {
	e, m, request := installFixture(t)
	request.Apply = true
	installed, err := e.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(request.StateRoot, "installations", string(installed.InstallationID), "runtime")
	if m.taskSpec.Directory != want || filepath.Dir(m.taskSpec.Executable) != m.taskSpec.Directory {
		t.Fatalf("working directory=%q executable=%q want=%q", m.taskSpec.Directory, m.taskSpec.Executable, want)
	}
}

func TestRemovalWithoutCompleteRuntimeConverges(t *testing.T) {
	for _, point := range []string{"before-delete:runtime/blendersessiond.exe", "before-create:runtime", "before-create:runtime/blender-box.exe", "before-create:runtime/python/Lib/site-packages/blendersessiond/__init__.py", "before-create:task"} {
		t.Run(point, func(t *testing.T) {
			e, m, request := installFixture(t)
			request.Apply = true
			removing := strings.Contains(point, "delete")
			if removing {
				installed, err := e.Execute(context.Background(), request)
				if err != nil {
					t.Fatal(err)
				}
				request = Request{Operation: "remove", Platform: "windows", StateRoot: request.StateRoot, InstallationID: installed.InstallationID, Apply: true}
			}
			fired := false
			e.checkpoint = func(at string) error {
				if at == point {
					fired = true
					return fmt.Errorf("simulated interruption")
				}
				return nil
			}
			partial, err := e.Execute(context.Background(), request)
			if err == nil || !fired {
				t.Fatalf("interruption error=%v fired=%v", err, fired)
			}
			e.checkpoint = nil
			request.Operation = "remove"
			request.InstallationID = partial.InstallationID
			request.OperationID = ""
			probes := m.probes
			removed, err := e.Execute(context.Background(), request)
			if err != nil || removed.State != "removed" {
				t.Fatalf("removal state=%s error=%v", removed.State, err)
			}
			if m.probes != probes || m.current.Exists {
				t.Fatalf("probes=%d want=%d task exists=%v", m.probes, probes, m.current.Exists)
			}
			if _, err := os.Lstat(filepath.Join(request.StateRoot, "installations", string(removed.InstallationID), "runtime")); !os.IsNotExist(err) {
				t.Fatalf("runtime remains: %v", err)
			}
			repeated, err := e.Execute(context.Background(), request)
			if err != nil || repeated.State != "removed" || repeated.OperationID != removed.OperationID {
				t.Fatalf("repeat removal state=%s operation=%s error=%v", repeated.State, repeated.OperationID, err)
			}
		})
	}
}

func TestRemovalRefusesReplacementAndPreservesUnknownFiles(t *testing.T) {
	for _, kind := range []string{"changed-bytes", "replaced-file", "unknown-descendant", "task-replacement", "running-task", "probe-failure"} {
		t.Run(kind, func(t *testing.T) {
			e, m, r := installFixture(t)
			r.Apply = true
			result, err := e.Execute(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join(r.StateRoot, "installations", string(result.InstallationID), "runtime")
			hostPath := filepath.Join(directory, "blender-box.exe")
			switch kind {
			case "changed-bytes":
				err = os.WriteFile(hostPath, []byte("modified"), 0600)
			case "replaced-file":
				err = os.Rename(hostPath, filepath.Join(directory, "kept-original.exe"))
				if err == nil {
					err = os.WriteFile(hostPath, peFixture(), 0600)
				}
			case "unknown-descendant":
				err = os.WriteFile(filepath.Join(directory, "operator.txt"), []byte("keep"), 0600)
			case "task-replacement":
				m.current.Matches = false
				m.current.Fingerprint = SHA256(strings.Repeat("e", 64))
			case "running-task":
				m.current.Running = true
			case "probe-failure":
				m.probeErr = fmt.Errorf("capability unavailable")
			}
			if err != nil {
				t.Fatal(err)
			}
			if kind == "probe-failure" {
				_, err = e.Execute(context.Background(), r)
			} else {
				_, err = e.Execute(context.Background(), Request{Operation: "remove", Platform: "windows", StateRoot: r.StateRoot, InstallationID: result.InstallationID, Apply: true})
			}
			if err == nil {
				t.Fatal("conflict accepted")
			}
			if kind == "unknown-descendant" {
				data, err := os.ReadFile(filepath.Join(directory, "operator.txt"))
				if err != nil || string(data) != "keep" {
					t.Fatal("unknown file removed")
				}
			} else if _, err := os.Stat(hostPath); err != nil {
				t.Fatal("owned executable deleted through conflict")
			}
		})
	}
}
func TestUnsupportedPlatformAndUnownedCollisionsNeverWrite(t *testing.T) {
	e, m, r := installFixture(t)
	r.Platform = "linux"
	r.Apply = true
	if _, err := e.Execute(context.Background(), r); err == nil {
		t.Fatal("unsupported accepted")
	}
	if len(m.taskCalls) != 0 {
		t.Fatal("unsupported called native task")
	}
	if _, err := os.Stat(r.StateRoot); !os.IsNotExist(err) {
		t.Fatal("unsupported wrote")
	}
	r.Platform = "windows"
	m.current = taskObservation{Exists: true, Matches: true}
	if _, err := e.Execute(context.Background(), r); err == nil {
		t.Fatal("unowned task adopted")
	}
	if _, err := os.Stat(r.StateRoot); !os.IsNotExist(err) {
		t.Fatal("task collision wrote")
	}
	if runtime.GOOS != "windows" {
		if _, err := NewLocal().Execute(context.Background(), r); err == nil {
			t.Fatal("non-Windows local executor accepted")
		}
	}
}
func TestRemovalRetainsUnrecordedCreations(t *testing.T) {
	for _, component := range []string{"runtime", "runtime/blender-box.exe", "task"} {
		t.Run(component, func(t *testing.T) {
			e, m, request := installFixture(t)
			request.Apply = true
			fired := false
			e.checkpoint = func(point string) error {
				if point == "after-create:"+component {
					fired = true
					return fmt.Errorf("simulated interruption")
				}
				return nil
			}
			partial, err := e.Execute(context.Background(), request)
			if err == nil || !fired {
				t.Fatalf("interruption error=%v fired=%v", err, fired)
			}
			e.checkpoint = nil
			directory := filepath.Join(request.StateRoot, "installations", string(partial.InstallationID))
			path := filepath.Join(directory, "receipt.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			taskBefore := m.current
			remove := Request{Operation: "remove", Platform: "windows", StateRoot: request.StateRoot, InstallationID: partial.InstallationID, Apply: true}
			result, err := e.Execute(context.Background(), remove)
			if err == nil || result.State == "removed" {
				t.Fatalf("unrecorded creation removed: state=%s error=%v", result.State, err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) || m.current != taskBefore {
				t.Fatalf("unrecorded creation changed receipt/task: %v", err)
			}
			if component != "task" {
				if _, err := os.Stat(filepath.Join(directory, filepath.FromSlash(component))); err != nil {
					t.Fatalf("unrecorded creation not retained: %v", err)
				}
			}
		})
	}
}

func TestReceiptReadbackFailureReportsUnknownCompletion(t *testing.T) {
	e, _, request := installFixture(t)
	request.Apply = true
	request.InstallationID = "bbxi_11111111111111111111111111111111"
	e.checkpoint = func(point string) error {
		if point != "prepared" {
			return nil
		}
		path := filepath.Join(request.StateRoot, "installations", string(request.InstallationID), "receipt.json")
		if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
			t.Fatal(err)
		}
		return fmt.Errorf("simulated receipt corruption")
	}
	result, err := e.Execute(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "read installation receipt") || result.Completion != "unknown" || result.State != "partial" {
		t.Fatalf("state=%s completion=%s error=%v", result.State, result.Completion, err)
	}
}

func TestReceiptPublicationRejectsInvalidState(t *testing.T) {
	for _, kind := range []string{"pending-terminal-state", "duplicate-inventory"} {
		t.Run(kind, func(t *testing.T) {
			e, _, request := installFixture(t)
			request.Apply = true
			installed, err := e.Execute(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(request.StateRoot, "installations", string(installed.InstallationID), "receipt.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			receipt, err := readReceipt(path)
			if err != nil {
				t.Fatal(err)
			}
			generation := receipt.Generation
			if kind == "pending-terminal-state" {
				receipt.State = "removed"
				receipt.Pending = &mutation{Action: "create", Path: "runtime"}
			} else {
				receipt.Intent.Files = append(receipt.Intent.Files, receipt.Intent.Files[0])
				receipt.IntentSHA256 = objectDigest(receipt.Intent)
			}
			if err := saveReceipt(path, &receipt, true); err == nil {
				t.Fatal("invalid receipt published")
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) || receipt.Generation != generation {
				t.Fatalf("invalid save changed durable receipt or generation: %v", err)
			}
		})
	}
}

func TestExpandedInventoryRejectsBeforeHostStateMutation(t *testing.T) {
	for _, kind := range []string{"excessive-directories", "implicit-directory-case-collision", "implicit-directory-unicode-collision"} {
		for _, apply := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/apply=%t", kind, apply), func(t *testing.T) {
				e, m, request := installFixture(t)
				bundle, err := ReadBundle(request.RuntimePath)
				if err != nil {
					t.Fatal(err)
				}
				extra := map[string]string{"blendersessiond/Foo/a.py": "", "blendersessiond/foo/b.py": ""}
				if kind == "implicit-directory-unicode-collision" {
					extra = map[string]string{"blendersessiond/S/a.py": "", "blendersessiond/ſ/b.py": ""}
				}
				if kind == "excessive-directories" {
					extra = map[string]string{}
					for i := 0; i < 1100; i++ {
						extra[fmt.Sprintf("blendersessiond/package%d/module.py", i)] = ""
					}
				}
				wheel := wheelFixture(t, extra)
				for i := range bundle.Manifest.Artifacts {
					artifact := &bundle.Manifest.Artifacts[i]
					if artifact.Role == ArtifactDaemonWheel {
						if err := os.WriteFile(artifact.Name, wheel, 0600); err != nil {
							t.Fatal(err)
						}
						artifact.Size = int64(len(wheel))
						artifact.SHA256 = digest(wheel)
					}
				}
				manifest, err := json.Marshal(bundle.Manifest)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(request.RuntimePath, manifest, 0600); err != nil {
					t.Fatal(err)
				}
				request.Apply = apply
				e.checkpoint = func(string) error { return fmt.Errorf("unexpected receipt publication") }
				result, err := e.Execute(context.Background(), request)
				if err == nil || !strings.Contains(err.Error(), "invalid-inventory") {
					t.Errorf("inventory state=%s error=%v", result.State, err)
				}
				if _, err := os.Lstat(request.StateRoot); !os.IsNotExist(err) {
					t.Errorf("invalid inventory created state root: %v", err)
				}
				if len(m.taskCalls) != 0 || m.probes != 0 {
					t.Errorf("invalid inventory reached task/probe effects: tasks=%v probes=%d", m.taskCalls, m.probes)
				}
			})
		}
	}
}

func TestWheelRejectsWindowsUnicodeAliases(t *testing.T) {
	for _, extra := range []map[string]string{
		{"blendersessiond/S.py": "", "blendersessiond/ſ.py": ""},
		{"blendersessiond/S": "", "blendersessiond/ſ/child.py": ""},
	} {
		if _, err := readWheel(wheelFixture(t, extra)); err == nil {
			t.Fatalf("Windows aliases accepted: %v", extra)
		}
	}
}

func TestRemovalWithoutExternalInterpreter(t *testing.T) {
	e, machine, request := installFixture(t)
	request.Apply = true
	installed, err := e.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	machine.probeErr = fmt.Errorf("external Python is unavailable")
	removed, err := e.Execute(context.Background(), Request{Operation: "remove", Platform: "windows", StateRoot: request.StateRoot, InstallationID: installed.InstallationID, Apply: true})
	if err != nil || removed.State != "removed" || machine.current.Exists {
		t.Fatalf("remove with unavailable interpreter=%s, error=%v", removed.State, err)
	}
}

func TestNativeCleanupUncertaintyReachesResult(t *testing.T) {
	e, machine, request := installFixture(t)
	request.Apply = true
	machine.probeErr = fmt.Errorf("probe process tree: %w", errNativeCleanupUnknown)
	result, err := e.Execute(context.Background(), request)
	if err == nil || result.State != "partial" || result.Completion != "unknown" || machine.current.Exists {
		t.Fatalf("uncertain probe cleanup result=%+v, error=%v", result, err)
	}
}

func TestManifestRejectsChangedSourcesAndUnsafeWheel(t *testing.T) {
	for _, extra := range []map[string]string{{"../escape": "x"}, {"blendersessiond/../escape": "x"}, {"blendersessiond/CON": "x"}, {"blendersessiond/__MAIN__.py": "x"}, {"blendersessiond/ambient.pth": "x"}, {"evil/module.py": "x"}, {"blendersessiond-1.0.dist-info/METADATA": "Name: blendersessiond\nRequires-Python: >=3.11\nRequires-Dist: external\n"}, {"blendersessiond-1.0.dist-info/WHEEL": "Root-Is-Purelib: false\nTag: cp311-win_amd64\n"}} {
		if _, err := readWheel(wheelFixture(t, extra)); err == nil {
			t.Fatalf("unsafe wheel accepted: %v", extra)
		}
	}
	_, _, r := installFixture(t)
	bundle, err := ReadBundle(r.RuntimePath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(bundle.Manifest.Artifacts[0].Name, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadBundle(r.RuntimePath); err == nil {
		t.Fatal("changed manifest source accepted")
	}
}

func TestImmutableIntentChangeAndCorruptOtherReceiptRefuseApply(t *testing.T) {
	e, _, r := installFixture(t)
	r.Apply = true
	installed, err := e.Execute(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	r.InstallationID = installed.InstallationID
	r.TaskName = "changed-task"
	if _, err := e.Execute(context.Background(), r); err == nil || !strings.Contains(err.Error(), "intent-conflict") {
		t.Fatalf("changed intent=%v", err)
	}
	r.TaskName = "other-task"
	r.InstallationID = "bbxi_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	foreign := filepath.Join(r.StateRoot, "installations", "bbxi_cccccccccccccccccccccccccccccccc")
	if err := os.Mkdir(foreign, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "receipt.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Execute(context.Background(), r); err == nil {
		t.Fatal("corrupt other receipt ignored")
	}
	if _, err := os.Stat(filepath.Join(r.StateRoot, "installations", string(r.InstallationID))); !os.IsNotExist(err) {
		t.Fatal("wrote through corrupt authority")
	}
}
func TestManifestRejectsDuplicateMetadataAndSourceLinks(t *testing.T) {
	if _, err := readWheel(wheelFixture(t, map[string]string{"blendersessiond-1.0.dist-info/METADATA": "Name: blendersessiond\nName: blendersessiond\nRequires-Python: >=3.11\n"})); err == nil {
		t.Fatal("duplicate metadata accepted")
	}
	if _, err := readWheel(wheelFixture(t, map[string]string{"blendersessiond/nested": "x", "blendersessiond/nested/child.py": "x"})); err == nil {
		t.Fatal("file-directory collision accepted")
	}
	_, _, r := installFixture(t)
	bundle, err := ReadBundle(r.RuntimePath)
	if err != nil {
		t.Fatal(err)
	}
	source := bundle.Manifest.Artifacts[0].Name
	link := filepath.Join(filepath.Dir(source), "link.exe")
	if err := os.Symlink(source, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := readSource(link); err == nil {
		t.Fatal("source symlink accepted")
	}
}

func TestRunAcceptedBetweenPreviewAndFencePreventsManagedDirectoryWrites(t *testing.T) {
	e, m, r := installFixture(t)
	if err := os.Mkdir(r.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	r.Apply = true
	m.taskHook = func() {
		m.taskHook = nil
		if err := os.WriteFile(filepath.Join(r.StateRoot, "host-lock.json"), []byte("new-run"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.Execute(context.Background(), r); err == nil {
		t.Fatal("accepted Run ignored")
	}
	for _, directory := range []string{"runs", "receipts", "installations"} {
		if _, err := os.Stat(filepath.Join(r.StateRoot, directory)); !os.IsNotExist(err) {
			t.Fatalf("created %s before maintenance fence", directory)
		}
	}
	if m.current.Exists {
		t.Fatal("task created while Run active")
	}
}

func TestRemovalRetryPreservesTaskRecreatedAfterDeletion(t *testing.T) {
	for _, interrupted := range []bool{true, false} {
		t.Run(fmt.Sprintf("interrupted=%v", interrupted), func(t *testing.T) {
			e, machine, request := installFixture(t)
			request.Apply = true
			installed, err := e.Execute(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			original := machine.current
			request = Request{Operation: "remove", Platform: "windows", StateRoot: request.StateRoot, InstallationID: installed.InstallationID, Apply: true}
			if interrupted {
				e.checkpoint = func(point string) error {
					if strings.HasPrefix(point, "before-delete:runtime") {
						return fmt.Errorf("interrupted runtime removal")
					}
					return nil
				}
			}
			if _, err := e.Execute(context.Background(), request); (err != nil) != interrupted || machine.current.Exists {
				t.Fatalf("expected task deletion, interrupted=%v: %v", interrupted, err)
			}
			receiptPath := filepath.Join(request.StateRoot, "installations", string(installed.InstallationID), "receipt.json")
			receipt, err := readReceipt(receiptPath)
			if err != nil || !contains(receipt.Deleted, "task") {
				t.Fatalf("missing committed task deletion: %v", err)
			}
			e.checkpoint = nil
			machine.current = original
			for _, apply := range []bool{false, true} {
				request.Apply = apply
				machine.taskCalls = nil
				if _, err := e.Execute(context.Background(), request); err == nil {
					t.Fatalf("recreated task accepted, apply=%v", apply)
				}
				if !machine.current.Exists || contains(machine.taskCalls, "delete") {
					t.Fatal("recreated task deleted after ownership ended")
				}
				if _, err := readReceipt(receiptPath); err != nil {
					t.Fatalf("retry invalidated receipt: %v", err)
				}
			}
		})
	}
}
