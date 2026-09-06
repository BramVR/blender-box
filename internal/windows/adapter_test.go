package windows

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/BramVR/blender-box/internal/capture"
	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/payload"
	"github.com/BramVR/blender-box/internal/target"
)

type scriptedSSH struct {
	outputs      [][]byte
	arguments    [][]string
	inputs       [][]byte
	uploads      []scriptedUpload
	runHook      func()
	runResult    func(context.Context, int, []string, []byte) ([]byte, error)
	uploadResult func(context.Context, int, string, string, string) error
}

type scriptedUpload struct {
	host        string
	source      string
	destination string
	contents    []byte
}

func TestInspectReadsCaptureSupportFromInstalledHost(t *testing.T) {
	checks := make([]map[string]any, 0, 10)
	for _, id := range []string{
		"host.windows", "host.console-user", "host.ssh-user", "host.limited-token-policy",
		"blender.executable", "daemon.executable", "host.executable", "work-root.access",
		"work-root.state-tree", "task.interactive",
	} {
		checks = append(checks, map[string]any{"id": id, "passed": true, "required": true})
	}
	checkResult := map[string]any{"schema_version": 1, "status": "pass", "checks": checks}
	capabilities := host.CapabilitiesResponse{
		SchemaVersion: 1,
		Status:        "pass",
		Captures: []orchestrator.CaptureSupport{
			{Kind: capture.Viewport, Capability: "capture-viewport-v1", Supported: true},
			{Kind: capture.BlenderWindow, Capability: "capture-blender-window-v1", Supported: true},
			{Kind: capture.Desktop, Capability: "capture-desktop-v1", Supported: false},
		},
	}
	fake := &scriptedSSH{outputs: [][]byte{mustJSON(t, checkResult), mustJSON(t, capabilities)}}

	inspection, err := NewAdapter(fake).Inspect(context.Background(), adapterTarget(), orchestrator.HostRequirements{PayloadSchemaVersion: 2, Captures: []capture.Kind{capture.Desktop}})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Status != "pass" || len(inspection.Captures) != 3 || inspection.Captures[2].Supported {
		t.Fatalf("inspection = %+v", inspection)
	}
	if string(fake.inputs[1]) != "{\"schema_version\":1}" {
		t.Fatalf("legacy schema2 capabilities changed: %s", fake.inputs[1])
	}
	if len(fake.arguments) != 2 || !strings.Contains(decodedAdapterScript(t, fake.arguments[1]), "'host' 'capabilities'") {
		t.Fatalf("host capability calls = %d", len(fake.arguments))
	}
}

func TestInspectPreservesLegacyViewportWithoutHostCapabilityCommand(t *testing.T) {
	checks := make([]map[string]any, 0, 10)
	for _, id := range []string{
		"host.windows", "host.console-user", "host.ssh-user", "host.limited-token-policy",
		"blender.executable", "daemon.executable", "host.executable", "work-root.access",
		"work-root.state-tree", "task.interactive",
	} {
		checks = append(checks, map[string]any{"id": id, "passed": true, "required": true})
	}
	checkResult := map[string]any{"schema_version": 1, "status": "pass", "checks": checks}
	fake := &scriptedSSH{outputs: [][]byte{mustJSON(t, checkResult)}}

	inspection, err := NewAdapter(fake).Inspect(context.Background(), adapterTarget(), orchestrator.HostRequirements{PayloadSchemaVersion: 1, Captures: []capture.Kind{capture.Viewport}})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Status != "pass" || len(inspection.Captures) != 1 || !inspection.Captures[0].Supported || inspection.Captures[0].Kind != capture.Viewport {
		t.Fatalf("inspection = %+v", inspection)
	}
	if len(fake.arguments) != 1 {
		t.Fatalf("legacy inspection made %d SSH calls", len(fake.arguments))
	}
}

func TestInspectRequiresUpgradedHostCapabilitiesForSchema2Viewport(t *testing.T) {
	capabilities := host.CapabilitiesResponse{SchemaVersion: 1, Status: "pass", Captures: []orchestrator.CaptureSupport{
		{Kind: capture.Viewport, Capability: "capture-viewport-v1", Supported: true},
		{Kind: capture.BlenderWindow, Capability: "capture-blender-window-v1", Supported: true},
		{Kind: capture.Desktop, Capability: "capture-desktop-v1", Supported: true},
	}}
	fake := &scriptedSSH{outputs: [][]byte{passingAdapterCheck(t), mustJSON(t, capabilities)}}

	inspection, err := NewAdapter(fake).Inspect(context.Background(), adapterTarget(), orchestrator.HostRequirements{PayloadSchemaVersion: 2, Captures: []capture.Kind{capture.Viewport}})
	if err != nil || inspection.Status != "pass" {
		t.Fatalf("inspection = %+v, error = %v", inspection, err)
	}
	if len(fake.arguments) != 2 {
		t.Fatalf("schema 2 inspection made %d SSH calls", len(fake.arguments))
	}
}

func passingAdapterCheck(t *testing.T) []byte {
	t.Helper()
	checks := make([]map[string]any, 0, 10)
	for _, id := range []string{
		"host.windows", "host.console-user", "host.ssh-user", "host.limited-token-policy",
		"blender.executable", "daemon.executable", "host.executable", "work-root.access",
		"work-root.state-tree", "task.interactive",
	} {
		checks = append(checks, map[string]any{"id": id, "passed": true, "required": true})
	}
	return mustJSON(t, map[string]any{"schema_version": 1, "status": "pass", "checks": checks})
}

func (fake *scriptedSSH) Run(ctx context.Context, _ string, arguments []string, input []byte) ([]byte, error) {
	if fake.runHook != nil {
		hook := fake.runHook
		fake.runHook = nil
		hook()
	}
	fake.arguments = append(fake.arguments, append([]string(nil), arguments...))
	fake.inputs = append(fake.inputs, append([]byte(nil), input...))
	if fake.runResult != nil {
		return fake.runResult(ctx, len(fake.arguments)-1, arguments, input)
	}
	if len(fake.outputs) == 0 {
		return nil, fmt.Errorf("unexpected SSH call %d", len(fake.arguments)-1)
	}
	output := fake.outputs[0]
	fake.outputs = fake.outputs[1:]
	return output, nil
}

func (fake *scriptedSSH) Upload(ctx context.Context, host, source, destination string) error {
	contents, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	fake.uploads = append(fake.uploads, scriptedUpload{host: host, source: source, destination: destination, contents: contents})
	if fake.uploadResult != nil {
		return fake.uploadResult(ctx, len(fake.uploads)-1, host, source, destination)
	}
	return nil
}

func TestAdapterCarriesTypedAuthorityAcrossEveryHostOperation(t *testing.T) {
	claim := orchestrator.LockClaim{
		SchemaVersion: 1,
		RunID:         "bbx_01ADAPTERRUNIDENTITY00000000",
		RequestID:     "req_01ADAPTERREQUESTIDENTITY000",
		ControllerID:  "ctl_adapter-test",
		Deadline:      time.Now().Add(time.Hour).UTC(),
		RequestHash:   strings.Repeat("a", 64),
		TaskName:      "BlenderBoxTest",
	}
	starting := orchestrator.RunReceipt{SchemaVersion: 1, Claim: claim, State: orchestrator.StateStarting}
	running := starting
	running.State = orchestrator.StateRunning
	running.SessionID = "bss_exact-adapter-session-identity-123456"
	complete := running
	complete.State = orchestrator.StateComplete
	contents := []byte("returned evidence")
	cleanup := orchestrator.CleanupState{SessionStopped: true, PayloadRemoved: true, RunRootRemoved: true, LockReleased: true}
	fake := &scriptedSSH{outputs: [][]byte{
		mustJSON(t, host.Acknowledgement{SchemaVersion: 1, Status: "acquired"}),
		mustJSON(t, host.Acknowledgement{SchemaVersion: 1, Status: "staged"}),
		mustJSON(t, starting),
		mustJSON(t, running),
		mustJSON(t, complete),
		mustJSON(t, host.FetchResponse{SchemaVersion: 1, Contents: contents}),
		mustJSON(t, host.SettleResponse{SchemaVersion: 1, Cleanup: cleanup}),
	}}
	adapter := NewAdapter(fake)
	adapter.pollInterval = time.Millisecond
	selected := adapterTarget()
	loaded := adapterPayload(t)

	if err := adapter.Acquire(context.Background(), selected, claim); err != nil {
		t.Fatal(err)
	}
	if err := adapter.Stage(context.Background(), selected, claim, loaded); err != nil {
		t.Fatal(err)
	}
	request := orchestrator.RunRequest{Claim: claim, Body: orchestrator.RequestBody{SchemaVersion: 1, Payload: loaded}}
	started, err := adapter.Start(context.Background(), selected, request)
	if err != nil {
		t.Fatal(err)
	}
	if started.SessionID != running.SessionID {
		t.Fatalf("Start returned Session identity %q", started.SessionID)
	}
	observed, err := adapter.Observe(context.Background(), selected, claim.RunID)
	if err != nil {
		t.Fatal(err)
	}
	file := orchestrator.EvidenceFile{Path: "result/scenario-result.json", Type: "scenario-result", Size: int64(len(contents)), SHA256: strings.Repeat("b", 64)}
	fetched, err := adapter.Fetch(context.Background(), selected, observed, file)
	if err != nil {
		t.Fatal(err)
	}
	if string(fetched) != string(contents) {
		t.Fatalf("fetched = %q", fetched)
	}
	settled, err := adapter.Settle(context.Background(), selected, observed)
	if err != nil {
		t.Fatal(err)
	}
	if settled != cleanup {
		t.Fatalf("cleanup = %+v", settled)
	}

	wantOperations := []string{"acquire", "stage", "start", "start", "status", "fetch", "settle"}
	for index, want := range wantOperations {
		script := decodedAdapterScript(t, fake.arguments[index])
		if !strings.Contains(script, "'host' '"+want+"'") || !strings.Contains(script, selected.HostExecutable) || !strings.Contains(script, selected.WorkRoot) {
			t.Fatalf("operation %d script = %q", index, script)
		}
	}
	var staged host.StageRequest
	if err := json.Unmarshal(fake.inputs[1], &staged); err != nil {
		t.Fatal(err)
	}
	if staged.Claim != claim || len(staged.Files) != 1 || string(staged.Files[0].Contents) != string(loaded.Files[0].Contents()) {
		t.Fatalf("staged request = %+v", staged)
	}
	var settlement host.SettleRequest
	if err := json.Unmarshal(fake.inputs[6], &settlement); err != nil {
		t.Fatal(err)
	}
	if settlement.Receipt.SessionID != running.SessionID || settlement.Receipt.Claim != claim {
		t.Fatalf("settlement authority changed: %+v", settlement)
	}
	if settlement.SessionBrokerExecutable != selected.SessionBrokerExecutable || settlement.SessionName != orchestrator.SessionNameForRun(claim.RunID) {
		t.Fatalf("settlement daemon authority changed: %+v", settlement)
	}
}

func TestAdapterEscapesTargetPathsAsPowerShellLiterals(t *testing.T) {
	selected := adapterTarget()
	selected.WorkRoot = `C:\Operator's Box`
	selected.HostExecutable = `C:\Operator's Box\bin\blender-box.exe`
	fake := &scriptedSSH{outputs: [][]byte{mustJSON(t, host.Acknowledgement{SchemaVersion: 1, Status: "acquired"})}}
	claim := orchestrator.LockClaim{
		SchemaVersion: 1,
		RunID:         "bbx_01QUOTEDPATHRUNIDENTITY0000",
		RequestID:     "req_01QUOTEDPATHREQUESTIDENTITY",
		ControllerID:  "ctl_quoted-path-test",
		Deadline:      time.Now().Add(time.Hour).UTC(),
		RequestHash:   strings.Repeat("a", 64),
		TaskName:      selected.TaskName,
	}

	if err := NewAdapter(fake).Acquire(context.Background(), selected, claim); err != nil {
		t.Fatal(err)
	}
	script := decodedAdapterScript(t, fake.arguments[0])
	if !strings.Contains(script, `& 'C:\Operator''s Box\bin\blender-box.exe'`) || !strings.Contains(script, `'--state-root' 'C:\Operator''s Box'`) {
		t.Fatalf("target paths are not safe PowerShell literals: %s", script)
	}
}

func adapterTarget() target.Target {
	return target.Target{
		SchemaVersion:           1,
		SSHAlias:                "windows-test",
		SSHUser:                 "test-user",
		WorkRoot:                `C:\BlenderBoxTest`,
		InteractiveUser:         "test-user",
		TaskName:                "BlenderBoxTest",
		BlenderExecutable:       `C:\Program Files\Blender Foundation\Blender 5.2\blender.exe`,
		SessionBrokerExecutable: `C:\BlenderBoxTest\bin\blendersessiond.exe`,
		HostExecutable:          `C:\BlenderBoxTest\bin\blender-box.exe`,
	}
}

func adapterPayload(t *testing.T) payload.Payload {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "scenario.py"), []byte("print('{}')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	document := `{"schema_version":1,"files":[{"source":"scenario.py","destination":"scenario.py"}],"scenario":{"script":"scenario.py"}}`
	path := filepath.Join(root, "payload.json")
	if err := os.WriteFile(path, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := payload.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func decodedAdapterScript(t *testing.T, arguments []string) string {
	t.Helper()
	for index, argument := range arguments {
		if argument != "-EncodedCommand" || index+1 >= len(arguments) {
			continue
		}
		encoded, err := base64.StdEncoding.DecodeString(arguments[index+1])
		if err != nil || len(encoded)%2 != 0 {
			t.Fatalf("invalid encoded command: %v", err)
		}
		runes := make([]uint16, len(encoded)/2)
		for runeIndex := range runes {
			runes[runeIndex] = binary.LittleEndian.Uint16(encoded[runeIndex*2:])
		}
		return string(utf16.Decode(runes))
	}
	t.Fatal("missing encoded command")
	return ""
}
