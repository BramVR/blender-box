package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/payload"
)

type fakeTaskLauncher struct {
	taskName string
}

func (fake *fakeTaskLauncher) Launch(_ context.Context, taskName string) error {
	fake.taskName = taskName
	return nil
}

type fakeDaemon struct {
	starts          []DaemonStart
	calls           []DaemonCall
	stops           []DaemonStop
	captureResponse json.RawMessage
}

func (fake *fakeDaemon) Start(_ context.Context, request DaemonStart) (orchestrator.SessionID, error) {
	fake.starts = append(fake.starts, request)
	return "bss_exact-host-session-identity-123456", nil
}

func (fake *fakeDaemon) Call(_ context.Context, request DaemonCall) (json.RawMessage, error) {
	fake.calls = append(fake.calls, request)
	if request.Command == "execute_code" {
		return json.RawMessage(`{"executed":true,"result":"{\"schema_version\":1,\"status\":\"pass\",\"object\":\"Slice0Cube\"}\n"}`), nil
	}
	var parameters struct {
		Filepath string `json:"filepath"`
	}
	if err := json.Unmarshal(request.Parameters, &parameters); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(parameters.Filepath), 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(parameters.Filepath, []byte("fake-viewport-png"), 0o600); err != nil {
		return nil, err
	}
	if fake.captureResponse != nil {
		return fake.captureResponse, nil
	}
	response, _ := json.Marshal(map[string]any{"success": true, "method": "offscreen", "width": 800, "height": 600, "filepath": parameters.Filepath})
	return response, nil
}

func TestViewportEvidenceRequiresSuccessfulCaptureProvenance(t *testing.T) {
	root := t.TempDir()
	runID := orchestrator.RunID("bbx_01CAPTURERUNIDENTITY00000000")
	daemon := &fakeDaemon{captureResponse: json.RawMessage(`{"error":"capture failed"}`)}
	service := NewService(Dependencies{Daemon: daemon})
	request := orchestrator.RunRequest{
		Claim: orchestrator.LockClaim{RunID: runID},
		Body: orchestrator.RequestBody{
			SessionName:             "blender-box-capture-test",
			SessionBrokerExecutable: `C:\Fake\blendersessiond.exe`,
		},
	}
	_, err := service.captureViewport(context.Background(), root, request, "bss_exact-capture-session-identity-123456", nil)
	if err == nil || !strings.Contains(err.Error(), "invalid viewport capture result") {
		t.Fatalf("capture error = %v", err)
	}
}

func (fake *fakeDaemon) Stop(_ context.Context, request DaemonStop) error {
	fake.stops = append(fake.stops, request)
	return nil
}

func TestServiceRunsFencedScenarioAndReturnsEvidenceBeforeExactCleanup(t *testing.T) {
	root := t.TempDir()
	launcher := &fakeTaskLauncher{}
	daemon := &fakeDaemon{}
	now := time.Now().UTC()
	service := NewService(Dependencies{
		Tasks:  launcher,
		Daemon: daemon,
		Now:    func() time.Time { return now },
	})
	script := []byte("print scenario result\n")
	scriptHash := sha256.Sum256(script)
	manifest := payload.Payload{
		SchemaVersion: 1,
		Files: []payload.File{{
			Source:      "scenario.py",
			Destination: "scenario.py",
			Size:        int64(len(script)),
			SHA256:      hex.EncodeToString(scriptHash[:]),
		}},
		Scenario: payload.Scenario{
			Script:             "scenario.py",
			ReadTimeoutSeconds: 600,
			CaptureViewport:    true,
		},
	}
	body := orchestrator.RequestBody{
		SchemaVersion:           1,
		SessionName:             "blender-box-host-test",
		BlenderExecutable:       `C:\Fake\blender.exe`,
		SessionBrokerExecutable: `C:\Fake\blendersessiond.exe`,
		Payload:                 manifest,
	}
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	requestHash := sha256.Sum256(bodyJSON)
	claim := orchestrator.LockClaim{
		SchemaVersion: 1,
		RunID:         "bbx_01HOSTRUNIDENTITY00000000000",
		RequestID:     "req_01HOSTREQUESTIDENTITY000000",
		ControllerID:  "ctl_host-test",
		Deadline:      now.Add(20 * time.Minute),
		RequestHash:   hex.EncodeToString(requestHash[:]),
		TaskName:      "BlenderBoxTest",
	}
	request := orchestrator.RunRequest{Claim: claim, Body: body}

	if err := service.Acquire(context.Background(), root, AcquireRequest{SchemaVersion: 1, Claim: claim}); err != nil {
		t.Fatal(err)
	}
	if err := service.Stage(context.Background(), root, StageRequest{SchemaVersion: 1, Claim: claim, Files: []StageFile{{
		Destination: "scenario.py",
		Size:        int64(len(script)),
		SHA256:      hex.EncodeToString(scriptHash[:]),
		Contents:    script,
	}}}); err != nil {
		t.Fatal(err)
	}
	starting, err := service.Start(context.Background(), root, request)
	if err != nil {
		t.Fatal(err)
	}
	if starting.State != orchestrator.StateStarting || starting.SessionID != "" || launcher.taskName != claim.TaskName {
		t.Fatalf("starting receipt = %+v, task = %q", starting, launcher.taskName)
	}
	if err := service.ExecutePending(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: claim.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != orchestrator.StateComplete || receipt.SessionID != "bss_exact-host-session-identity-123456" || len(receipt.Evidence.Files) != 2 {
		t.Fatalf("complete receipt = %+v", receipt)
	}
	if len(daemon.starts) != 1 || daemon.starts[0].Name != body.SessionName {
		t.Fatalf("daemon starts = %+v", daemon.starts)
	}
	if len(daemon.calls) != 2 {
		t.Fatalf("daemon calls = %+v", daemon.calls)
	}
	for _, call := range daemon.calls {
		if call.SessionID != receipt.SessionID || call.Name != body.SessionName {
			t.Fatalf("call lost Session identity: %+v", call)
		}
	}
	if daemon.calls[0].Command != "execute_code" || daemon.calls[0].ReadTimeoutSeconds != 600 {
		t.Fatalf("Scenario call = %+v", daemon.calls[0])
	}
	if daemon.calls[1].Command != "get_viewport_screenshot" {
		t.Fatalf("capture call = %+v", daemon.calls[1])
	}

	for _, evidence := range receipt.Evidence.Files {
		contents, err := service.Fetch(root, FetchRequest{SchemaVersion: 1, Receipt: receipt, File: evidence})
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(contents)
		if int64(len(contents)) != evidence.Size || hex.EncodeToString(hash[:]) != evidence.SHA256 {
			t.Fatalf("fetched evidence changed: %+v", evidence)
		}
	}
	// A dropped Start response may leave the client with claim-only authority;
	// the host still resolves and stops its recorded exact Session identity.
	cleanup, err := service.Settle(context.Background(), root, SettleRequest{SchemaVersion: 1, Receipt: starting})
	if err != nil {
		t.Fatal(err)
	}
	if !cleanup.Known() {
		t.Fatalf("cleanup = %+v", cleanup)
	}
	if len(daemon.stops) != 1 || daemon.stops[0].SessionID != receipt.SessionID || daemon.stops[0].Name != body.SessionName {
		t.Fatalf("daemon stops = %+v", daemon.stops)
	}
	if _, err := os.Stat(filepath.Join(root, "runs", string(claim.RunID))); !os.IsNotExist(err) {
		t.Fatalf("Run root remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "host-lock.json")); !os.IsNotExist(err) {
		t.Fatalf("Host Lock remains: %v", err)
	}
	finalReceipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: claim.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if !finalReceipt.Cleanup.Known() {
		t.Fatalf("persisted cleanup is not known: %+v", finalReceipt)
	}
	if strings.Contains(string(mustRead(t, filepath.Join(root, "receipts", string(claim.RunID)+".json"))), "fake-viewport-png") {
		t.Fatal("receipt embedded evidence contents")
	}
}

func TestStatusRejectsRunIDPathTraversal(t *testing.T) {
	service := NewService(Dependencies{})
	_, err := service.Status(t.TempDir(), StatusRequest{
		SchemaVersion: 1,
		RunID:         "bbx_../../host-lock",
	})
	if err == nil || !strings.Contains(err.Error(), "invalid status contract") {
		t.Fatalf("Status() error = %v, want invalid status contract", err)
	}
}

func TestRepeatedAcquireDoesNotRegressReceiptState(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	service := NewService(Dependencies{Now: func() time.Time { return now }})
	claim := orchestrator.LockClaim{
		SchemaVersion: 1,
		RunID:         "bbx_01IDEMPOTENTRUNIDENTITY000000",
		RequestID:     "req_01IDEMPOTENTREQUESTIDENTITY00",
		ControllerID:  "ctl_idempotent-test",
		Deadline:      now.Add(time.Hour),
		RequestHash:   strings.Repeat("a", 64),
		TaskName:      "BlenderBoxTest",
	}
	request := AcquireRequest{SchemaVersion: 1, Claim: claim}
	if err := service.Acquire(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	receipt := orchestrator.RunReceipt{SchemaVersion: 1, Claim: claim, State: orchestrator.StateStaged}
	if err := service.writeReceipt(root, receipt); err != nil {
		t.Fatal(err)
	}
	if err := service.Acquire(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	got, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: claim.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if got.State != orchestrator.StateStaged {
		t.Fatalf("receipt state regressed to %q", got.State)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
