package host

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/payload"
)

type fakeTaskLauncher struct {
	taskName string
	launches int
}

type stoppingDaemon struct {
	started chan struct{}
	stopped chan struct{}
	once    sync.Once
	stops   []DaemonStop
}

type waitingDaemon struct {
	readyStarted chan struct{}
	stopped      chan struct{}
	once         sync.Once
	stops        []DaemonStop
}

type launchingDaemon struct {
	started chan struct{}
	stopped chan struct{}
	once    sync.Once
	stops   []DaemonStop
}

func (daemon *launchingDaemon) Start(context.Context, DaemonStart) (orchestrator.SessionID, error) {
	close(daemon.started)
	<-daemon.stopped
	return "bss_exact-launching-session-identity-123456", nil
}

func (daemon *launchingDaemon) Recover(context.Context, DaemonRecover) (orchestrator.SessionID, bool, error) {
	return "bss_exact-launching-session-identity-123456", true, nil
}

func (daemon *launchingDaemon) WaitReady(context.Context, DaemonReady) error {
	return errors.New("unexpected readiness after settlement")
}

func (daemon *launchingDaemon) Call(context.Context, DaemonCall) (json.RawMessage, error) {
	return nil, errors.New("unexpected call after settlement")
}

func (daemon *launchingDaemon) Stop(_ context.Context, request DaemonStop) error {
	daemon.stops = append(daemon.stops, request)
	daemon.once.Do(func() { close(daemon.stopped) })
	return nil
}

func (daemon *waitingDaemon) Start(context.Context, DaemonStart) (orchestrator.SessionID, error) {
	return "bss_exact-waiting-session-identity-123456", nil
}

func (daemon *waitingDaemon) Recover(context.Context, DaemonRecover) (orchestrator.SessionID, bool, error) {
	return "", false, nil
}

func (daemon *waitingDaemon) WaitReady(ctx context.Context, _ DaemonReady) error {
	close(daemon.readyStarted)
	select {
	case <-daemon.stopped:
		return errors.New("Session stopped")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (daemon *waitingDaemon) Call(context.Context, DaemonCall) (json.RawMessage, error) {
	return nil, errors.New("unexpected call before readiness")
}

func (daemon *waitingDaemon) Stop(_ context.Context, request DaemonStop) error {
	daemon.stops = append(daemon.stops, request)
	daemon.once.Do(func() { close(daemon.stopped) })
	return nil
}

func (daemon *stoppingDaemon) Start(context.Context, DaemonStart) (orchestrator.SessionID, error) {
	return "bss_exact-stoppable-session-identity-123456", nil
}

func (daemon *stoppingDaemon) Recover(context.Context, DaemonRecover) (orchestrator.SessionID, bool, error) {
	return "", false, nil
}

func (daemon *stoppingDaemon) WaitReady(context.Context, DaemonReady) error { return nil }

func (daemon *stoppingDaemon) Call(ctx context.Context, request DaemonCall) (json.RawMessage, error) {
	if request.Command != "execute_code" {
		return nil, errors.New("unexpected capture after stop")
	}
	close(daemon.started)
	select {
	case <-daemon.stopped:
		return nil, errors.New("Session stopped")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (daemon *stoppingDaemon) Stop(_ context.Context, request DaemonStop) error {
	daemon.stops = append(daemon.stops, request)
	daemon.once.Do(func() { close(daemon.stopped) })
	return nil
}

func (fake *fakeTaskLauncher) Launch(_ context.Context, taskName string) error {
	fake.taskName = taskName
	fake.launches++
	return nil
}

type fakeDaemon struct {
	starts          []DaemonStart
	readies         []DaemonReady
	calls           []DaemonCall
	stops           []DaemonStop
	recovered       orchestrator.SessionID
	captureResponse json.RawMessage
}

type deadlineReadyDaemon struct {
	fakeDaemon
}

type lockedReadyDaemon struct {
	fakeDaemon
	root string
}

type publicationFailureDaemon struct {
	fakeDaemon
	sessionID          orchestrator.SessionID
	rollbackContextErr error
	stopCalls          int
}

func (daemon *deadlineReadyDaemon) WaitReady(context.Context, DaemonReady) error {
	return context.DeadlineExceeded
}

func (daemon *lockedReadyDaemon) WaitReady(ctx context.Context, _ DaemonReady) error {
	release, err := acquireOperation(context.Background(), daemon.root)
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		release()
	}()
	return nil
}

func (daemon *publicationFailureDaemon) Start(ctx context.Context, _ DaemonStart) (orchestrator.SessionID, error) {
	<-ctx.Done()
	return daemon.sessionID, nil
}

func (daemon *publicationFailureDaemon) Recover(context.Context, DaemonRecover) (orchestrator.SessionID, bool, error) {
	return daemon.sessionID, true, nil
}

func (daemon *publicationFailureDaemon) Stop(ctx context.Context, request DaemonStop) error {
	daemon.stopCalls++
	daemon.fakeDaemon.stops = append(daemon.fakeDaemon.stops, request)
	if daemon.stopCalls == 1 {
		daemon.rollbackContextErr = ctx.Err()
		return errors.New("injected rollback failure")
	}
	return nil
}

func (fake *fakeDaemon) Start(_ context.Context, request DaemonStart) (orchestrator.SessionID, error) {
	fake.starts = append(fake.starts, request)
	return "bss_exact-host-session-identity-123456", nil
}

func (fake *fakeDaemon) Recover(_ context.Context, _ DaemonRecover) (orchestrator.SessionID, bool, error) {
	return fake.recovered, fake.recovered != "", nil
}

func (fake *fakeDaemon) WaitReady(_ context.Context, request DaemonReady) error {
	fake.readies = append(fake.readies, request)
	return nil
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
	file, err := os.OpenFile(parameters.Filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := png.Encode(file, image.NewRGBA(image.Rect(0, 0, 800, 600))); err != nil {
		file.Close()
		return nil, err
	}
	if err := file.Close(); err != nil {
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

func TestViewportEvidenceRequiresMatchingPNGDimensions(t *testing.T) {
	root := t.TempDir()
	runID := orchestrator.RunID("bbx_01CAPTUREDIMENSIONRUN0000000")
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Daemon: daemon})
	request := orchestrator.RunRequest{
		Claim: orchestrator.LockClaim{RunID: runID},
		Body: orchestrator.RequestBody{
			SessionName:             "blender-box-capture-test",
			SessionBrokerExecutable: `C:\Fake\blendersessiond.exe`,
		},
	}
	path := filepath.Join(runPath(root, runID), "evidence", "screenshots", "viewport.png")
	response, err := json.Marshal(map[string]any{"success": true, "method": "offscreen", "width": 640, "height": 480, "filepath": path})
	if err != nil {
		t.Fatal(err)
	}
	daemon.captureResponse = response
	_, err = service.captureViewport(context.Background(), root, request, "bss_exact-capture-session-identity-123456", nil)
	if err == nil || !strings.Contains(err.Error(), "declared PNG") {
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
	if len(daemon.readies) != 1 || daemon.readies[0].SessionID != receipt.SessionID || daemon.readies[0].Name != body.SessionName {
		t.Fatalf("daemon readiness = %+v", daemon.readies)
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

func TestAcquireRejectsAReleasedRunIdentity(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	service := NewService(Dependencies{Now: func() time.Time { return now }})
	claim := orchestrator.LockClaim{
		SchemaVersion: 1,
		RunID:         "bbx_01RELEASEDRUNIDENTITY0000000",
		RequestID:     "req_01RELEASEDREQUESTIDENTITY000",
		ControllerID:  "ctl_released-test",
		Deadline:      now.Add(time.Hour),
		RequestHash:   strings.Repeat("a", 64),
		TaskName:      "BlenderBoxTest",
	}
	receipt := orchestrator.RunReceipt{
		SchemaVersion: 1,
		Claim:         claim,
		State:         orchestrator.StateComplete,
		SessionID:     "bss_released-session-identity-123456",
		Evidence: orchestrator.EvidenceManifest{SchemaVersion: 1, Files: []orchestrator.EvidenceFile{{
			Path: "result.json", Type: "scenario-result", Size: 1, SHA256: strings.Repeat("b", 64),
		}}},
		Cleanup: orchestrator.CleanupState{SessionStopped: true, PayloadRemoved: true, RunRootRemoved: true, LockReleased: true},
	}
	if err := service.writeReceipt(root, receipt); err != nil {
		t.Fatal(err)
	}

	err := service.Acquire(context.Background(), root, AcquireRequest{SchemaVersion: 1, Claim: claim})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("Acquire() error = %v", err)
	}
	if _, statErr := os.Lstat(lockPath(root)); !os.IsNotExist(statErr) {
		t.Fatalf("Acquire() recreated Host Lock: %v", statErr)
	}
	stored, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: claim.RunID})
	if err != nil || stored.State != orchestrator.StateComplete || !stored.Cleanup.Known() {
		t.Fatalf("durable receipt changed: receipt = %+v, error = %v", stored, err)
	}
}

func TestAcquireRejectsTerminalReceiptWithAnActiveLock(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	service := NewService(Dependencies{Now: func() time.Time { return now }})
	claim := orchestrator.LockClaim{
		SchemaVersion: 1,
		RunID:         "bbx_01FAILEDRUNIDENTITY000000000",
		RequestID:     "req_01FAILEDREQUESTIDENTITY0000",
		ControllerID:  "ctl_failed-test",
		Deadline:      now.Add(time.Hour),
		RequestHash:   strings.Repeat("b", 64),
		TaskName:      "BlenderBoxTest",
	}
	request := AcquireRequest{SchemaVersion: 1, Claim: claim}
	if err := service.Acquire(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	receipt := orchestrator.RunReceipt{SchemaVersion: 1, Claim: claim, State: orchestrator.StateFailed, Error: "pre-session failure"}
	if err := service.writeReceipt(root, receipt); err != nil {
		t.Fatal(err)
	}

	err := service.Acquire(context.Background(), root, request)
	if err == nil || !strings.Contains(err.Error(), "non-replayable") {
		t.Fatalf("Acquire() error = %v", err)
	}
	stored, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: claim.RunID})
	if err != nil || stored.State != orchestrator.StateFailed || stored.Error != "pre-session failure" {
		t.Fatalf("terminal receipt changed: receipt = %+v, error = %v", stored, err)
	}
}

func TestHostOperationLockSurvivesPriorProcessExit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".operation.lock"), []byte("stale-owner\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	release, err := acquireOperation(ctx, root)
	if err != nil {
		t.Fatalf("acquire OS-released operation lock: %v", err)
	}
	release()
}

func TestCanceledOperationContextDoesNotAcquireAFreeLock(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	release, err := acquireOperation(ctx, t.TempDir())
	if err == nil {
		release()
		t.Fatal("acquireOperation() ignored canceled context")
	}
}

func TestSettleReleasesExactPartialAcquireWithoutReceipt(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	service := NewService(Dependencies{Now: func() time.Time { return now }})
	claim := testHostClaim(now, "PARTIALACQUIRE")
	if err := writeJSONAtomic(lockPath(root), lockRecord{SchemaVersion: 1, Claim: claim}); err != nil {
		t.Fatal(err)
	}
	cleanup, err := service.Settle(context.Background(), root, SettleRequest{
		SchemaVersion: 1,
		Receipt:       orchestrator.RunReceipt{SchemaVersion: 1, Claim: claim, State: orchestrator.StateAccepted},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cleanup.Known() {
		t.Fatalf("cleanup = %+v", cleanup)
	}
	if _, err := os.Stat(lockPath(root)); !os.IsNotExist(err) {
		t.Fatalf("Host Lock remains: %v", err)
	}
}

func TestStatusRecoversExactPartialAcquireWithoutReceipt(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	service := NewService(Dependencies{Now: func() time.Time { return now }})
	claim := testHostClaim(now, "PARTIALSTATUS")
	if err := writeJSONAtomic(lockPath(root), lockRecord{SchemaVersion: 1, Claim: claim}); err != nil {
		t.Fatal(err)
	}

	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: claim.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.SchemaVersion != 1 || !receipt.Claim.Equal(claim) || receipt.State != orchestrator.StateAccepted || receipt.SessionID != "" {
		t.Fatalf("recovered receipt = %+v", receipt)
	}
}

func TestSettleRecoversAfterLockReleaseBeforeFinalReceipt(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	service := NewService(Dependencies{Now: func() time.Time { return now }})
	claim := testHostClaim(now, "FINALRECEIPT")
	receipt := orchestrator.RunReceipt{
		SchemaVersion: 1,
		Claim:         claim,
		State:         orchestrator.StateComplete,
		Cleanup:       orchestrator.CleanupState{SessionStopped: true},
	}
	if err := service.writeReceipt(root, receipt); err != nil {
		t.Fatal(err)
	}

	cleanup, err := service.Settle(context.Background(), root, SettleRequest{SchemaVersion: 1, Receipt: receipt})
	if err != nil {
		t.Fatal(err)
	}
	if !cleanup.Known() {
		t.Fatalf("cleanup = %+v", cleanup)
	}
	stored, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: claim.RunID})
	if err != nil || !stored.Cleanup.Known() {
		t.Fatalf("stored receipt = %+v, error = %v", stored, err)
	}
}

func TestSettleRecoversPartialRunRootCleanupWithoutRepeatingStop(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
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
	receipt.Cleanup.SessionStopped = true
	if err := service.writeReceipt(root, receipt); err != nil {
		t.Fatal(err)
	}
	runRoot := runPath(root, request.Claim.RunID)
	entries, err := os.ReadDir(runRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() != "ownership.json" {
			if err := os.RemoveAll(filepath.Join(runRoot, entry.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Remove(filepath.Join(runRoot, "ownership.json")); err != nil {
		t.Fatal(err)
	}

	cleanup, err := service.Settle(context.Background(), root, SettleRequest{SchemaVersion: 1, Receipt: receipt})
	if err != nil {
		t.Fatal(err)
	}
	if !cleanup.Known() || len(daemon.stops) != 0 {
		t.Fatalf("cleanup = %+v, stops = %+v", cleanup, daemon.stops)
	}
}

func TestSettleRejectsNonEmptyRunRootWithoutOwnership(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
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
	receipt.Cleanup.SessionStopped = true
	if err := service.writeReceipt(root, receipt); err != nil {
		t.Fatal(err)
	}
	runRoot := runPath(root, request.Claim.RunID)
	if err := os.Remove(filepath.Join(runRoot, "ownership.json")); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(runRoot, "foreign.txt")
	if err := os.WriteFile(foreign, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = service.Settle(context.Background(), root, SettleRequest{SchemaVersion: 1, Receipt: receipt})
	if err == nil || !strings.Contains(err.Error(), "ownership") {
		t.Fatalf("Settle() error = %v", err)
	}
	if contents, readErr := os.ReadFile(foreign); readErr != nil || string(contents) != "preserve" {
		t.Fatalf("foreign file changed: contents = %q, error = %v", contents, readErr)
	}
}

func TestRunRootCleanupPreservesOwnershipUntilOtherEntriesAreRemoved(t *testing.T) {
	runRoot := t.TempDir()
	ownership := filepath.Join(runRoot, "ownership.json")
	if err := os.WriteFile(ownership, []byte("owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(runRoot, "daemon")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	removeAll := func(path string) error {
		if path == blocked {
			return fmt.Errorf("sharing violation")
		}
		return os.RemoveAll(path)
	}

	if err := removeRunRootPreservingOwnership(runRoot, removeAll); err == nil {
		t.Fatal("cleanup unexpectedly succeeded")
	}
	if _, err := os.Stat(ownership); err != nil {
		t.Fatalf("ownership proof was removed before blocked entries: %v", err)
	}
}

func TestRunRootCleanupRetriesTransientSharingViolation(t *testing.T) {
	runRoot := t.TempDir()
	if err := os.WriteFile(filepath.Join(runRoot, "ownership.json"), []byte("owned\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(runRoot, "daemon")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	removeAll := func(path string) error {
		if path == blocked && attempts == 0 {
			attempts++
			return fmt.Errorf("sharing violation")
		}
		return os.RemoveAll(path)
	}
	if err := removeRunRootWithRetry(context.Background(), runRoot, removeAll, func(error) bool { return true }, 0); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 {
		t.Fatalf("transient removals = %d, want 1", attempts)
	}
	if _, err := os.Stat(runRoot); !os.IsNotExist(err) {
		t.Fatalf("Run root remains: %v", err)
	}
}

func TestStartRehashesPublishedPayloadBeforeLaunch(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
	path := filepath.Join(runPath(root, request.Claim.RunID), "payload", "scenario.py")
	if err := os.WriteFile(path, []byte("tampered after transfer\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := service.Start(context.Background(), root, request)
	if err == nil || !strings.Contains(err.Error(), "published payload") {
		t.Fatalf("Start() error = %v, want published payload validation", err)
	}
}

func TestExactStopCanInterruptLongScenarioCall(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	daemon := &stoppingDaemon{started: make(chan struct{}), stopped: make(chan struct{})}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
	starting, err := service.Start(context.Background(), root, request)
	if err != nil {
		t.Fatal(err)
	}
	executionDone := make(chan error, 1)
	go func() { executionDone <- service.ExecutePending(context.Background(), root) }()
	select {
	case <-daemon.started:
	case <-time.After(time.Second):
		t.Fatal("Scenario call did not start")
	}
	settleCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cleanup, err := service.Settle(settleCtx, root, SettleRequest{SchemaVersion: 1, Receipt: starting})
	if err != nil {
		t.Fatalf("settle during Scenario call: %v", err)
	}
	if !cleanup.Known() {
		t.Fatalf("cleanup = %+v", cleanup)
	}
	select {
	case <-executionDone:
	case <-time.After(time.Second):
		t.Fatal("Scheduled Task did not observe exact stop")
	}
	if len(daemon.stops) != 1 || daemon.stops[0].SessionID != "bss_exact-stoppable-session-identity-123456" {
		t.Fatalf("daemon stops = %+v", daemon.stops)
	}
	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil || !receipt.Cleanup.Known() {
		t.Fatalf("final receipt = %+v, error = %v", receipt, err)
	}
}

func TestExactStopCanInterruptSessionReadiness(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	daemon := &waitingDaemon{readyStarted: make(chan struct{}), stopped: make(chan struct{})}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
	starting, err := service.Start(context.Background(), root, request)
	if err != nil {
		t.Fatal(err)
	}
	executionDone := make(chan error, 1)
	go func() { executionDone <- service.ExecutePending(context.Background(), root) }()
	select {
	case <-daemon.readyStarted:
	case <-time.After(time.Second):
		t.Fatal("Session readiness did not start")
	}
	cleanup, err := service.Settle(context.Background(), root, SettleRequest{SchemaVersion: 1, Receipt: starting})
	if err != nil {
		t.Fatal(err)
	}
	if !cleanup.Known() || len(daemon.stops) != 1 || daemon.stops[0].SessionID != "bss_exact-waiting-session-identity-123456" {
		t.Fatalf("cleanup = %+v, stops = %+v", cleanup, daemon.stops)
	}
	select {
	case <-executionDone:
	case <-time.After(time.Second):
		t.Fatal("Scheduled Task did not observe exact stop during readiness")
	}
}

func TestExpiredLaunchDeadlinePersistsTimedOutReceipt(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Add(-21 * time.Minute)
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	if err := service.ExecutePending(context.Background(), root); err == nil {
		t.Fatal("ExecutePending() unexpectedly passed its deadline")
	}
	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil || receipt.State != orchestrator.StateTimedOut {
		t.Fatalf("deadline receipt = %+v, error = %v", receipt, err)
	}
	if _, err := service.Settle(context.Background(), root, SettleRequest{SchemaVersion: 1, Receipt: receipt}); err != nil {
		t.Fatal(err)
	}
}

func TestReadinessDeadlinePersistsTimedOutReceipt(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	daemon := &deadlineReadyDaemon{}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	if err := service.ExecutePending(context.Background(), root); err == nil {
		t.Fatal("ExecutePending() unexpectedly passed daemon deadline")
	}
	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil || receipt.State != orchestrator.StateTimedOut || receipt.SessionID == "" {
		t.Fatalf("readiness deadline receipt = %+v, error = %v", receipt, err)
	}
	if _, err := service.Settle(context.Background(), root, SettleRequest{SchemaVersion: 1, Receipt: receipt}); err != nil {
		t.Fatal(err)
	}
}

func TestReadinessReconciliationPersistsTimedOutReceipt(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Add(-20*time.Minute + 2*time.Second)
	daemon := &lockedReadyDaemon{root: root}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	if err := service.ExecutePending(context.Background(), root); err == nil {
		t.Fatal("ExecutePending() unexpectedly passed reconciliation after its deadline")
	}
	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil || receipt.State != orchestrator.StateTimedOut || receipt.SessionID == "" {
		t.Fatalf("reconciliation deadline receipt = %+v, error = %v", receipt, err)
	}
	if _, err := service.Settle(context.Background(), root, SettleRequest{SchemaVersion: 1, Receipt: receipt}); err != nil {
		t.Fatal(err)
	}
}

func TestExactStopCanInterruptDaemonStartup(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	daemon := &launchingDaemon{started: make(chan struct{}), stopped: make(chan struct{})}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
	starting, err := service.Start(context.Background(), root, request)
	if err != nil {
		t.Fatal(err)
	}
	executionDone := make(chan error, 1)
	go func() { executionDone <- service.ExecutePending(context.Background(), root) }()
	select {
	case <-daemon.started:
	case <-time.After(time.Second):
		t.Fatal("daemon startup did not begin")
	}
	settleCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cleanup, err := service.Settle(settleCtx, root, SettleRequest{SchemaVersion: 1, Receipt: starting})
	if err != nil {
		t.Fatalf("settle during daemon startup: %v", err)
	}
	if !cleanup.Known() || len(daemon.stops) != 1 || daemon.stops[0].SessionID != "bss_exact-launching-session-identity-123456" {
		t.Fatalf("cleanup = %+v, stops = %+v", cleanup, daemon.stops)
	}
	select {
	case <-executionDone:
	case <-time.After(time.Second):
		t.Fatal("Scheduled Task did not observe settlement during daemon startup")
	}
}

func TestExactStartReplayReturnsDurableReceiptWithoutRelaunch(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	launcher := &fakeTaskLauncher{}
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Tasks: launcher, Daemon: daemon, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	if err := service.ExecutePending(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	replayed, err := service.Start(context.Background(), root, request)
	if err != nil {
		t.Fatal(err)
	}
	if replayed.State != orchestrator.StateComplete || replayed.SessionID == "" {
		t.Fatalf("replayed receipt = %+v", replayed)
	}
	if launcher.launches != 1 {
		t.Fatalf("task launches = %d, want 1", launcher.launches)
	}
}

func TestSettleReconcilesSessionPublishedOnlyInHostLock(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
	starting, err := service.Start(context.Background(), root, request)
	if err != nil {
		t.Fatal(err)
	}
	lock, err := service.readLock(root)
	if err != nil {
		t.Fatal(err)
	}
	lock.SessionID = "bss_exact-published-lock-session-123456"
	if err := writeJSONAtomic(lockPath(root), lock); err != nil {
		t.Fatal(err)
	}
	cleanup, err := service.Settle(context.Background(), root, SettleRequest{SchemaVersion: 1, Receipt: starting})
	if err != nil {
		t.Fatal(err)
	}
	if !cleanup.Known() || len(daemon.stops) != 1 || daemon.stops[0].SessionID != lock.SessionID {
		t.Fatalf("cleanup = %+v, stops = %+v", cleanup, daemon.stops)
	}
}

func TestSettleRecoversSessionStartedBeforeHostLockPublication(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	daemon := &fakeDaemon{recovered: "bss_exact-recovered-session-identity-123456"}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
	starting, err := service.Start(context.Background(), root, request)
	if err != nil {
		t.Fatal(err)
	}

	cleanup, err := service.Settle(context.Background(), root, SettleRequest{SchemaVersion: 1, Receipt: starting})
	if err != nil {
		t.Fatal(err)
	}
	if !cleanup.Known() || len(daemon.stops) != 1 || daemon.stops[0].SessionID != daemon.recovered {
		t.Fatalf("cleanup = %+v, stops = %+v", cleanup, daemon.stops)
	}
}

func TestSettleAdoptsExactReceiptIdentityAfterPublicationRollbackFails(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC().Add(-20*time.Minute + 2*time.Second)
	daemon := &publicationFailureDaemon{sessionID: "bss_exact-publication-failure-session-123456"}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, Now: func() time.Time { return now }})
	writeCalls := 0
	service.writeLock = func(path string, lock lockRecord) error {
		writeCalls++
		if writeCalls == 1 {
			return errors.New("injected Host Lock publication failure")
		}
		return writeLockAtomic(path, lock)
	}
	request := stageHostTestRun(t, service, root, now, false)
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	executeErr := service.ExecutePending(context.Background(), root)
	if executeErr == nil {
		t.Fatal("ExecutePending() unexpectedly survived injected publication failure")
	}
	if daemon.rollbackContextErr != nil {
		t.Fatalf("rollback used expired Run context: %v", daemon.rollbackContextErr)
	}
	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil || receipt.State != orchestrator.StateCleanupFailed || receipt.SessionID != daemon.sessionID {
		t.Fatalf("publication failure receipt = %+v, status error = %v, execute error = %v", receipt, err, executeErr)
	}
	cleanup, err := service.Settle(context.Background(), root, SettleRequest{SchemaVersion: 1, Receipt: receipt})
	if err != nil {
		t.Fatal(err)
	}
	if !cleanup.Known() || daemon.stopCalls != 2 || daemon.stops[1].SessionID != daemon.sessionID {
		t.Fatalf("cleanup = %+v, stops = %+v", cleanup, daemon.stops)
	}
}

func TestSettleRejectsTamperedStoredRunRequestBeforeDaemonStop(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, Now: func() time.Time { return now }})
	request := stageHostTestRun(t, service, root, now, false)
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
	request.Body.SessionBrokerExecutable = `C:\Attacker\replacement.exe`
	if err := writeJSONAtomic(filepath.Join(runPath(root, request.Claim.RunID), "request.json"), request); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Settle(context.Background(), root, SettleRequest{SchemaVersion: 1, Receipt: receipt}); err == nil || !strings.Contains(err.Error(), "stored Run request") {
		t.Fatalf("Settle() error = %v", err)
	}
	if len(daemon.stops) != 0 {
		t.Fatalf("tampered daemon path reached stop: %+v", daemon.stops)
	}
}

func stageHostTestRun(t *testing.T, service *Service, root string, now time.Time, capture bool) orchestrator.RunRequest {
	t.Helper()
	script := []byte("print scenario result\n")
	hash := sha256.Sum256(script)
	manifest := payload.Payload{
		SchemaVersion: 1,
		Files: []payload.File{{
			Source:      "scenario.py",
			Destination: "scenario.py",
			Size:        int64(len(script)),
			SHA256:      hex.EncodeToString(hash[:]),
		}},
		Scenario: payload.Scenario{Script: "scenario.py", ReadTimeoutSeconds: 600, CaptureViewport: capture},
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
	claim := testHostClaim(now, "HOSTSTAGETEST")
	claim.RequestHash = hex.EncodeToString(requestHash[:])
	request := orchestrator.RunRequest{Claim: claim, Body: body}
	if err := service.Acquire(context.Background(), root, AcquireRequest{SchemaVersion: 1, Claim: claim}); err != nil {
		t.Fatal(err)
	}
	if err := service.Stage(context.Background(), root, StageRequest{SchemaVersion: 1, Claim: claim, Files: []StageFile{{
		Destination: "scenario.py", Size: int64(len(script)), SHA256: hex.EncodeToString(hash[:]), Contents: script,
	}}}); err != nil {
		t.Fatal(err)
	}
	return request
}

func testHostClaim(now time.Time, suffix string) orchestrator.LockClaim {
	return orchestrator.LockClaim{
		SchemaVersion: 1,
		RunID:         orchestrator.RunID("bbx_01" + suffix + "RUNIDENTITY0000000000"),
		RequestID:     orchestrator.RequestID("req_01" + suffix + "REQUESTIDENTITY000000"),
		ControllerID:  "ctl_host-test",
		Deadline:      now.Add(20 * time.Minute),
		RequestHash:   strings.Repeat("a", 64),
		TaskName:      "BlenderBoxTest",
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
