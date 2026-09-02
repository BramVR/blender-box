package orchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/payload"
	"github.com/BramVR/blender-box/internal/target"
)

type fakeHost struct {
	operations []string
	receipt    RunReceipt
	evidence   map[string][]byte
}

func (host *fakeHost) Inspect(context.Context, target.Target) error {
	host.operations = append(host.operations, "inspect")
	return nil
}

func (host *fakeHost) Acquire(_ context.Context, _ target.Target, claim LockClaim) error {
	host.operations = append(host.operations, "acquire")
	host.receipt.Claim = claim
	return nil
}

func (host *fakeHost) Stage(_ context.Context, _ target.Target, claim LockClaim, _ payload.Payload) error {
	host.operations = append(host.operations, "stage")
	if claim != host.receipt.Claim {
		return fmt.Errorf("stage claim changed")
	}
	return nil
}

func (host *fakeHost) Start(_ context.Context, _ target.Target, request RunRequest) (RunReceipt, error) {
	host.operations = append(host.operations, "start")
	if request.Claim != host.receipt.Claim {
		return RunReceipt{}, fmt.Errorf("start claim changed")
	}
	host.receipt.State = StateRunning
	host.receipt.SchemaVersion = 1
	host.receipt.SessionID = "bss_exact-fake-session-identity-123456"
	return host.receipt, nil
}

func (host *fakeHost) Observe(_ context.Context, _ target.Target, runID RunID) (RunReceipt, error) {
	host.operations = append(host.operations, "observe")
	if runID != host.receipt.Claim.RunID {
		return RunReceipt{}, fmt.Errorf("observe run changed")
	}
	host.receipt.State = StateComplete
	host.receipt.Evidence = EvidenceManifest{
		SchemaVersion: 1,
		Files: []EvidenceFile{
			evidenceFile("scenario-result.json", "scenario-result", host.evidence["scenario-result.json"]),
			evidenceFile("viewport.png", "viewport", host.evidence["viewport.png"]),
		},
	}
	return host.receipt, nil
}

func (host *fakeHost) Fetch(_ context.Context, _ target.Target, receipt RunReceipt, file EvidenceFile) ([]byte, error) {
	host.operations = append(host.operations, "fetch:"+file.Path)
	if receipt.SessionID != host.receipt.SessionID || receipt.Claim != host.receipt.Claim {
		return nil, fmt.Errorf("fetch authority changed")
	}
	return append([]byte(nil), host.evidence[file.Path]...), nil
}

func (host *fakeHost) Settle(_ context.Context, _ target.Target, receipt RunReceipt) (CleanupState, error) {
	host.operations = append(host.operations, "settle")
	if receipt.SessionID != host.receipt.SessionID || receipt.Claim != host.receipt.Claim {
		return CleanupState{}, fmt.Errorf("settle authority changed")
	}
	return CleanupState{
		SessionStopped: true,
		PayloadRemoved: true,
		RunRootRemoved: true,
		LockReleased:   true,
	}, nil
}

func TestRunFromIntentToVerifiedEvidenceAndKnownCleanup(t *testing.T) {
	resultJSON := []byte(`{"objects":["Slice0Cube"],"status":"pass"}`)
	viewportPNG := testViewportPNG()
	host := &fakeHost{evidence: map[string][]byte{
		"scenario-result.json": resultJSON,
		"viewport.png":         viewportPNG,
	}}
	evidenceDir := filepath.Join(t.TempDir(), "artifacts", "blender-box", "bbx_test")
	deadline := time.Now().Add(time.Hour).UTC()
	intent := RunIntent{
		RunID:        "bbx_01TESTRUNIDENTITY0000000000",
		RequestID:    "req_01TESTREQUESTIDENTITY00000",
		ControllerID: "controller-test",
		Deadline:     deadline,
		Target: target.Target{
			SchemaVersion: 1,
			SSHAlias:      "windows-test",
			TaskName:      "BlenderBoxTest",
		},
		Payload:     loadTestPayload(t),
		EvidenceDir: evidenceDir,
	}

	result, err := New(host).Run(context.Background(), intent)
	if err != nil {
		t.Fatal(err)
	}

	wantOperations := []string{
		"inspect",
		"acquire",
		"stage",
		"start",
		"observe",
		"fetch:scenario-result.json",
		"fetch:viewport.png",
		"settle",
	}
	if !reflect.DeepEqual(host.operations, wantOperations) {
		t.Fatalf("operations = %#v, want %#v", host.operations, wantOperations)
	}
	if result.RunID != intent.RunID || result.RequestID != intent.RequestID {
		t.Fatalf("result identity changed: %+v", result)
	}
	if result.SessionID != host.receipt.SessionID {
		t.Fatalf("Session identity = %q", result.SessionID)
	}
	if result.State != StateComplete || !result.Cleanup.Known() {
		t.Fatalf("result not complete with known cleanup: %+v", result)
	}
	for name, content := range host.evidence {
		actual, err := os.ReadFile(filepath.Join(evidenceDir, name))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, content) {
			t.Fatalf("evidence %s changed", name)
		}
	}
	var storedManifest EvidenceManifest
	manifestJSON, err := os.ReadFile(filepath.Join(evidenceDir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(manifestJSON, &storedManifest); err != nil || !reflect.DeepEqual(storedManifest, result.Evidence) {
		t.Fatalf("stored manifest = %+v, error = %v", storedManifest, err)
	}
	var storedResult RunResult
	resultDocument, err := os.ReadFile(filepath.Join(evidenceDir, "evidence.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(resultDocument, &storedResult); err != nil || !reflect.DeepEqual(storedResult, result) {
		t.Fatalf("stored result = %+v, error = %v", storedResult, err)
	}
}

func TestValidateReceiptRequiresVersionStateAndPinnedSession(t *testing.T) {
	claim := LockClaim{
		SchemaVersion: 1,
		RunID:         "bbx_01TESTRUNIDENTITY0000000000",
		RequestID:     "req_01TESTREQUESTIDENTITY00000",
		ControllerID:  "controller-test",
		Deadline:      time.Now().Add(time.Hour).UTC(),
		RequestHash:   strings.Repeat("0", 64),
		TaskName:      "BlenderBoxTest",
	}
	valid := RunReceipt{
		SchemaVersion: 1,
		Claim:         claim,
		State:         StateRunning,
		SessionID:     "bss_exact-fake-session-identity-123456",
	}
	tests := []struct {
		name    string
		mutate  func(*RunReceipt)
		wantErr string
	}{
		{"versionless", func(receipt *RunReceipt) { receipt.SchemaVersion = 0 }, "schema version"},
		{"unknown state", func(receipt *RunReceipt) { receipt.State = "surprise" }, "Run state"},
		{"missing Session identity", func(receipt *RunReceipt) { receipt.SessionID = "" }, "Session identity"},
		{"changed Session identity", func(receipt *RunReceipt) { receipt.SessionID = "bss_other-valid-session-identity-123456" }, "Session identity changed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			receipt := valid
			test.mutate(&receipt)
			err := validateReceipt(receipt, claim, valid.SessionID, StateRunning)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, test.wantErr)
			}
		})
	}
}

func TestRunRequestRejectsUnsafeHostExecutablePaths(t *testing.T) {
	intent := testIntent(t)
	request, err := buildRequest(intent)
	if err != nil {
		t.Fatal(err)
	}
	request.Body.BlenderExecutable = `C:\Blender\blender.exe`
	request.Body.SessionBrokerExecutable = `C:\BlenderBox\bin\blendersessiond.exe`
	request.Body.BlenderExecutable = `..\replacement.exe`
	body, err := requestBodyHash(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	request.Claim.RequestHash = body
	if err := request.Validate(); err == nil || !strings.Contains(err.Error(), "unsafe Windows executable path") {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateReceiptComparesDeadlineByInstant(t *testing.T) {
	deadline := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	claim := LockClaim{
		SchemaVersion: 1,
		RunID:         "bbx_01TESTRUNIDENTITY0000000000",
		RequestID:     "req_01TESTREQUESTIDENTITY00000",
		ControllerID:  "controller-test",
		Deadline:      deadline,
		RequestHash:   strings.Repeat("0", 64),
		TaskName:      "BlenderBoxTest",
	}
	receipt := RunReceipt{
		SchemaVersion: 1,
		Claim:         claim,
		State:         StateRunning,
		SessionID:     "bss_exact-fake-session-identity-123456",
	}
	receipt.Claim.Deadline = deadline.In(time.FixedZone("equivalent-zero-offset", 0))
	if err := validateReceipt(receipt, claim, receipt.SessionID, StateRunning); err != nil {
		t.Fatalf("equivalent deadline rejected: %v", err)
	}
	receipt.Claim.Deadline = deadline.Add(time.Nanosecond)
	if err := validateReceipt(receipt, claim, receipt.SessionID, StateRunning); err == nil || !strings.Contains(err.Error(), "Host Lock claim changed") {
		t.Fatalf("changed deadline error = %v", err)
	}
}

type startErrorHost struct {
	fakeHost
	settledClaim LockClaim
}

type acquireErrorHost struct {
	fakeHost
	settledClaim LockClaim
}

func (host *acquireErrorHost) Acquire(_ context.Context, _ target.Target, claim LockClaim) error {
	host.receipt.Claim = claim
	return errors.New("response lost after lock creation")
}

func (host *acquireErrorHost) Settle(_ context.Context, _ target.Target, receipt RunReceipt) (CleanupState, error) {
	host.settledClaim = receipt.Claim
	return CleanupState{SessionStopped: true, PayloadRemoved: true, RunRootRemoved: true, LockReleased: true}, nil
}

func TestAcquireErrorAttemptsExactClaimOnlySettlement(t *testing.T) {
	host := &acquireErrorHost{fakeHost: fakeHost{evidence: testEvidence()}}
	intent := testIntent(t)
	_, err := New(host).Run(context.Background(), intent)
	if err == nil || !strings.Contains(err.Error(), "acquire Host Lock") {
		t.Fatalf("error = %v", err)
	}
	if host.settledClaim.RunID != intent.RunID || host.settledClaim.RequestID != intent.RequestID || host.settledClaim.RequestHash == "" {
		t.Fatalf("ambiguous acquisition lost cleanup authority: %+v", host.settledClaim)
	}
}

func (host *startErrorHost) Start(context.Context, target.Target, RunRequest) (RunReceipt, error) {
	return RunReceipt{}, errors.New("connection dropped")
}

func (host *startErrorHost) Settle(_ context.Context, _ target.Target, receipt RunReceipt) (CleanupState, error) {
	host.settledClaim = receipt.Claim
	return CleanupState{SessionStopped: true, PayloadRemoved: true, RunRootRemoved: true, LockReleased: true}, nil
}

func TestStartErrorPreservesClaimForSettlement(t *testing.T) {
	host := &startErrorHost{fakeHost: fakeHost{evidence: map[string][]byte{}}}
	intent := testIntent(t)
	_, err := New(host).Run(context.Background(), intent)
	if err == nil || !strings.Contains(err.Error(), "start Run") {
		t.Fatalf("error = %v", err)
	}
	if host.settledClaim.RunID != intent.RunID || host.settledClaim.RequestID != intent.RequestID || host.settledClaim.RequestHash == "" {
		t.Fatalf("settlement lost authority: %+v", host.settledClaim)
	}
}

func TestForgedPayloadFailsBeforeHostInspection(t *testing.T) {
	host := &fakeHost{evidence: testEvidence()}
	intent := testIntent(t)
	intent.Payload = payload.Payload{
		SchemaVersion: 1,
		Files: []payload.File{{
			Source:      "scenario.py",
			Destination: "scenario.py",
			Size:        1,
			SHA256:      strings.Repeat("0", 64),
		}},
		Scenario: payload.Scenario{Script: "scenario.py", ReadTimeoutSeconds: 180},
	}
	_, err := New(host).Run(context.Background(), intent)
	if err == nil || !strings.Contains(err.Error(), "invalid Run Payload") {
		t.Fatalf("error = %v", err)
	}
	if len(host.operations) != 0 {
		t.Fatalf("host operations = %v", host.operations)
	}
}

type malformedStartHost struct {
	startErrorHost
}

func (host *malformedStartHost) Start(ctx context.Context, target target.Target, request RunRequest) (RunReceipt, error) {
	receipt, err := host.fakeHost.Start(ctx, target, request)
	receipt.SessionID = ""
	return receipt, err
}

func TestStartMustReturnExactSessionIdentity(t *testing.T) {
	host := &malformedStartHost{startErrorHost: startErrorHost{fakeHost: fakeHost{evidence: testEvidence()}}}
	_, err := New(host).Run(context.Background(), testIntent(t))
	if err == nil || !strings.Contains(err.Error(), "start receipt: invalid Session identity") {
		t.Fatalf("error = %v", err)
	}
	if host.settledClaim.RunID == "" {
		t.Fatal("malformed Start receipt lost claim-only cleanup")
	}
}

type driftingSessionHost struct {
	fakeHost
}

func (host *driftingSessionHost) Observe(ctx context.Context, target target.Target, runID RunID) (RunReceipt, error) {
	receipt, err := host.fakeHost.Observe(ctx, target, runID)
	receipt.SessionID = "bss_other-valid-session-identity-123456"
	return receipt, err
}

func TestObserveCannotReplaceSessionIdentity(t *testing.T) {
	host := &driftingSessionHost{fakeHost: fakeHost{evidence: testEvidence()}}
	_, err := New(host).Run(context.Background(), testIntent(t))
	if err == nil || !strings.Contains(err.Error(), "Session identity changed") {
		t.Fatalf("error = %v", err)
	}
}

type blockingSettleHost struct {
	fakeHost
	settleCalls int
}

func (host *blockingSettleHost) Settle(ctx context.Context, _ target.Target, _ RunReceipt) (CleanupState, error) {
	host.settleCalls++
	<-ctx.Done()
	return CleanupState{}, ctx.Err()
}

func TestSettlementHasIndependentBoundedDeadline(t *testing.T) {
	host := &blockingSettleHost{fakeHost: fakeHost{evidence: testEvidence()}}
	runner := New(host)
	runner.settlementTimeout = 10 * time.Millisecond
	started := time.Now()
	_, err := runner.Run(context.Background(), testIntent(t))
	if err == nil || !strings.Contains(err.Error(), "settle Run") {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("settlement was not bounded: %s", elapsed)
	}
	if host.settleCalls != 2 {
		t.Fatalf("settle calls = %d, want fallback retry", host.settleCalls)
	}
}

type incompleteSettleHost struct {
	fakeHost
	settleCalls int
}

func (host *incompleteSettleHost) Settle(context.Context, target.Target, RunReceipt) (CleanupState, error) {
	host.settleCalls++
	if host.settleCalls == 1 {
		return CleanupState{SessionStopped: true}, nil
	}
	return CleanupState{SessionStopped: true, PayloadRemoved: true, RunRootRemoved: true, LockReleased: true}, nil
}

func TestIncompleteSettlementGetsFallbackRetry(t *testing.T) {
	host := &incompleteSettleHost{fakeHost: fakeHost{evidence: testEvidence()}}
	_, err := New(host).Run(context.Background(), testIntent(t))
	if err == nil || !strings.Contains(err.Error(), "cleanup state is not known") {
		t.Fatalf("error = %v", err)
	}
	if host.settleCalls != 2 {
		t.Fatalf("settle calls = %d, want 2", host.settleCalls)
	}
}

type duplicateEvidenceHost struct {
	fakeHost
	fetchCalls int
}

func (host *duplicateEvidenceHost) Observe(ctx context.Context, target target.Target, runID RunID) (RunReceipt, error) {
	receipt, err := host.fakeHost.Observe(ctx, target, runID)
	receipt.Evidence.Files = append(receipt.Evidence.Files, receipt.Evidence.Files[0])
	return receipt, err
}

func (host *duplicateEvidenceHost) Fetch(ctx context.Context, target target.Target, receipt RunReceipt, file EvidenceFile) ([]byte, error) {
	host.fetchCalls++
	return host.fakeHost.Fetch(ctx, target, receipt, file)
}

func TestDuplicateEvidencePathsFailBeforeFetch(t *testing.T) {
	host := &duplicateEvidenceHost{fakeHost: fakeHost{evidence: testEvidence()}}
	_, err := New(host).Run(context.Background(), testIntent(t))
	if err == nil || !strings.Contains(err.Error(), "duplicate path") {
		t.Fatalf("error = %v", err)
	}
	if host.fetchCalls != 0 {
		t.Fatalf("fetched %d files before rejecting manifest", host.fetchCalls)
	}
}

type unicodeCollisionEvidenceHost struct {
	duplicateEvidenceHost
}

func (host *unicodeCollisionEvidenceHost) Observe(ctx context.Context, target target.Target, runID RunID) (RunReceipt, error) {
	receipt, err := host.fakeHost.Observe(ctx, target, runID)
	collision := receipt.Evidence.Files[0]
	collision.Path = "ſcenario-result.json"
	receipt.Evidence.Files = append(receipt.Evidence.Files, collision)
	return receipt, err
}

func TestWindowsUnicodeEvidenceCollisionFailsBeforeFetch(t *testing.T) {
	host := &unicodeCollisionEvidenceHost{duplicateEvidenceHost: duplicateEvidenceHost{fakeHost: fakeHost{evidence: testEvidence()}}}
	_, err := New(host).Run(context.Background(), testIntent(t))
	if err == nil || !strings.Contains(err.Error(), "duplicate path") {
		t.Fatalf("error = %v", err)
	}
	if host.fetchCalls != 0 {
		t.Fatalf("fetched %d files before rejecting manifest", host.fetchCalls)
	}
}

func TestRunRejectsInvalidViewportBytes(t *testing.T) {
	host := &fakeHost{evidence: map[string][]byte{
		"scenario-result.json": []byte(`{"status":"pass"}`),
		"viewport.png":         []byte("not-a-png"),
	}}
	_, err := New(host).Run(context.Background(), testIntent(t))
	if err == nil || !strings.Contains(err.Error(), "PNG") {
		t.Fatalf("error = %v", err)
	}
}

func TestEvidenceManifestRejectsEmptyFiles(t *testing.T) {
	err := validateEvidenceFile(EvidenceFile{
		Path:   "result.json",
		Type:   "scenario-result",
		Size:   0,
		SHA256: strings.Repeat("0", 64),
	})
	if err == nil || !strings.Contains(err.Error(), "size") {
		t.Fatalf("error = %v", err)
	}
}

func TestEvidencePathsUseWindowsSafePortableGrammar(t *testing.T) {
	for _, path := range []string{"C:/temp/result.json", "CON.png", "nested/trailing. "} {
		t.Run(path, func(t *testing.T) {
			err := validateEvidenceFile(EvidenceFile{
				Path:   path,
				Type:   "scenario-result",
				Size:   0,
				SHA256: strings.Repeat("0", 64),
			})
			if err == nil || !strings.Contains(err.Error(), "unsafe") {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestEvidenceWriteRejectsSymlinkedParent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("creating an unprivileged symlink is not portable on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "nested")); err != nil {
		t.Fatal(err)
	}
	err := writeEvidence(root, "nested/result.json", []byte("evidence"))
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "result.json")); !os.IsNotExist(err) {
		t.Fatalf("evidence escaped configured root: %v", err)
	}
}

func TestEvidenceWriteDoesNotReplaceExistingFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "result.json")
	if err := os.WriteFile(path, []byte("prior evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeEvidence(root, "result.json", []byte("replacement")); err == nil || !strings.Contains(err.Error(), "exists") {
		t.Fatalf("error = %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "prior evidence" {
		t.Fatalf("existing evidence changed to %q", contents)
	}
}

func TestPrepareEvidenceRootCreatesExclusiveCanonicalRunDirectory(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "bbx_new-run")
	prepared, err := prepareEvidenceRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(prepared) {
		t.Fatalf("prepared root is not absolute: %q", prepared)
	}
	if _, err := prepareEvidenceRoot(root); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second prepare error = %v", err)
	}
}

type recoveryHost struct {
	fakeHost
}

func (host *recoveryHost) Observe(_ context.Context, _ target.Target, runID RunID) (RunReceipt, error) {
	host.operations = append(host.operations, "observe")
	return host.receipt, nil
}

func TestStatusAndStopRecoverAndSettleExactHostReceipt(t *testing.T) {
	claim := LockClaim{
		SchemaVersion: 1,
		RunID:         "bbx_01TESTRUNIDENTITY0000000000",
		RequestID:     "req_01TESTREQUESTIDENTITY00000",
		ControllerID:  "controller-test",
		Deadline:      time.Now().Add(time.Hour).UTC(),
		RequestHash:   strings.Repeat("a", 64),
		TaskName:      "BlenderBoxTest",
	}
	host := &recoveryHost{fakeHost: fakeHost{receipt: RunReceipt{
		SchemaVersion: 1,
		Claim:         claim,
		State:         StateRunning,
		SessionID:     "bss_exact-fake-session-identity-123456",
	}}}
	selected := target.Target{SchemaVersion: 1, TaskName: "BlenderBoxTest"}
	runner := New(host)

	status, err := runner.Status(context.Background(), selected, claim.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if status.RunID != claim.RunID || status.RequestID != claim.RequestID || status.RequestHash != claim.RequestHash || status.Deadline != claim.Deadline || status.SessionID != host.receipt.SessionID {
		t.Fatalf("status authority changed: %+v", status)
	}
	stopped, err := runner.Stop(context.Background(), selected, claim.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.RunID != claim.RunID || stopped.RequestID != claim.RequestID || stopped.SessionID != host.receipt.SessionID || !stopped.Cleanup.Known() {
		t.Fatalf("stop result changed authority: %+v", stopped)
	}
	wantOperations := []string{"observe", "observe", "settle"}
	if !reflect.DeepEqual(host.operations, wantOperations) {
		t.Fatalf("operations = %v, want %v", host.operations, wantOperations)
	}
}

func TestStatusRejectsReceiptForReplacementRun(t *testing.T) {
	requested := RunID("bbx_01TESTRUNIDENTITY0000000000")
	host := &recoveryHost{fakeHost: fakeHost{receipt: RunReceipt{
		SchemaVersion: 1,
		Claim: LockClaim{
			SchemaVersion: 1,
			RunID:         "bbx_01REPLACEMENTIDENTITY000000",
			RequestID:     "req_01TESTREQUESTIDENTITY00000",
			ControllerID:  "controller-test",
			Deadline:      time.Now().Add(time.Hour).UTC(),
			RequestHash:   strings.Repeat("a", 64),
			TaskName:      "BlenderBoxTest",
		},
		State:     StateRunning,
		SessionID: "bss_replacement-session-identity-123456",
	}}}
	_, err := New(host).Status(context.Background(), target.Target{TaskName: "BlenderBoxTest"}, requested)
	if err == nil || !strings.Contains(err.Error(), "Run ID changed") {
		t.Fatalf("error = %v", err)
	}
}

func TestStatusAllowsFailedReceiptBeforeSessionStart(t *testing.T) {
	claim := LockClaim{
		SchemaVersion: 1,
		RunID:         "bbx_01TESTRUNIDENTITY0000000000",
		RequestID:     "req_01TESTREQUESTIDENTITY00000",
		ControllerID:  "controller-test",
		Deadline:      time.Now().Add(time.Hour).UTC(),
		RequestHash:   strings.Repeat("a", 64),
		TaskName:      "BlenderBoxTest",
	}
	host := &recoveryHost{fakeHost: fakeHost{receipt: RunReceipt{
		SchemaVersion: 1,
		Claim:         claim,
		State:         StateFailed,
		Error:         "Session start failed",
	}}}
	status, err := New(host).Status(context.Background(), target.Target{TaskName: claim.TaskName}, claim.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateFailed || status.SessionID != "" {
		t.Fatalf("status = %+v", status)
	}
}

func TestStatusAllowsStartingReceiptBeforeSessionPublication(t *testing.T) {
	claim := LockClaim{
		SchemaVersion: 1,
		RunID:         "bbx_01TESTRUNIDENTITY0000000000",
		RequestID:     "req_01TESTREQUESTIDENTITY00000",
		ControllerID:  "controller-test",
		Deadline:      time.Now().Add(time.Hour).UTC(),
		RequestHash:   strings.Repeat("a", 64),
		TaskName:      "BlenderBoxTest",
	}
	host := &recoveryHost{fakeHost: fakeHost{receipt: RunReceipt{
		SchemaVersion: 1,
		Claim:         claim,
		State:         StateStarting,
	}}}
	status, err := New(host).Status(context.Background(), target.Target{TaskName: claim.TaskName}, claim.RunID)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != StateStarting || status.SessionID != "" {
		t.Fatalf("status = %+v", status)
	}
}

func testIntent(t *testing.T) RunIntent {
	t.Helper()
	return RunIntent{
		RunID:        "bbx_01TESTRUNIDENTITY0000000000",
		RequestID:    "req_01TESTREQUESTIDENTITY00000",
		ControllerID: "controller-test",
		Deadline:     time.Now().Add(time.Hour).UTC(),
		Target: target.Target{
			SchemaVersion: 1,
			SSHAlias:      "windows-test",
			TaskName:      "BlenderBoxTest",
		},
		Payload:     loadTestPayload(t),
		EvidenceDir: filepath.Join(t.TempDir(), "evidence"),
	}
}

func loadTestPayload(t *testing.T) payload.Payload {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "scenario.py"), []byte("print('slice 0')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	document := `{"schema_version":1,"files":[{"source":"scenario.py","destination":"scenario.py"}],"scenario":{"script":"scenario.py","read_timeout_seconds":600,"capture_viewport":true}}`
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

func testEvidence() map[string][]byte {
	return map[string][]byte{
		"scenario-result.json": []byte(`{"status":"pass"}`),
		"viewport.png":         testViewportPNG(),
	}
}

func testViewportPNG() []byte {
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 800, 600))); err != nil {
		panic(err)
	}
	return encoded.Bytes()
}

func evidenceFile(path string, kind string, content []byte) EvidenceFile {
	hash := sha256.Sum256(content)
	file := EvidenceFile{
		Path:   path,
		Type:   kind,
		Size:   int64(len(content)),
		SHA256: fmt.Sprintf("%x", hash),
	}
	if kind == "viewport" {
		file.CaptureMethod = "offscreen"
		file.Width = 800
		file.Height = 600
	}
	return file
}
