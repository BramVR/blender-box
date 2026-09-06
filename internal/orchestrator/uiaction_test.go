package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/uiaction"
)

func testUIBatch(t *testing.T) *uiaction.Batch {
	t.Helper()
	var b uiaction.Batch
	if err := json.Unmarshal([]byte(`{"schema_version":1,"timeout_seconds":10,"actions":[{"type":"text","text":"private value"}]}`), &b); err != nil {
		t.Fatal(err)
	}
	return &b
}
func TestUIPlanRedactsAndDoctorRejectsMissingCapability(t *testing.T) {
	intent := testIntent(t)
	intent.Payload.SchemaVersion = 3
	intent.Payload.Scenario.CaptureViewport = false
	intent.Payload.Scenario.CaptureBlenderWindow = true
	intent.Payload.Scenario.UIActions = testUIBatch(t)
	plan, err := New(nil, filepath.Join(t.TempDir(), "private")).Plan(PlanIntent{Target: intent.Target, Payload: intent.Payload})
	if err != nil {
		t.Fatal(err)
	}
	if plan.UIActions == nil || plan.UIActions.Count != 1 || len(plan.Captures) != 2 || plan.Captures[0].Path != uiaction.BeforePath || plan.Captures[1].Path != uiaction.AfterPath {
		t.Fatalf("plan %+v", plan)
	}
	if !slices.Equal(plan.ExpectedEvidence, []EvidenceType{EvidenceScenarioResult, EvidenceUIActions, EvidenceBlenderWindow}) {
		t.Fatalf("expected_evidence must list each type once, got %v", plan.ExpectedEvidence)
	}
	encoded, _ := json.Marshal(plan)
	if strings.Contains(string(encoded), "private value") {
		t.Fatal("plan leaked text")
	}
	result, err := New(&fakeHost{}, filepath.Join(t.TempDir(), "private")).Doctor(context.Background(), PlanIntent{Target: intent.Target, Payload: intent.Payload})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "fail" {
		t.Fatal("doctor accepted missing UI capability")
	}
	before, err := buildRequest(intent)
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(`{"schema_version":1,"timeout_seconds":10,"actions":[{"type":"text","text":"changed value"}]}`), intent.Payload.Scenario.UIActions)
	after, err := buildRequest(intent)
	if err != nil {
		t.Fatal(err)
	}
	if before.Claim.RequestHash == after.Claim.RequestHash {
		t.Fatal("batch missing from request hash")
	}
	intent.Payload.SchemaVersion = 2
	if intent.Payload.ValidateManifest() == nil {
		t.Fatal("schema2 accepted UI actions")
	}
}

type terminalUIHost struct {
	*fakeHost
	terminal RunReceipt
}

func (h *terminalUIHost) Observe(_ context.Context, _ target.Target, _ RunID) (RunReceipt, error) {
	h.operations = append(h.operations, "observe")
	if h.receipt.Cleanup.Known() {
		return h.receipt, nil
	}
	h.terminal.Claim = h.receipt.Claim
	h.receipt = h.terminal
	return h.terminal, nil
}
func TestFailedUIRunReturnsAvailableBundleBeforeCleanup(t *testing.T) {
	intent := testIntent(t)
	intent.Payload.SchemaVersion = 3
	intent.Payload.Scenario.CaptureViewport = false
	intent.Payload.Scenario.UIActions = testUIBatch(t)
	session := SessionID("bss_exact-fake-session-identity-123456")
	journal := &uiaction.Journal{SchemaVersion: 1, Receipts: []uiaction.Receipt{{Index: 0, Kind: uiaction.Text, SessionID: string(session), Outcome: uiaction.Uncertain, ErrorCode: "delivery-unknown"}}}
	content, _ := json.Marshal(journal)
	file := evidenceFile(uiaction.EvidencePath, EvidenceUIActions, content)
	file.SourcePath = "evidence/" + file.Path
	file.MediaType = "application/json"
	file.SessionID = session
	h := &terminalUIHost{fakeHost: &fakeHost{inspection: HostInspection{SchemaVersion: 1, Status: "pass", UIActions: &UIActionSupport{Capability: uiaction.Capability, Supported: true}}, evidence: map[string][]byte{uiaction.EvidencePath: content}}, terminal: RunReceipt{SchemaVersion: 1, SessionID: session, State: StateFailed, UIActions: journal, Evidence: EvidenceManifest{SchemaVersion: 3, Files: []EvidenceFile{file}}, Error: "UI action batch failed"}}
	result, err := New(h, filepath.Join(t.TempDir(), "private")).Run(context.Background(), intent)
	if err == nil {
		t.Fatal("failed run returned success")
	}
	if result.State != StateFailed || !result.Cleanup.Known() || result.UIActions == nil {
		t.Fatalf("result %+v", result)
	}
	if slices.Index(h.operations, "fetch:"+uiaction.EvidencePath) > slices.Index(h.operations, "settle") {
		t.Fatal("evidence fetched after destructive cleanup")
	}
	for _, path := range []string{uiaction.EvidencePath, "manifest.json", "evidence.json"} {
		bytes, err := os.ReadFile(filepath.Join(intent.EvidenceDir, path))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(bytes), "private value") {
			t.Fatal("failure bundle leaked text")
		}
	}
}
func TestUIJournalRejectsRewrittenQueuedPrefix(t *testing.T) {
	previous := &uiaction.Journal{SchemaVersion: 1, Receipts: []uiaction.Receipt{{Index: 0, Kind: uiaction.Key, SessionID: "exact", Outcome: uiaction.Queued, Window: &uiaction.Window{Width: 100, Height: 80}, EventCount: 2}}}
	next := &uiaction.Journal{SchemaVersion: 1, Receipts: append([]uiaction.Receipt(nil), previous.Receipts...)}
	next.Receipts[0].Outcome = uiaction.Pending
	if uiaction.ValidateProgress(previous, next) == nil {
		t.Fatal("queued action regressed to pending")
	}
	next.Receipts[0] = previous.Receipts[0]
	next.Receipts[0].EventCount = 4
	if uiaction.ValidateProgress(previous, next) == nil {
		t.Fatal("queued event count changed")
	}
}

type cancelledUIHost struct {
	*fakeHost
	cancel context.CancelFunc
}

func (h *cancelledUIHost) Start(ctx context.Context, selected target.Target, request RunRequest) (RunReceipt, error) {
	receipt, err := h.fakeHost.Start(ctx, selected, request)
	if err != nil {
		return receipt, err
	}
	receipt.State = StateInteracting
	content := []byte(`{"schema_version":1,"status":"pass"}`)
	file := evidenceFile("result/scenario-result.json", EvidenceScenarioResult, content)
	file.SourcePath = "evidence/" + file.Path
	file.MediaType = "application/json"
	file.SessionID = receipt.SessionID
	h.evidence = map[string][]byte{file.Path: content}
	receipt.Evidence = EvidenceManifest{SchemaVersion: 3, Files: []EvidenceFile{file}}
	receipt.UIActions = &uiaction.Journal{SchemaVersion: 1, Receipts: []uiaction.Receipt{{Index: 0, Kind: uiaction.Text, SessionID: string(receipt.SessionID), Outcome: uiaction.Pending}}}
	h.receipt = receipt
	h.cancel()
	return receipt, nil
}
func (h *cancelledUIHost) Observe(_ context.Context, _ target.Target, _ RunID) (RunReceipt, error) {
	return h.receipt, nil
}
func (h *cancelledUIHost) Settle(ctx context.Context, selected target.Target, receipt RunReceipt) (CleanupState, error) {
	cleanup, err := h.fakeHost.Settle(ctx, selected, receipt)
	if err != nil {
		return cleanup, err
	}
	h.receipt.State = StateFailed
	h.receipt.UIActions.MarkUncertain()
	content, _ := json.Marshal(h.receipt.UIActions)
	content = append(content, '\n')
	file := evidenceFile(uiaction.EvidencePath, EvidenceUIActions, content)
	file.SourcePath = "evidence/" + file.Path
	file.MediaType = "application/json"
	file.SessionID = receipt.SessionID
	h.receipt.Evidence = EvidenceManifest{SchemaVersion: 3, Files: []EvidenceFile{file}}
	return cleanup, nil
}
func TestCancelledUIRunRecoversTerminalJournalFromReceiptAfterCleanup(t *testing.T) {
	intent := testIntent(t)
	intent.Payload.SchemaVersion = 3
	intent.Payload.Scenario.CaptureViewport = false
	intent.Payload.Scenario.UIActions = testUIBatch(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	host := &cancelledUIHost{fakeHost: &fakeHost{inspection: HostInspection{SchemaVersion: 1, Status: "pass", UIActions: &UIActionSupport{Capability: uiaction.Capability, Supported: true}}}, cancel: cancel}
	result, err := New(host, filepath.Join(t.TempDir(), "private")).Run(ctx, intent)
	if err == nil {
		t.Fatal("cancelled Run succeeded")
	}
	if !result.Cleanup.Known() || !result.UIJournalRecoveredFromReceipt || result.UIActions.Receipts[0].Outcome != uiaction.Uncertain {
		t.Fatalf("result %+v error %v", result, err)
	}
	content, err := os.ReadFile(filepath.Join(intent.EvidenceDir, uiaction.EvidencePath))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "delivery-unknown") || strings.Contains(string(content), "private value") {
		t.Fatalf("journal %s", content)
	}
}

func TestSchemaThreeWithoutBatchFailsBeforeHostContact(t *testing.T) {
	intent := testIntent(t)
	intent.Payload.SchemaVersion = 3
	host := &fakeHost{}
	runner := New(host, filepath.Join(t.TempDir(), "private"))
	planIntent := PlanIntent{Target: intent.Target, Payload: intent.Payload}
	if _, err := runner.Plan(planIntent); err == nil {
		t.Fatal("plan accepted schema3 without a batch")
	}
	if _, err := runner.Doctor(context.Background(), planIntent); err == nil {
		t.Fatal("doctor accepted schema3 without a batch")
	}
	if _, err := runner.Run(context.Background(), intent); err == nil || !IsPreflightError(err) {
		t.Fatalf("Run must fail preflight, got %v", err)
	}
	if len(host.operations) != 0 {
		t.Fatalf("invalid payload contacted host: %v", host.operations)
	}
	if _, err := os.Stat(intent.EvidenceDir); !os.IsNotExist(err) {
		t.Fatalf("invalid payload created evidence root: %v", err)
	}
	if _, err := os.Stat(runner.journal.root); !os.IsNotExist(err) {
		t.Fatalf("invalid UI payload created authority storage: %v", err)
	}
	for _, version := range []int{1, 2} {
		intent.Payload.SchemaVersion = version
		if err := intent.Payload.ValidateManifest(); err != nil {
			t.Fatalf("schema%d without batch regressed: %v", version, err)
		}
	}
}

func TestUIPreparationFailurePreservesReasonWithoutManifest(t *testing.T) {
	intent := testIntent(t)
	intent.Payload.SchemaVersion = 3
	intent.Payload.Scenario.UIActions = testUIBatch(t)
	host := &terminalUIHost{fakeHost: &fakeHost{inspection: HostInspection{SchemaVersion: 1, Status: "pass", Captures: []CaptureSupport{{Kind: "viewport", Capability: "capture-viewport-v1", Supported: true}}, UIActions: &UIActionSupport{Capability: uiaction.Capability, Supported: true}}}, terminal: RunReceipt{SchemaVersion: 1, SessionID: "bss_exact-fake-session-identity-123456", State: StateFailed, Error: "Scenario call failed"}}
	result, err := New(host, filepath.Join(t.TempDir(), "private")).Run(context.Background(), intent)
	if err == nil || !strings.Contains(err.Error(), "Scenario call failed") || strings.Contains(err.Error(), "evidence schema") {
		t.Fatalf("error %v", err)
	}
	if result.Error != "Scenario call failed" || result.UIActions != nil || !result.Cleanup.Known() {
		t.Fatalf("result %+v", result)
	}
	settlements := 0
	for _, operation := range host.operations {
		if strings.HasPrefix(operation, "fetch:") {
			t.Fatalf("collected absent evidence: %v", host.operations)
		}
		if operation == "settle" {
			settlements++
		}
	}
	if settlements != 1 {
		t.Fatalf("settled %d times", settlements)
	}
	if _, err := os.Stat(filepath.Join(intent.EvidenceDir, "evidence.json")); err != nil {
		t.Fatal(err)
	}
}
func TestUIEvidenceCollectionErrorKeepsTerminalRunReason(t *testing.T) {
	intent := testIntent(t)
	intent.Payload.SchemaVersion = 3
	intent.Payload.Scenario.CaptureViewport = false
	intent.Payload.Scenario.UIActions = testUIBatch(t)
	session := SessionID("bss_exact-fake-session-identity-123456")
	file := evidenceFile("result/scenario-result.json", EvidenceScenarioResult, []byte(`{"schema_version":1,"status":"pass"}`))
	file.SourcePath = "evidence/" + file.Path
	file.MediaType = "application/json"
	file.SessionID = session
	host := &terminalUIHost{fakeHost: &fakeHost{inspection: HostInspection{SchemaVersion: 1, Status: "pass", UIActions: &UIActionSupport{Capability: uiaction.Capability, Supported: true}}, evidence: map[string][]byte{file.Path: []byte("truncated")}}, terminal: RunReceipt{SchemaVersion: 1, SessionID: session, State: StateFailed, Error: "UI action batch failed", Evidence: EvidenceManifest{SchemaVersion: 3, Files: []EvidenceFile{file}}}}
	_, err := New(host, filepath.Join(t.TempDir(), "private")).Run(context.Background(), intent)
	if err == nil || !strings.Contains(err.Error(), "UI action batch failed") || !strings.Contains(err.Error(), "size changed") {
		t.Fatalf("error %v", err)
	}
}

type settlementJournalUIHost struct{ *terminalUIHost }

func (h *settlementJournalUIHost) Settle(ctx context.Context, selected target.Target, receipt RunReceipt) (CleanupState, error) {
	cleanup, err := h.fakeHost.Settle(ctx, selected, receipt)
	if err != nil {
		return cleanup, err
	}
	var content bytes.Buffer
	_ = json.NewEncoder(&content).Encode(h.receipt.UIActions)
	file := evidenceFile(uiaction.EvidencePath, EvidenceUIActions, content.Bytes())
	file.SourcePath = "evidence/" + file.Path
	file.MediaType = "application/json"
	file.SessionID = receipt.SessionID
	h.receipt.Evidence.Files = append(h.receipt.Evidence.Files, file)
	return cleanup, nil
}
func TestFailedUIRunRecoversJournalPublishedOnlyDuringSettlement(t *testing.T) {
	intent := testIntent(t)
	intent.Payload.SchemaVersion = 3
	intent.Payload.Scenario.CaptureViewport = false
	intent.Payload.Scenario.UIActions = testUIBatch(t)
	session := SessionID("bss_exact-fake-session-identity-123456")
	journal := &uiaction.Journal{SchemaVersion: 1, Receipts: []uiaction.Receipt{{Index: 0, Kind: uiaction.Text, SessionID: string(session), Outcome: uiaction.Uncertain, ErrorCode: "delivery-unknown"}}}
	scenario := []byte(`{"schema_version":1,"status":"pass"}`)
	scenarioFile := evidenceFile("result/scenario-result.json", EvidenceScenarioResult, scenario)
	scenarioFile.SourcePath = "evidence/" + scenarioFile.Path
	scenarioFile.MediaType = "application/json"
	scenarioFile.SessionID = session
	h := &settlementJournalUIHost{terminalUIHost: &terminalUIHost{
		fakeHost: &fakeHost{evidence: map[string][]byte{scenarioFile.Path: scenario}, inspection: HostInspection{SchemaVersion: 1, Status: "pass", UIActions: &UIActionSupport{Capability: uiaction.Capability, Supported: true}}},
		terminal: RunReceipt{SchemaVersion: 1, SessionID: session, State: StateFailed, Error: "UI action batch failed", UIActions: journal, Evidence: EvidenceManifest{SchemaVersion: 3, Files: []EvidenceFile{scenarioFile}}}}}
	result, err := New(h, filepath.Join(t.TempDir(), "private")).Run(context.Background(), intent)
	if err == nil || !strings.Contains(err.Error(), "UI action batch failed") || result.Error != "UI action batch failed" {
		t.Fatalf("result %+v error %v", result, err)
	}
	if !result.Cleanup.Known() || !result.UIJournalRecoveredFromReceipt {
		t.Fatalf("journal recovery missing: %+v", result)
	}
	var canonical bytes.Buffer
	_ = json.NewEncoder(&canonical).Encode(journal)
	content, err := os.ReadFile(filepath.Join(intent.EvidenceDir, uiaction.EvidencePath))
	if err != nil || !bytes.Equal(content, canonical.Bytes()) {
		t.Fatalf("canonical journal differs: %q %v", content, err)
	}
	expected := evidenceFile(uiaction.EvidencePath, EvidenceUIActions, canonical.Bytes())
	if len(result.Evidence.Files) != 2 || result.Evidence.Files[1].SHA256 != expected.SHA256 || result.Evidence.Files[1].Size != expected.Size {
		t.Fatalf("evidence %+v", result.Evidence)
	}
	if slices.Contains(h.operations, "fetch:"+uiaction.EvidencePath) {
		t.Fatalf("journal was fetched after cleanup: %v", h.operations)
	}
}

func TestUIRecoveryRejectsChangedTargetBeforeContact(t *testing.T) {
	intent := testIntent(t)
	intent.Payload.SchemaVersion = 3
	intent.Payload.Scenario.CaptureViewport = false
	intent.Payload.Scenario.UIActions = testUIBatch(t)
	request, err := buildRequest(intent)
	if err != nil {
		t.Fatal(err)
	}
	host := &fakeHost{}
	runner := recoveryRunner(t, host, request.Claim)
	changed, err := target.NewWindows("replacement", intent.Target.Windows())
	if err != nil {
		t.Fatal(err)
	}
	intent.Target = changed
	_, settled, err := runner.recoverUIFailure(context.Background(), intent, &RunReceipt{Claim: request.Claim}, t.TempDir())
	if !IsAuthorityError(err) || settled || len(host.operations) != 0 {
		t.Fatalf("changed target recovery err=%v settled=%v effects=%v", err, settled, host.operations)
	}
}

func TestUIRecoveryRetainsPinPublishedDuringFailedObservation(t *testing.T) {
	intent := testIntent(t)
	request, err := buildRequest(intent)
	if err != nil {
		t.Fatal(err)
	}
	host := &recoveryAuthorityHost{}
	runner := recoveryRunner(t, host, request.Claim)
	pinned := RunReceipt{SchemaVersion: 1, Claim: request.Claim, State: StateRunning, SessionID: "bss_concurrent-trusted-session-123456"}
	observeErr := errors.New("Observe transport failed")
	host.observe = func() (RunReceipt, error) {
		if err := runner.journal.accept(intent.Target, pinned); err != nil {
			t.Fatal(err)
		}
		return RunReceipt{SessionID: "untrusted-partial"}, observeErr
	}
	previous := RunReceipt{Claim: request.Claim}
	_, settled, err := runner.recoverUIFailure(context.Background(), intent, &previous, t.TempDir())
	if !errors.Is(err, observeErr) || IsAuthorityError(err) || settled || previous.SessionID != pinned.SessionID {
		t.Fatalf("UI fallback discarded trusted concurrent authority or trusted partial receipt: %+v %v", previous, err)
	}
}

func TestEvidenceCollectionRequiresOriginalAuthorityBeforeFetch(t *testing.T) {
	intent := testIntent(t)
	intent.Payload.SchemaVersion = 3
	intent.Payload.Scenario.CaptureViewport = false
	intent.Payload.Scenario.UIActions = testUIBatch(t)
	request, err := buildRequest(intent)
	if err != nil {
		t.Fatal(err)
	}
	session := SessionID("bss_exact-fake-session-identity-123456")
	content := []byte(`{"status":"pass"}`)
	file := evidenceFileV2("result/scenario-result.json", EvidenceScenarioResult, content, "application/json", "", 0, 0, session)
	receipt := RunReceipt{SchemaVersion: 1, Claim: request.Claim, SessionID: session, State: StateFailed, Evidence: EvidenceManifest{SchemaVersion: 3, Files: []EvidenceFile{file}}}
	for _, mode := range []string{"missing", "changed-target", "changed-session"} {
		t.Run(mode, func(t *testing.T) {
			host := &fakeHost{evidence: map[string][]byte{file.Path: content}}
			runner := New(host, filepath.Join(t.TempDir(), "private"))
			selected := intent
			if mode != "missing" {
				if err := runner.journal.record(intent.Target, request.Claim); err != nil {
					t.Fatal(err)
				}
				pinned := receipt
				if mode == "changed-session" {
					pinned.SessionID = "bss_original-pinned-session-123456"
				}
				if err := runner.journal.accept(intent.Target, pinned); err != nil {
					t.Fatal(err)
				}
				if mode == "changed-target" {
					selected.Target, err = target.NewWindows("replacement", intent.Target.Windows())
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			destination := t.TempDir()
			err := runner.collectEvidence(context.Background(), selected, receipt, destination)
			if !IsAuthorityError(err) || len(host.operations) != 0 {
				t.Fatalf("err=%v effects=%v", err, host.operations)
			}
			if _, err := os.Stat(filepath.Join(destination, file.Path)); !os.IsNotExist(err) {
				t.Fatalf("evidence written without authority: %v", err)
			}
		})
	}
}

type replacedRecoveryUIHost struct {
	*cancelledUIHost
	replacement string
}

func (h *replacedRecoveryUIHost) Observe(_ context.Context, _ target.Target, _ RunID) (RunReceipt, error) {
	h.operations = append(h.operations, "observe-replacement")
	receipt := RunReceipt{SchemaVersion: 1, Claim: h.receipt.Claim, State: StateFailed, SessionID: h.receipt.SessionID}
	if h.replacement == "claim" {
		receipt.Claim.ControllerID = "replacement-controller"
	} else if h.replacement == "erased-session" {
		receipt = h.receipt
		receipt.SessionID = ""
	} else {
		receipt.SessionID = "bss_replacement-session-identity-123456"
	}
	return receipt, nil
}

func TestCancelledUIRecoveryDoesNotSettleAfterAuthorityReplacement(t *testing.T) {
	for _, replacement := range []string{"claim", "session", "erased-session"} {
		t.Run(replacement, func(t *testing.T) {
			intent := testIntent(t)
			intent.Payload.SchemaVersion = 3
			intent.Payload.Scenario.CaptureViewport = false
			intent.Payload.Scenario.UIActions = testUIBatch(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			host := &replacedRecoveryUIHost{cancelledUIHost: &cancelledUIHost{fakeHost: &fakeHost{inspection: HostInspection{SchemaVersion: 1, Status: "pass", UIActions: &UIActionSupport{Capability: uiaction.Capability, Supported: true}}}, cancel: cancel}, replacement: replacement}
			runner := New(host, filepath.Join(t.TempDir(), "private"))
			_, err := runner.Run(ctx, intent)
			if !IsAuthorityError(err) {
				t.Fatalf("replacement authority error lost: %v", err)
			}
			for _, operation := range host.operations {
				if operation == "settle" || strings.HasPrefix(operation, "fetch:") {
					t.Fatalf("replacement recovery caused effects: %v", host.operations)
				}
			}
			record, pin, err := runner.journal.load(intent.Target, intent.RunID)
			if err != nil || !record.Claim.Equal(host.receipt.Claim) || pin != host.receipt.SessionID {
				t.Fatalf("original claim/pin changed: %+v %q %v", record, pin, err)
			}
		})
	}
}

type corruptAuthorityFetchHost struct {
	*fakeHost
	claimFile string
}

func (h *corruptAuthorityFetchHost) Fetch(ctx context.Context, selected target.Target, receipt RunReceipt, file EvidenceFile) ([]byte, error) {
	content, err := h.fakeHost.Fetch(ctx, selected, receipt, file)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(h.claimFile, []byte(`{}`), 0o600); err != nil {
		return nil, err
	}
	return content, nil
}

func TestEvidenceAuthorityLossDuringFetchPreventsPublicationAndCleanup(t *testing.T) {
	intent := testIntent(t)
	host := &corruptAuthorityFetchHost{fakeHost: &fakeHost{evidence: testEvidence()}}
	runner := New(host, filepath.Join(t.TempDir(), "private"))
	host.claimFile = filepath.Join(runner.journal.root, claimPath(intent.RunID))
	_, err := runner.Run(context.Background(), intent)
	if !IsAuthorityError(err) {
		t.Fatalf("authority loss error=%v", err)
	}
	if slices.Contains(host.operations, "settle") {
		t.Fatalf("cleanup after authority loss: %v", host.operations)
	}
	entries, err := os.ReadDir(intent.EvidenceDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("published evidence after authority loss: %v %v", entries, err)
	}
}

type lostPinUIHost struct {
	*cancelledUIHost
	pinFile      string
	loseAt       string
	observations int
}

func (host *lostPinUIHost) Observe(ctx context.Context, selected target.Target, runID RunID) (RunReceipt, error) {
	host.observations++
	receipt, err := host.cancelledUIHost.Observe(ctx, selected, runID)
	if err == nil && receipt.Cleanup.Known() && host.loseAt == "observe" {
		err = os.Remove(host.pinFile)
	}
	return receipt, err
}
func (host *lostPinUIHost) Settle(ctx context.Context, selected target.Target, receipt RunReceipt) (CleanupState, error) {
	cleanup, err := host.cancelledUIHost.Settle(ctx, selected, receipt)
	if err == nil && host.loseAt == "settle" {
		err = os.Remove(host.pinFile)
	}
	return cleanup, err
}
func TestUIJournalReconstructionRequiresRetainedSessionPin(t *testing.T) {
	for _, boundary := range []string{"observe", "settle"} {
		t.Run(boundary, func(t *testing.T) {
			intent := testIntent(t)
			intent.Payload.SchemaVersion = 3
			intent.Payload.Scenario.CaptureViewport = false
			intent.Payload.Scenario.UIActions = testUIBatch(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			root := filepath.Join(t.TempDir(), "private")
			host := &lostPinUIHost{cancelledUIHost: &cancelledUIHost{fakeHost: &fakeHost{inspection: HostInspection{SchemaVersion: 1, Status: "pass", UIActions: &UIActionSupport{Capability: uiaction.Capability, Supported: true}}}, cancel: cancel}, pinFile: filepath.Join(root, pinPath(intent.RunID)), loseAt: boundary}
			result, err := New(host, root).Run(ctx, intent)
			if !IsAuthorityError(err) || result.UIJournalRecoveredFromReceipt {
				t.Fatalf("lost UI pin result=%+v err=%v", result, err)
			}
			if _, err := os.Stat(host.pinFile); !os.IsNotExist(err) {
				t.Fatalf("UI recovery recreated pin: %v", err)
			}
			for _, path := range []string{uiaction.EvidencePath, "evidence.json"} {
				if _, err := os.Stat(filepath.Join(intent.EvidenceDir, path)); !os.IsNotExist(err) {
					t.Fatalf("UI publication after pin loss %s: %v", path, err)
				}
			}
			wantObservations := 2
			if boundary == "settle" {
				wantObservations = 1
			}
			if host.observations != wantObservations {
				t.Fatalf("UI observe after known pin loss: %d", host.observations)
			}
		})
	}
}
