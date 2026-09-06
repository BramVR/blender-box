package host

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/payload"
	"github.com/BramVR/blender-box/internal/uiaction"
)

type fakeUIActor struct {
	checkErr error
	calls    []AuthorizedAction
	perform  func(context.Context, AuthorizedAction) (uiaction.Receipt, error)
}

func (a *fakeUIActor) CheckUI(context.Context, string, string) error { return a.checkErr }
func (a *fakeUIActor) Perform(ctx context.Context, r AuthorizedAction) (uiaction.Receipt, error) {
	a.calls = append(a.calls, r)
	if a.perform != nil {
		return a.perform(ctx, r)
	}
	return uiaction.Receipt{Index: r.Index, Kind: r.Action.Kind(), SessionID: string(r.SessionID), Outcome: uiaction.Queued, Window: &uiaction.Window{Width: 1920, Height: 1080}, EventCount: r.Action.EventCount()}, nil
}
func uiTestBatch(t *testing.T) *uiaction.Batch {
	t.Helper()
	var b uiaction.Batch
	if err := json.Unmarshal([]byte(`{"schema_version":1,"timeout_seconds":30,"actions":[{"type":"key","key":"F2"},{"type":"text","text":"private value"},{"type":"key","key":"ENTER"}]}`), &b); err != nil {
		t.Fatal(err)
	}
	return &b
}
func TestUIBatchPersistsPendingBeforeInputAndReturnsBoundedEvidence(t *testing.T) {
	root := t.TempDir()
	now := time.Now().UTC()
	actor := &fakeUIActor{}
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon, UIActor: actor})
	request := stageHostScenarioTestRun(t, service, root, now, 3, payload.Scenario{Script: "scenario.py", ReadTimeoutSeconds: 180, CaptureBlenderWindow: true, UIActions: uiTestBatch(t)})
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	actor.perform = func(ctx context.Context, r AuthorizedAction) (uiaction.Receipt, error) {
		saved, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
		if err != nil {
			t.Fatal(err)
		}
		if !saved.Claim.Equal(request.Claim) || saved.SessionID != r.SessionID || saved.UIActions == nil || saved.UIActions.Receipts[r.Index].Outcome != uiaction.Pending {
			t.Fatal("input preceded durable pending identity")
		}
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > uiaction.MaxActionSeconds*time.Second {
			t.Fatal("unbounded action")
		}
		return uiaction.Receipt{Index: r.Index, Kind: r.Action.Kind(), SessionID: string(r.SessionID), Outcome: uiaction.Queued, Window: &uiaction.Window{Width: 1920, Height: 1080}, EventCount: r.Action.EventCount()}, nil
	}
	if err := service.ExecutePending(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if len(actor.calls) != 3 || !daemon.starts[0].EnableUIEvents || receipt.State != orchestrator.StateComplete || len(receipt.Evidence.Files) != 4 {
		t.Fatalf("calls=%d receipt=%+v", len(actor.calls), receipt)
	}
	for _, file := range receipt.Evidence.Files {
		contents, err := service.Fetch(root, FetchRequest{SchemaVersion: 1, Receipt: receipt, File: file})
		if err != nil {
			t.Fatal(err)
		}
		if file.Type == orchestrator.EvidenceUIActions && strings.Contains(string(contents), "private value") {
			t.Fatal("journal leaked text")
		}
	}
	if receipt.Evidence.Files[1].Path != uiaction.BeforePath || receipt.Evidence.Files[3].Path != uiaction.AfterPath {
		t.Fatalf("capture order %v", receipt.Evidence.Files)
	}
	cleanup, err := service.Settle(context.Background(), root, settleHostRequest(receipt))
	if err != nil || !cleanup.Known() {
		t.Fatalf("cleanup %+v %v", cleanup, err)
	}
}
func TestUIFailureStopsBatchAndPreservesJournal(t *testing.T) {
	for _, outcome := range []uiaction.Outcome{uiaction.Rejected, uiaction.Uncertain} {
		t.Run(string(outcome), func(t *testing.T) {
			root := t.TempDir()
			actor := &fakeUIActor{}
			service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: &fakeDaemon{}, UIActor: actor})
			request := stageHostScenarioTestRun(t, service, root, time.Now(), 3, payload.Scenario{Script: "scenario.py", ReadTimeoutSeconds: 180, UIActions: uiTestBatch(t)})
			if _, err := service.Start(context.Background(), root, request); err != nil {
				t.Fatal(err)
			}
			actor.perform = func(_ context.Context, r AuthorizedAction) (uiaction.Receipt, error) {
				if outcome == uiaction.Uncertain {
					return uiaction.Receipt{}, errors.New("private value in daemon error")
				}
				return uiaction.Receipt{Index: r.Index, Kind: r.Action.Kind(), SessionID: string(r.SessionID), Outcome: outcome, ErrorCode: "focus-lost"}, nil
			}
			err := service.ExecutePending(context.Background(), root)
			if err == nil || strings.Contains(err.Error(), "private value") {
				t.Fatalf("error %v", err)
			}
			receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
			if err != nil {
				t.Fatal(err)
			}
			if len(actor.calls) != 1 || receipt.UIActions.Receipts[0].Outcome != outcome || len(receipt.Evidence.Files) != 2 {
				t.Fatalf("receipt %+v", receipt)
			}
			if err := service.ExecutePending(context.Background(), root); err == nil {
				t.Fatal("replayed failed batch")
			}
			if len(actor.calls) != 1 {
				t.Fatal("replayed input")
			}
			if _, err := os.Stat(filepath.Join(runPath(root, request.Claim.RunID), "evidence", uiaction.EvidencePath)); err != nil {
				t.Fatal("missing failure journal", err)
			}
		})
	}
}
func TestRestartMakesPendingUIActionUncertain(t *testing.T) {
	root := t.TempDir()
	actor := &fakeUIActor{}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: &fakeDaemon{}, UIActor: actor})
	request := stageHostScenarioTestRun(t, service, root, time.Now(), 3, payload.Scenario{Script: "scenario.py", ReadTimeoutSeconds: 180, UIActions: uiTestBatch(t)})
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	session := orchestrator.SessionID("bss_exact-crashed-session-identity-123456")
	lock := lockRecord{SchemaVersion: 1, Claim: request.Claim, SessionID: session}
	if err := writeLockAtomic(lockPath(root), lock); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runPath(root, request.Claim.RunID), "evidence", "result"), 0o700); err != nil {
		t.Fatal(err)
	}
	receipt := orchestrator.RunReceipt{SchemaVersion: 1, Claim: request.Claim, SessionID: session, State: orchestrator.StateInteracting, UIActions: &uiaction.Journal{SchemaVersion: 1, Receipts: []uiaction.Receipt{{Index: 0, Kind: uiaction.Key, SessionID: string(session), Outcome: uiaction.Pending}}}}
	if err := service.writeReceipt(root, receipt); err != nil {
		t.Fatal(err)
	}
	if err := service.ExecutePending(context.Background(), root); err == nil {
		t.Fatal("resumed pending input")
	}
	got, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if len(actor.calls) != 0 || got.UIActions.Receipts[0].Outcome != uiaction.Uncertain || got.State != orchestrator.StateFailed || len(got.Evidence.Files) != 1 {
		t.Fatalf("receipt %+v", got)
	}
}
func TestCapabilitiesFailClosedWithoutUIActor(t *testing.T) {
	request := CapabilitiesRequest{SchemaVersion: 1, UIActions: true, BlenderExecutable: `C:\Program Files\Blender\blender.exe`, SessionBrokerExecutable: `C:\Test\blendersessiond.exe`}
	for _, actor := range []*fakeUIActor{nil, {checkErr: errors.New("old daemon")}, {}} {
		service := NewService(Dependencies{})
		if actor != nil {
			service.uiActor = actor
		}
		got, err := service.Capabilities(context.Background(), request)
		if err != nil {
			t.Fatal(err)
		}
		want := actor != nil && actor.checkErr == nil
		if got.UIActions == nil || got.UIActions.Capability != uiaction.Capability || got.UIActions.Supported != want {
			t.Fatalf("capabilities %+v", got)
		}
	}
}

func TestUIActionDeadlinesKeepTypedCauseAndRedactedReceipt(t *testing.T) {
	for _, variant := range []string{"typed", "backend-rejected", "backend-uncertain"} {
		t.Run(variant, func(t *testing.T) {
			root := t.TempDir()
			actor := &fakeUIActor{}
			service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: &fakeDaemon{}, UIActor: actor})
			request := stageHostScenarioTestRun(t, service, root, time.Now(), 3, payload.Scenario{Script: "scenario.py", ReadTimeoutSeconds: 180, UIActions: uiTestBatch(t)})
			if _, err := service.Start(context.Background(), root, request); err != nil {
				t.Fatal(err)
			}
			actor.perform = func(_ context.Context, r AuthorizedAction) (uiaction.Receipt, error) {
				if variant == "typed" {
					return uiaction.Receipt{}, fmt.Errorf("private value: %w", context.DeadlineExceeded)
				}
				outcome := uiaction.Rejected
				if variant == "backend-uncertain" {
					outcome = uiaction.Uncertain
				}
				return uiaction.Receipt{Index: r.Index, Kind: r.Action.Kind(), SessionID: string(r.SessionID), Outcome: outcome, ErrorCode: "timed-out"}, nil
			}
			err := service.ExecutePending(context.Background(), root)
			if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "private value") {
				t.Fatalf("error %v", err)
			}
			receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
			if err != nil {
				t.Fatal(err)
			}
			if receipt.State != orchestrator.StateTimedOut || len(actor.calls) != 1 || receipt.UIActions.Receipts[0].ErrorCode != "timed-out" {
				t.Fatalf("receipt %+v", receipt)
			}
		})
	}
}

type captureDeadlineDaemon struct{ fakeDaemon }

func (d *captureDeadlineDaemon) Call(ctx context.Context, r DaemonCall) (json.RawMessage, error) {
	if strings.Contains(string(r.Parameters), "bpy.ops.screen.screenshot") {
		return nil, fmt.Errorf("private value: %w", context.DeadlineExceeded)
	}
	return d.fakeDaemon.Call(ctx, r)
}
func TestUIBeforeCaptureDeadlineTerminalizesWithoutInput(t *testing.T) {
	root := t.TempDir()
	actor := &fakeUIActor{}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: &captureDeadlineDaemon{}, UIActor: actor})
	request := stageHostScenarioTestRun(t, service, root, time.Now(), 3, payload.Scenario{Script: "scenario.py", ReadTimeoutSeconds: 180, CaptureBlenderWindow: true, UIActions: uiTestBatch(t)})
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	err := service.ExecutePending(context.Background(), root)
	if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "private value") {
		t.Fatalf("error %v", err)
	}
	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != orchestrator.StateTimedOut || receipt.UIActions == nil || len(receipt.UIActions.Receipts) != 0 || len(actor.calls) != 0 || len(receipt.Evidence.Files) != 2 {
		t.Fatalf("receipt %+v", receipt)
	}
}

func stagePendingUIReceipt(t *testing.T, service *Service, root string) (orchestrator.RunRequest, orchestrator.RunReceipt) {
	t.Helper()
	request := stageHostScenarioTestRun(t, service, root, time.Now(), 3, payload.Scenario{Script: "scenario.py", ReadTimeoutSeconds: 180, UIActions: uiTestBatch(t)})
	if _, err := service.Start(context.Background(), root, request); err != nil {
		t.Fatal(err)
	}
	session := orchestrator.SessionID("bss_exact-pending-ui-session-identity-123456")
	if err := writeLockAtomic(lockPath(root), lockRecord{SchemaVersion: 1, Claim: request.Claim, SessionID: session}); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(runPath(root, request.Claim.RunID), "evidence", "result"), 0o700); err != nil {
		t.Fatal(err)
	}
	receipt := orchestrator.RunReceipt{SchemaVersion: 1, Claim: request.Claim, SessionID: session, State: orchestrator.StateInteracting, UIActions: &uiaction.Journal{SchemaVersion: 1, Receipts: []uiaction.Receipt{{Index: 0, Kind: uiaction.Key, SessionID: string(session), Outcome: uiaction.Pending}}}}
	if err := service.writeReceipt(root, receipt); err != nil {
		t.Fatal(err)
	}
	return request, receipt
}
func TestExpiredUIBatchReconcilesWithFreshContext(t *testing.T) {
	root := t.TempDir()
	actor := &fakeUIActor{}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: &fakeDaemon{}, UIActor: actor})
	request, receipt := stagePendingUIReceipt(t, service, root)
	expired, cancel := context.WithDeadline(context.Background(), time.Unix(0, 0))
	defer cancel()
	release, _, err := service.resumeActiveExecution(expired, expired, root, request, receipt.SessionID, "UI action admission")
	if release != nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reconciliation error %v", err)
	}
	saved, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if saved.State != orchestrator.StateTimedOut || saved.UIActions.Receipts[0].Outcome != uiaction.Uncertain || len(saved.Evidence.Files) != 1 || len(actor.calls) != 0 {
		t.Fatalf("receipt %+v", saved)
	}
	if _, err := os.Stat(filepath.Join(runPath(root, request.Claim.RunID), "evidence", uiaction.EvidencePath)); err != nil {
		t.Fatal(err)
	}
}
func TestSettleStopsExactSessionBeforeJournalPublicationFailure(t *testing.T) {
	root := t.TempDir()
	daemon := &fakeDaemon{}
	service := NewService(Dependencies{Tasks: &fakeTaskLauncher{}, Daemon: daemon})
	request, receipt := stagePendingUIReceipt(t, service, root)
	blockedPath := filepath.Join(runPath(root, request.Claim.RunID), "evidence", uiaction.EvidencePath)
	if err := os.Mkdir(blockedPath, 0o700); err != nil {
		t.Fatal(err)
	}
	cleanup, err := service.Settle(context.Background(), root, settleHostRequest(receipt))
	if err == nil || !cleanup.SessionStopped || cleanup.RunRootRemoved || cleanup.LockReleased {
		t.Fatalf("partial cleanup %+v, error %v", cleanup, err)
	}
	if len(daemon.stops) != 1 || daemon.stops[0].SessionID != receipt.SessionID {
		t.Fatalf("stop calls %+v", daemon.stops)
	}
	saved, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil {
		t.Fatal(err)
	}
	if !saved.Cleanup.SessionStopped || saved.UIActions.Receipts[0].Outcome != uiaction.Uncertain {
		t.Fatalf("receipt %+v", saved)
	}
	for _, path := range []string{lockPath(root), filepath.Join(runPath(root, request.Claim.RunID), "payload", "scenario.py")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("retry authority or evidence was removed: %v", err)
		}
	}
	if err := os.Remove(blockedPath); err != nil {
		t.Fatal(err)
	}
	cleanup, err = service.Settle(context.Background(), root, settleHostRequest(saved))
	if err != nil || !cleanup.Known() {
		t.Fatalf("retry cleanup %+v, error %v", cleanup, err)
	}
}

type cancelPendingUIProcess struct {
	cancel context.CancelFunc
	calls  int
	output []byte
}

func (p *cancelPendingUIProcess) Run(context.Context, string, []string, map[string]string) ([]byte, error) {
	p.calls++
	p.cancel()
	return p.output, nil
}
func TestUIPollPacingHonorsCancellationWithoutAnotherBrokerCall(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	claim := testHostClaim(time.Now(), "UIPOLL")
	session := orchestrator.SessionID("bss_exact-poll-ui-session-identity-123456")
	receipt := uiaction.Receipt{Index: 0, Kind: uiaction.Key, SessionID: string(session), Outcome: uiaction.Pending}
	reply, _ := json.Marshal(map[string]any{"schema_version": 1, "ready": false, "receipt": receipt})
	envelope, _ := json.Marshal(map[string]any{"executed": true, "result": string(reply)})
	process := &cancelPendingUIProcess{cancel: cancel, output: envelope}
	_, err := NewRuntime(process).Perform(ctx, AuthorizedAction{Claim: claim, RunRoot: uiRuntimeRoot(t, claim), SessionID: session, SessionName: orchestrator.SessionNameForRun(claim.RunID), Executable: `C:\Fake\blendersessiond.exe`, Action: uiTestBatch(t).Actions[0]})
	if !errors.Is(err, context.Canceled) || process.calls != 1 {
		t.Fatalf("calls=%d error=%v", process.calls, err)
	}
}
func TestRuntimeUIErrorRetainsOnlySafeContextCause(t *testing.T) {
	claim := testHostClaim(time.Now(), "UITIMEOUT")
	process := &fakeProcessRunner{outputs: [][]byte{nil}, errors: []error{fmt.Errorf("private value: %w", context.DeadlineExceeded)}}
	_, err := NewRuntime(process).Perform(context.Background(), AuthorizedAction{Claim: claim, RunRoot: uiRuntimeRoot(t, claim), SessionID: "bss_exact-timeout-ui-session-identity-123456", SessionName: orchestrator.SessionNameForRun(claim.RunID), Executable: `C:\Fake\blendersessiond.exe`, Action: uiTestBatch(t).Actions[0]})
	if !errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "private value") {
		t.Fatalf("error %v", err)
	}
}

func uiRuntimeRoot(t *testing.T, claim orchestrator.LockClaim) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), string(claim.RunID))
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

type uiAcknowledgementProcess struct {
	t       *testing.T
	calls   int
	respond func(uiAcknowledgement, string) ([]byte, error)
}

func (p *uiAcknowledgementProcess) Run(_ context.Context, _ string, arguments []string, _ map[string]string) ([]byte, error) {
	p.t.Helper()
	p.calls++
	var params struct {
		Code string `json:"code"`
	}
	for index, arg := range arguments {
		if arg == "--params" {
			if err := json.Unmarshal([]byte(arguments[index+1]), &params); err != nil {
				p.t.Fatal(err)
			}
		}
	}
	marker := "base64.b64decode('"
	start := strings.LastIndex(params.Code, marker)
	if start < 0 {
		p.t.Fatal("missing encoded UI request")
	}
	encoded := strings.SplitN(params.Code[start+len(marker):], "'", 2)[0]
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		p.t.Fatal(err)
	}
	var data struct {
		Claim     orchestrator.LockClaim `json:"claim"`
		SessionID orchestrator.SessionID `json:"session_id"`
		Nonce     string                 `json:"nonce"`
		Path      string                 `json:"ack_path"`
		Index     int                    `json:"index"`
		Action    uiaction.Action        `json:"action"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		p.t.Fatal(err)
	}
	if data.Nonce == "" || data.Path == "" {
		p.t.Fatal("missing private acknowledgement identity")
	}
	ack := uiAcknowledgement{SchemaVersion: 1, Claim: data.Claim, SessionID: data.SessionID, Nonce: data.Nonce,
		Receipt: uiaction.Receipt{Index: data.Index, Kind: data.Action.Kind(), SessionID: string(data.SessionID), Outcome: uiaction.Queued, Window: &uiaction.Window{Width: 100, Height: 80}, EventCount: data.Action.EventCount()}}
	return p.respond(ack, data.Path)
}
func pendingUIReply(t *testing.T, receipt uiaction.Receipt) []byte {
	t.Helper()
	receipt.Outcome = uiaction.Pending
	receipt.EventCount = 0
	raw, err := json.Marshal(map[string]any{"schema_version": 1, "ready": false, "receipt": receipt})
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := json.Marshal(map[string]any{"executed": true, "result": string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}
func TestUIAcknowledgementUsesOneDaemonCallAndValidatesPrivateFile(t *testing.T) {
	for _, mode := range []string{"success", "claim", "session", "nonce", "index", "count", "symlink", "directory-symlink", "oversized", "cancelled", "without-pending"} {
		t.Run(mode, func(t *testing.T) {
			claim := testHostClaim(time.Now(), "UIACK")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			process := &uiAcknowledgementProcess{t: t}
			process.respond = func(ack uiAcknowledgement, path string) ([]byte, error) {
				pending := pendingUIReply(t, ack.Receipt)
				switch mode {
				case "claim":
					ack.Claim.RequestHash = strings.Repeat("0", 64)
				case "session":
					ack.SessionID = "bss_other-exact-ui-session-identity-123456"
				case "nonce":
					ack.Nonce = "other"
				case "index":
					ack.Receipt.Index++
				case "count":
					ack.Receipt.EventCount++
				case "cancelled":
					cancel()
				case "without-pending":
					pending = []byte(`{"executed":true,"result":"{}"}`)
				}
				raw, _ := json.Marshal(ack)
				switch mode {
				case "symlink":
					target := filepath.Join(t.TempDir(), "ack.json")
					if err := os.WriteFile(target, raw, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, path); err != nil {
						t.Skip(err)
					}
				case "directory-symlink":
					directory := filepath.Dir(path)
					if err := os.Remove(directory); err != nil {
						t.Fatal(err)
					}
					target := t.TempDir()
					if err := os.WriteFile(filepath.Join(target, "ack.json"), raw, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(target, directory); err != nil {
						t.Skip(err)
					}
				default:
					if mode == "oversized" {
						raw = []byte(strings.Repeat("x", (16<<10)+1))
					}
					if err := os.WriteFile(path, raw, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				return pending, nil
			}
			got, err := NewRuntime(process).Perform(ctx, AuthorizedAction{Claim: claim, RunRoot: uiRuntimeRoot(t, claim), SessionID: "bss_exact-ack-ui-session-identity-123456", SessionName: orchestrator.SessionNameForRun(claim.RunID), Executable: `C:\Fake\blendersessiond.exe`, Action: uiTestBatch(t).Actions[0]})
			if process.calls != 1 {
				t.Fatalf("broker calls %d", process.calls)
			}
			if mode == "success" {
				if err != nil || got.Outcome != uiaction.Queued || got.EventCount != 2 {
					t.Fatalf("receipt %+v error %v", got, err)
				}
			} else if err == nil || got.Outcome != uiaction.Uncertain {
				t.Fatalf("accepted invalid acknowledgement: %+v %v", got, err)
			}
			if mode == "cancelled" && !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation: %v", err)
			}
		})
	}
}
