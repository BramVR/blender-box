package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/target"
)

func originalClaim(t *testing.T) LockClaim {
	t.Helper()
	request, err := buildRequest(testIntent(t))
	if err != nil {
		t.Fatal(err)
	}
	return request.Claim
}
func TestRecoveryRejectsEveryChangedTargetFieldBeforeContact(t *testing.T) {
	original := testTarget(t)
	claim := originalClaim(t)
	for _, field := range []string{"SSHAlias", "SSHUser", "InteractiveUser", "WorkRoot", "TaskName", "BlenderExecutable", "SessionBrokerExecutable", "HostExecutable"} {
		t.Run(field, func(t *testing.T) {
			config := original.Windows()
			alias := original.SSHAlias()
			switch field {
			case "SSHAlias":
				alias = "replacement"
			case "WorkRoot":
				config.WorkRoot = `C:\Other`
				config.SessionBrokerExecutable = `C:\Other\bin\daemon.exe`
				config.HostExecutable = `C:\Other\bin\host.exe`
			default:
				value := reflect.ValueOf(&config).Elem().FieldByName(field)
				value.SetString(value.String() + "-changed")
			}
			changed, err := target.NewWindows(alias, config)
			if err != nil {
				t.Fatal(err)
			}
			host := &recoveryHost{fakeHost: fakeHost{receipt: RunReceipt{SchemaVersion: 1, Claim: claim, State: StateStarting}}}
			first := recoveryRunner(t, host, claim)
			fresh := New(host, first.journal.root)
			_, statusErr := fresh.Status(context.Background(), changed, claim.RunID)
			_, stopErr := fresh.Stop(context.Background(), changed, claim.RunID)
			for _, err := range []error{statusErr, stopErr} {
				if err == nil || !IsAuthorityError(err) || !strings.Contains(err.Error(), "target does not match original Run") {
					t.Fatalf("mismatch error=%v", err)
				}
			}
			if len(host.operations) != 0 {
				t.Fatalf("changed target contacted host: %v", host.operations)
			}
			if _, err := fresh.Status(context.Background(), original, claim.RunID); err != nil {
				t.Fatalf("original target failed recovery: %v", err)
			}
		})
	}
}
func TestRecoveryNeedsCompleteOriginalAuthority(t *testing.T) {
	for _, contents := range []string{"missing", `{}`, `{"schema_version":0}`, `{"schema_version":1,"target_fingerprint":"legacy"}`, `{"schema_version":1,"schema_version":1}`, strings.Repeat("x", maxAuthoritySize+1)} {
		t.Run(fmt.Sprintf("record-%d", len(contents)), func(t *testing.T) {
			claim := originalClaim(t)
			host := &recoveryHost{}
			root := filepath.Join(t.TempDir(), "private")
			runner := New(host, root)
			if contents != "missing" {
				if err := os.MkdirAll(filepath.Join(root, "runs"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, claimPath(claim.RunID)), []byte(contents), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := runner.Status(context.Background(), testTarget(t), claim.RunID); err == nil || !strings.Contains(err.Error(), "insufficient recovery authority") {
				t.Fatalf("error=%v", err)
			}
			if _, err := runner.Stop(context.Background(), testTarget(t), claim.RunID); err == nil {
				t.Fatal("stop without authority")
			}
			if len(host.operations) != 0 {
				t.Fatal("host contacted without authority")
			}
		})
	}
}
func TestFreshRecoveryRejectsEveryChangedClaimField(t *testing.T) {
	original := originalClaim(t)
	for _, field := range []string{"SchemaVersion", "RunID", "RequestID", "ControllerID", "Deadline", "RequestHash", "TaskName"} {
		t.Run(field, func(t *testing.T) {
			changed := original
			switch field {
			case "SchemaVersion":
				changed.SchemaVersion = 2
			case "RunID":
				changed.RunID = "bbx_replacement-run-identity-123456"
			case "RequestID":
				changed.RequestID = "req_replacement-request-identity-123456"
			case "ControllerID":
				changed.ControllerID = "another-controller"
			case "Deadline":
				changed.Deadline = changed.Deadline.Add(time.Second)
			case "RequestHash":
				changed.RequestHash = strings.Repeat("f", 64)
			case "TaskName":
				changed.TaskName = "OtherTask"
			}
			host := &recoveryHost{fakeHost: fakeHost{receipt: RunReceipt{SchemaVersion: 1, Claim: changed, State: StateStarting}}}
			runner := recoveryRunner(t, host, original)
			if _, err := New(host, runner.journal.root).Stop(context.Background(), testTarget(t), original.RunID); err == nil {
				t.Fatal("changed claim accepted")
			}
			if !reflect.DeepEqual(host.operations, []string{"observe"}) {
				t.Fatalf("unsafe effects %v", host.operations)
			}
			if _, err := os.Lstat(filepath.Join(runner.journal.root, pinPath(original.RunID))); !os.IsNotExist(err) {
				t.Fatal("invalid receipt pinned")
			}
		})
	}
}
func TestSessionPinPersistsAndRejectsChangeOrErasure(t *testing.T) {
	claim := originalClaim(t)
	session := SessionID("bss_original-session-identity-123456")
	host := &recoveryHost{fakeHost: fakeHost{receipt: RunReceipt{SchemaVersion: 1, Claim: claim, State: StateStarting}}}
	runner := recoveryRunner(t, host, claim)
	if _, err := runner.Status(context.Background(), testTarget(t), claim.RunID); err != nil {
		t.Fatal(err)
	}
	if _, session, err := runner.journal.load(testTarget(t), claim.RunID); err != nil || session != "" {
		t.Fatal("claim-only observation pinned Session")
	}
	host.receipt.SessionID = session
	if _, err := New(host, runner.journal.root).Status(context.Background(), testTarget(t), claim.RunID); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []SessionID{"bss_replacement-session-identity-123456", ""} {
		host.receipt.SessionID = changed
		host.operations = nil
		if _, err := New(host, runner.journal.root).Stop(context.Background(), testTarget(t), claim.RunID); err == nil || !IsAuthorityError(err) {
			t.Fatalf("changed Session accepted: %v", err)
		}
		if !reflect.DeepEqual(host.operations, []string{"observe"}) {
			t.Fatalf("unsafe effects %v", host.operations)
		}
	}
	host.receipt.SessionID = session
	for i := 0; i < 2; i++ {
		if _, err := New(host, runner.journal.root).Stop(context.Background(), testTarget(t), claim.RunID); err != nil {
			t.Fatal(err)
		}
	}
}
func TestConcurrentSessionPinsAreWriteOnce(t *testing.T) {
	claim := originalClaim(t)
	runner := recoveryRunner(t, &recoveryHost{}, claim)
	selected := testTarget(t)
	sessions := []SessionID{"bss_first-concurrent-session-123456", "bss_other-concurrent-session-123456"}
	var group sync.WaitGroup
	results := make(chan SessionID, 16)
	for i := 0; i < 16; i++ {
		session := sessions[i%2]
		group.Add(1)
		go func() {
			defer group.Done()
			err := runner.journal.accept(selected, RunReceipt{Claim: claim, SessionID: session})
			if err == nil {
				results <- session
			} else if !IsAuthorityError(err) {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	close(results)
	_, pinned, err := runner.journal.load(selected, claim.RunID)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for session := range results {
		count++
		if session != pinned {
			t.Fatal("conflicting publication succeeded")
		}
	}
	if count == 0 {
		t.Fatal("no pin published")
	}
	if err := runner.journal.accept(selected, RunReceipt{Claim: claim, SessionID: pinned}); err != nil {
		t.Fatal("identical pin not idempotent")
	}
}

type startHookHost struct {
	fakeHost
	hook func(RunRequest, RunReceipt) error
}

func (host *startHookHost) Start(ctx context.Context, selected target.Target, request RunRequest) (RunReceipt, error) {
	receipt, err := host.fakeHost.Start(ctx, selected, request)
	if err != nil {
		return receipt, err
	}
	if host.hook != nil {
		err = host.hook(request, receipt)
	}
	return receipt, err
}
func TestRunPinPersistenceFailureStopsAutomaticCleanup(t *testing.T) {
	intent := testIntent(t)
	root := filepath.Join(t.TempDir(), "private")
	host := &startHookHost{fakeHost: fakeHost{evidence: testEvidence()}}
	host.hook = func(request RunRequest, _ RunReceipt) error {
		return os.Mkdir(filepath.Join(root, pinPath(request.Claim.RunID)), 0o700)
	}
	_, err := New(host, root).Run(context.Background(), intent)
	if err == nil || !IsAuthorityError(err) {
		t.Fatalf("pin failure=%v", err)
	}
	for _, operation := range host.operations {
		if operation == "settle" || operation == "observe" || strings.HasPrefix(operation, "fetch:") {
			t.Fatalf("effect after failed pin: %v", host.operations)
		}
	}
}
func TestRunCannotOverwriteOriginalClaimOrContactOnRecordFailure(t *testing.T) {
	for _, existing := range []bool{false, true} {
		t.Run(fmt.Sprint(existing), func(t *testing.T) {
			intent := testIntent(t)
			host := &fakeHost{}
			root := filepath.Join(t.TempDir(), "private")
			runner := New(host, root)
			if existing {
				request, err := buildRequest(intent)
				if err != nil {
					t.Fatal(err)
				}
				if err := runner.journal.record(intent.Target, request.Claim); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.WriteFile(root, []byte("operator-file"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := runner.Run(context.Background(), intent)
			if err == nil || !IsPreflightError(err) {
				t.Fatalf("preflight=%v", err)
			}
			if len(host.operations) != 0 {
				t.Fatalf("host reached: %v", host.operations)
			}
		})
	}
}
func TestDeferredSettlementRefreshesConcurrentSessionPin(t *testing.T) {
	intent := testIntent(t)
	root := filepath.Join(t.TempDir(), "private")
	host := &startHookHost{fakeHost: fakeHost{evidence: testEvidence()}}
	host.hook = func(_ RunRequest, receipt RunReceipt) error {
		if err := (journal{root: root}).accept(intent.Target, receipt); err != nil {
			return err
		}
		return fmt.Errorf("dropped start response")
	}
	_, err := New(host, root).Run(context.Background(), intent)
	if err == nil || !strings.Contains(err.Error(), "dropped start response") {
		t.Fatalf("run error=%v", err)
	}
	if !reflect.DeepEqual(host.operations, []string{"inspect", "acquire", "stage", "start", "settle"}) {
		t.Fatalf("operations=%v", host.operations)
	}
	if !host.receipt.Cleanup.Known() {
		t.Fatal("known Session did not settle")
	}
}
func TestDeferredSettlementCannotUseCorruptOrLostPin(t *testing.T) {
	for _, mode := range []string{"corrupt-claim", "corrupt-pin", "lost-pin"} {
		t.Run(mode, func(t *testing.T) {
			intent := testIntent(t)
			root := filepath.Join(t.TempDir(), "private")
			host := &startHookHost{fakeHost: fakeHost{evidence: testEvidence()}}
			host.hook = func(request RunRequest, receipt RunReceipt) error {
				journal := journal{root: root}
				if err := journal.accept(intent.Target, receipt); err != nil {
					return err
				}
				path := filepath.Join(root, pinPath(request.Claim.RunID))
				if mode == "corrupt-claim" {
					path = filepath.Join(root, claimPath(request.Claim.RunID))
				}
				if mode == "lost-pin" {
					if err := os.Remove(path); err != nil {
						return err
					}
				} else {
					if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
						return err
					}
				}
				if mode == "lost-pin" {
					return nil
				}
				return fmt.Errorf("dropped start response")
			}
			if mode == "lost-pin" {
				_, err := New(host, root).Run(context.Background(), intent)
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			_, err := New(host, root).Run(context.Background(), intent)
			if err == nil || !IsAuthorityError(err) {
				t.Fatalf("error=%v", err)
			}
			for _, operation := range host.operations {
				if operation == "settle" {
					t.Fatalf("cleanup used corrupt authority %v", host.operations)
				}
			}
		})
	}
}
func TestJournalSettlementRejectsUnpinnedKnownSession(t *testing.T) {
	claim := originalClaim(t)
	runner := recoveryRunner(t, &recoveryHost{}, claim)
	if _, err := runner.journal.settlement(testTarget(t), RunReceipt{Claim: claim, SessionID: "bss_session-without-pin-123456"}); err == nil || !IsAuthorityError(err) {
		t.Fatalf("unpinned settlement=%v", err)
	}
}
func TestAuthorityRecordContainsOnlyClaimAndDigest(t *testing.T) {
	claim := originalClaim(t)
	runner := recoveryRunner(t, &recoveryHost{}, claim)
	data, err := os.ReadFile(filepath.Join(runner.journal.root, claimPath(claim.RunID)))
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 || fields["claim"] == nil || fields["target_fingerprint"] == nil {
		t.Fatalf("unexpected authority document %v", fields)
	}
}

func TestRecoveryRejectsCaseAliasesInClaimAndPinBeforeContact(t *testing.T) {
	for _, kind := range []string{"claim-uppercase", "claim-duplicate", "pin-uppercase", "pin-duplicate"} {
		t.Run(kind, func(t *testing.T) {
			claim := originalClaim(t)
			host := &recoveryHost{}
			runner := recoveryRunner(t, host, claim)
			path := filepath.Join(runner.journal.root, claimPath(claim.RunID))
			if strings.HasPrefix(kind, "pin") {
				if err := runner.journal.accept(testTarget(t), RunReceipt{Claim: claim, SessionID: "bss_case-test-session-identity-123456"}); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(runner.journal.root, pinPath(claim.RunID))
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			replacement := `"SCHEMA_VERSION":1`
			if strings.HasSuffix(kind, "duplicate") {
				replacement = `"schema_version":1,"SCHEMA_VERSION":2`
			}
			data = []byte(strings.Replace(string(data), `"schema_version":1`, replacement, 1))
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := New(host, runner.journal.root).Stop(context.Background(), testTarget(t), claim.RunID); err == nil || !IsAuthorityError(err) {
				t.Fatalf("case alias accepted: %v", err)
			}
			if len(host.operations) != 0 {
				t.Fatal("invalid local record reached host")
			}
		})
	}
}
func TestDirectRunnerRejectsZeroTargetBeforeEffects(t *testing.T) {
	host := &fakeHost{}
	runner := New(host, filepath.Join(t.TempDir(), "private"))
	intent := testIntent(t)
	intent.Target = target.Target{}
	if _, err := runner.Run(context.Background(), intent); err == nil || !IsPreflightError(err) {
		t.Fatalf("zero Run target: %v", err)
	}
	if _, err := runner.Status(context.Background(), target.Target{}, intent.RunID); err == nil {
		t.Fatal("zero status target")
	}
	if _, err := runner.Stop(context.Background(), target.Target{}, intent.RunID); err == nil {
		t.Fatal("zero stop target")
	}
	if len(host.operations) != 0 {
		t.Fatal("invalid target contacted host")
	}
	if _, err := os.Lstat(intent.EvidenceDir); !os.IsNotExist(err) {
		t.Fatal("invalid target reserved evidence")
	}
}

type fetchHookHost struct {
	fakeHost
	hook func() error
}

func (host *fetchHookHost) Fetch(ctx context.Context, selected target.Target, receipt RunReceipt, file EvidenceFile) ([]byte, error) {
	data, err := host.fakeHost.Fetch(ctx, selected, receipt, file)
	if err != nil {
		return nil, err
	}
	if err := host.hook(); err != nil {
		return nil, err
	}
	return data, fmt.Errorf("interrupted evidence fetch")
}
func TestDeferredSettlementRejectsPinLostAfterAcceptedSession(t *testing.T) {
	intent := testIntent(t)
	root := filepath.Join(t.TempDir(), "private")
	host := &fetchHookHost{fakeHost: fakeHost{evidence: testEvidence()}}
	host.hook = func() error { return os.Remove(filepath.Join(root, pinPath(intent.RunID))) }
	_, err := New(host, root).Run(context.Background(), intent)
	if err == nil || !IsAuthorityError(err) {
		t.Fatalf("lost accepted pin error=%v", err)
	}
	if len(host.operations) == 0 || !strings.HasPrefix(host.operations[len(host.operations)-1], "fetch:") {
		t.Fatalf("settlement used lost Session authority: %v", host.operations)
	}
}
func TestConflictingFirstSessionPinStopsRunCleanup(t *testing.T) {
	intent := testIntent(t)
	root := filepath.Join(t.TempDir(), "private")
	host := &startHookHost{fakeHost: fakeHost{evidence: testEvidence()}}
	host.hook = func(_ RunRequest, receipt RunReceipt) error {
		receipt.SessionID = "bss_concurrent-replacement-session-123456"
		return (journal{root: root}).accept(intent.Target, receipt)
	}
	_, err := New(host, root).Run(context.Background(), intent)
	if err == nil || !IsAuthorityError(err) {
		t.Fatalf("pin conflict=%v", err)
	}
	for _, operation := range host.operations {
		if operation == "settle" || operation == "observe" || strings.HasPrefix(operation, "fetch:") {
			t.Fatalf("effect after conflicting pin=%v", host.operations)
		}
	}
}

func TestOversizedOriginalClaimFailsBeforeHostContact(t *testing.T) {
	host := &fakeHost{}
	intent := testIntent(t)
	intent.ControllerID = strings.Repeat("x", maxAuthoritySize)
	_, err := New(host, filepath.Join(t.TempDir(), "private")).Run(context.Background(), intent)
	if err == nil || !IsPreflightError(err) {
		t.Fatalf("oversized authority error=%v", err)
	}
	if len(host.operations) != 0 {
		t.Fatal("unreadable future authority contacted host")
	}
}

type lostPinBoundaryHost struct {
	fakeHost
	pinFile string
	loseAt  string
}

func (host *lostPinBoundaryHost) Fetch(ctx context.Context, selected target.Target, receipt RunReceipt, file EvidenceFile) ([]byte, error) {
	data, err := host.fakeHost.Fetch(ctx, selected, receipt, file)
	if err == nil && host.loseAt == "fetch" {
		err = os.Remove(host.pinFile)
	}
	return data, err
}
func (host *lostPinBoundaryHost) Observe(ctx context.Context, selected target.Target, runID RunID) (RunReceipt, error) {
	receipt, err := host.fakeHost.Observe(ctx, selected, runID)
	if err == nil && host.loseAt == "observe" {
		err = os.Remove(host.pinFile)
	}
	return receipt, err
}
func (host *lostPinBoundaryHost) Settle(ctx context.Context, selected target.Target, receipt RunReceipt) (CleanupState, error) {
	cleanup, err := host.fakeHost.Settle(ctx, selected, receipt)
	if err == nil && host.loseAt == "settle" {
		err = os.Remove(host.pinFile)
	}
	return cleanup, err
}

func TestKnownSessionBoundariesDoNotRecreateLostPin(t *testing.T) {
	for _, boundary := range []string{"observe", "fetch", "settle"} {
		t.Run(boundary, func(t *testing.T) {
			intent := testIntent(t)
			root := filepath.Join(t.TempDir(), "private")
			host := &lostPinBoundaryHost{fakeHost: fakeHost{evidence: testEvidence()}, pinFile: filepath.Join(root, pinPath(intent.RunID)), loseAt: boundary}
			_, err := New(host, root).Run(context.Background(), intent)
			if !IsAuthorityError(err) {
				t.Fatalf("lost pin boundary=%s err=%v operations=%v", boundary, err, host.operations)
			}
			if _, err := os.Stat(host.pinFile); !os.IsNotExist(err) {
				t.Fatalf("pin recreated: %v", err)
			}
			if boundary != "settle" {
				for _, operation := range host.operations {
					if operation == "settle" || boundary == "observe" && strings.HasPrefix(operation, "fetch:") {
						t.Fatalf("effect after pin loss: %v", host.operations)
					}
				}
				entries, err := os.ReadDir(intent.EvidenceDir)
				if err != nil || len(entries) != 0 {
					t.Fatalf("evidence published after pin loss: %v %v", entries, err)
				}
			} else if _, err := os.Stat(filepath.Join(intent.EvidenceDir, "evidence.json")); !os.IsNotExist(err) {
				t.Fatalf("metadata published after pin loss: %v", err)
			}
		})
	}
}

func TestStatusDoesNotRepinAfterKnownSessionObservation(t *testing.T) {
	claim := originalClaim(t)
	host := &lostPinBoundaryHost{fakeHost: fakeHost{evidence: testEvidence(), receipt: RunReceipt{SchemaVersion: 1, Claim: claim, State: StateRunning, SessionID: "bss_original-pinned-session-123456"}}, loseAt: "observe"}
	runner := recoveryRunner(t, host, claim)
	host.pinFile = filepath.Join(runner.journal.root, pinPath(claim.RunID))
	if err := runner.journal.accept(testTarget(t), host.receipt); err != nil {
		t.Fatal(err)
	}
	_, err := runner.Status(context.Background(), testTarget(t), claim.RunID)
	if !IsAuthorityError(err) {
		t.Fatalf("known pin lost during Status: %v", err)
	}
	if _, err := os.Stat(host.pinFile); !os.IsNotExist(err) {
		t.Fatalf("Status recreated pin: %v", err)
	}
}

type malformedPinnedStartHost struct {
	fakeHost
	journal journal
}

func (host *malformedPinnedStartHost) Start(ctx context.Context, selected target.Target, request RunRequest) (RunReceipt, error) {
	receipt, err := host.fakeHost.Start(ctx, selected, request)
	if err != nil {
		return receipt, err
	}
	pinned := receipt
	pinned.SessionID = "bss_concurrent-pinned-session-123456"
	if err := host.journal.accept(selected, pinned); err != nil {
		return receipt, err
	}
	receipt.SchemaVersion = 99
	return receipt, nil
}
func TestConcurrentStartPinMismatchPrecedesReceiptShapeValidation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	host := &malformedPinnedStartHost{fakeHost: fakeHost{evidence: testEvidence()}, journal: journal{root: root}}
	_, err := New(host, root).Run(context.Background(), testIntent(t))
	if !IsAuthorityError(err) {
		t.Fatalf("concurrent start pin mismatch lost classification: %v", err)
	}
	for _, operation := range host.operations {
		if operation == "settle" || operation == "observe" {
			t.Fatalf("effect after concurrent pin mismatch: %v", host.operations)
		}
	}
}

func TestStopDoesNotObserveAfterLosingKnownPinDuringSettlement(t *testing.T) {
	claim := originalClaim(t)
	host := &lostPinBoundaryHost{fakeHost: fakeHost{evidence: testEvidence(), receipt: RunReceipt{SchemaVersion: 1, Claim: claim, State: StateRunning, SessionID: "bss_original-pinned-session-123456"}}, loseAt: "settle"}
	runner := recoveryRunner(t, host, claim)
	host.pinFile = filepath.Join(runner.journal.root, pinPath(claim.RunID))
	if err := runner.journal.accept(testTarget(t), host.receipt); err != nil {
		t.Fatal(err)
	}
	_, err := runner.Stop(context.Background(), testTarget(t), claim.RunID)
	if !IsAuthorityError(err) {
		t.Fatalf("known pin lost during Stop: %v", err)
	}
	if _, err := os.Stat(host.pinFile); !os.IsNotExist(err) {
		t.Fatalf("Stop recreated pin: %v", err)
	}
	if !reflect.DeepEqual(host.operations, []string{"observe", "settle"}) {
		t.Fatalf("effects after known pin loss: %v", host.operations)
	}
}
