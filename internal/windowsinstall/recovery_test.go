package windowsinstall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/orchestrator"
)

func TestExecutionRetryLimitPreservesJournalFenceAndStatus(t *testing.T) {
	owner, machine, request := ownerFixture(t)
	executions := 0
	owner.run = func(_ context.Context, record executionRequest, _ func(executionOwnership) error) (workerOutcome, *treeExit, error) {
		executions++
		if executions == 64 {
			machine.inspectionErr = fmt.Errorf("keeper interrupted after terminal publication")
		}
		outcome := workerOutcome{Result: record.Preview, TaskMutation: "settled", Error: "CreateProcess refused before spawn"}
		outcome.Result.State = "partial"
		return outcome, &treeExit{Kind: "not-started", Keeper: ProcessIdentity{101, "1001"}, ObservedAt: time.Now().UTC()}, nil
	}
	for attempt := 0; attempt < 64; attempt++ {
		result, err := owner.Execute(context.Background(), request)
		if err == nil || result.State != "partial" || result.Execution == nil || result.Execution.ProcessState != "not-started" || result.Execution.TreeCleanup != "known" {
			t.Fatalf("attempt %d execution=%+v error=%v", attempt+1, result.Execution, err)
		}
	}
	machine.inspectionErr = nil
	fresh := newOwner(machine)
	before, beforeErr := fresh.Status(context.Background(), statusRequest(request))
	if beforeErr == nil || beforeErr.Error() != "CreateProcess refused before spawn" || before.Execution == nil || before.Execution.FenceState != "held" || before.Completion != "known" {
		t.Fatalf("status at limit=%+v error=%v", before.Execution, beforeErr)
	}
	type snapshotFile struct{ identity, data string }
	snapshot := func(root string) map[string]snapshotFile {
		t.Helper()
		files := map[string]snapshotFile{}
		if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			identity, err := fileIdentity(path)
			if err != nil {
				return err
			}
			var data []byte
			if !entry.IsDir() {
				data, err = os.ReadFile(path)
				if err != nil {
					return err
				}
			}
			files[path] = snapshotFile{identity, string(data)}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return files
	}
	journalPath := filepath.Join(request.StateRoot, "setup-operations", string(request.OperationID))
	journalBefore := snapshot(journalPath)
	fencePath := filepath.Join(request.StateRoot, "pending-setup.json")
	fenceBefore, err := os.ReadFile(fencePath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Execute(context.Background(), request); err == nil || !strings.Contains(err.Error(), "execution count exceeds limit") {
		t.Fatalf("retry limit=%v", err)
	}
	if executions != 64 {
		t.Errorf("retry limit launched execution %d", executions)
	}
	if !reflect.DeepEqual(journalBefore, snapshot(journalPath)) {
		t.Error("retry limit changed execution journal bytes or identities")
	}
	fenceAfter, err := os.ReadFile(fencePath)
	if err != nil || !bytes.Equal(fenceBefore, fenceAfter) {
		t.Errorf("retry limit changed predecessor fence: %v", err)
	}
	after, afterErr := fresh.Status(context.Background(), statusRequest(request))
	if afterErr == nil || afterErr.Error() != beforeErr.Error() || !reflect.DeepEqual(before, after) {
		t.Errorf("retry limit changed fresh status: state=%s execution=%+v error=%v", after.State, after.Execution, afterErr)
	}
}

func TestExecutionCancelledPublicationResumesInstalledRuntime(t *testing.T) {
	owner, machine, request := ownerFixture(t)
	if err := os.Chmod(filepath.Dir(request.StateRoot), 0700); err != nil {
		t.Fatal(err)
	}
	request.TargetOut = filepath.Join(filepath.Dir(request.StateRoot), "target.json")
	request.ExpectedPlan = ""
	run := owner.run
	owner.run = func(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
		workerContext, cancel := context.WithCancel(ctx)
		defer cancel()
		owner.installer.checkpoint = func(stage string) error {
			if stage == "after-create:task" {
				cancel()
			}
			return nil
		}
		defer func() { owner.installer.checkpoint = nil }()
		return run(workerContext, record, publish)
	}
	failed, err := owner.Execute(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), context.Canceled.Error()) || failed.State != "installed" || failed.Completion != "known" || failed.TargetPublication.Status != "failed" || failed.TargetPublication.Error != context.Canceled.Error() {
		t.Fatalf("cancelled publication state=%s completion=%s publication=%+v error=%v", failed.State, failed.Completion, failed.TargetPublication, err)
	}
	if _, err := os.Stat(request.TargetOut); !os.IsNotExist(err) {
		t.Fatal("cancelled publication created target", err)
	}
	receiptPath := filepath.Join(request.StateRoot, "installations", string(request.InstallationID), "receipt.json")
	before, err := readReceipt(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	machine.taskCalls = nil
	owner.run = run
	installed, err := owner.Execute(context.Background(), request)
	if err != nil || installed.State != "installed" || installed.TargetPublication.Status != "published" || installed.Execution.Token == failed.Execution.Token || installed.InstallationID != failed.InstallationID || installed.OperationID != failed.OperationID {
		t.Fatalf("publication resume state=%s publication=%+v execution=%+v error=%v", installed.State, installed.TargetPublication, installed.Execution, err)
	}
	after, err := readReceipt(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	if before.InstallationID != after.InstallationID || before.OperationID != after.OperationID || before.RootIdentity != after.RootIdentity || before.IntentSHA256 != after.IntentSHA256 || before.TaskFingerprint != after.TaskFingerprint || !reflect.DeepEqual(before.Files, after.Files) {
		t.Fatal("publication resume changed installation authority or runtime identities")
	}
	for _, action := range machine.taskCalls {
		if action != "inspect" {
			t.Fatalf("publication resume mutated task: %s", action)
		}
	}
	if _, err := publicationFile(request, installed); err != nil {
		t.Fatal("published target differs from installed result", err)
	}
}

func TestExecutionReplayReleasesTerminalFenceBeforeRunAdmission(t *testing.T) {
	owner, machine, request := ownerFixture(t)
	run := owner.run
	owner.run = func(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
		outcome, proof, err := run(ctx, record, publish)
		machine.inspectionErr = fmt.Errorf("keeper interrupted after terminal publication")
		return outcome, proof, err
	}
	interrupted, err := owner.Execute(context.Background(), request)
	if err == nil || interrupted.Execution == nil || interrupted.Execution.FenceState != "held" {
		t.Fatalf("interruption=%+v %v", interrupted.Execution, err)
	}
	machine.inspectionErr = nil
	fresh := newOwner(machine)
	fresh.launch = func(ctx context.Context, request Request) (Result, error) {
		return fresh.keep(ctx, request)
	}
	service := host.NewService(host.Dependencies{})
	claim := orchestrator.LockClaim{SchemaVersion: 1, RunID: "bbx_01SRUNIDENTITY0000000000", RequestID: "req_01SREQUESTIDENTITY000000", ControllerID: "ctl_test", Deadline: time.Now().Add(time.Minute), RequestHash: strings.Repeat("a", 64), TaskName: "fixture-task"}
	if err := service.Acquire(context.Background(), request.StateRoot, host.AcquireRequest{SchemaVersion: 1, Claim: claim}); err == nil {
		t.Fatal("terminal but held fence admitted Run")
	}
	replayed, err := fresh.Execute(context.Background(), request)
	if err != nil || replayed.Execution == nil || replayed.Execution.Token != interrupted.Execution.Token {
		t.Fatalf("replay=%+v %v", replayed.Execution, err)
	}
	observed, err := fresh.Status(context.Background(), statusRequest(request))
	if err != nil || observed.Execution == nil {
		t.Fatalf("fresh status=%+v %v", observed.Execution, err)
	}
	if replayed.Execution.FenceState != "released" || !reflect.DeepEqual(replayed.Execution, observed.Execution) {
		t.Errorf("replay fence=%s differs from fresh status fence=%s", replayed.Execution.FenceState, observed.Execution.FenceState)
	}
	if err := service.Acquire(context.Background(), request.StateRoot, host.AcquireRequest{SchemaVersion: 1, Claim: claim}); err != nil {
		t.Fatal("settled replay did not reopen Run admission", err)
	}
}

func TestPublishTargetPrepublicationFailuresAndNonattempts(t *testing.T) {
	owner, _, request := ownerFixture(t)
	installed, err := owner.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, state, expected string
		apply, requested      bool
	}{
		{"validation-failure", "installed", "failed", true, true},
		{"preview", "installed", "not-published", false, true},
		{"partial", "partial", "not-published", true, true},
		{"not-requested", "installed", "not-requested", true, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			current := request
			current.Apply = test.apply
			if test.requested {
				current.TargetOut = filepath.Join(request.StateRoot, "target.json")
			}
			input := installed
			input.State = test.state
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			result, err := PublishTarget(ctx, current, input)
			if result.TargetPublication.Status != test.expected {
				t.Fatalf("publication=%+v error=%v", result.TargetPublication, err)
			}
			if test.expected == "failed" {
				if err == nil || errors.Is(err, context.Canceled) || result.TargetPublication.Error != err.Error() {
					t.Fatalf("validation failure not recorded: %+v %v", result.TargetPublication, err)
				}
			} else if err != nil || result.TargetPublication.Error != "" {
				t.Fatalf("nonattempt failed: %+v %v", result.TargetPublication, err)
			}
		})
	}
}
