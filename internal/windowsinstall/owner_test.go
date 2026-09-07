package windowsinstall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/orchestrator"
)

func ownerFixture(t *testing.T) (*owner, *fakeMachine, Request) {
	t.Helper()
	installer, machine, request := installFixture(t)
	preview, err := installer.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.InstallationID = preview.InstallationID
	request.OperationID = preview.OperationID
	request.ExpectedPlan = preview.Plan.PlanSHA256
	request.Apply = true
	owner := newOwner(machine)
	owner.installer = installer
	owner.pins = func(_ context.Context, request Request, _ Inspection) (File, []File, func(), error) {
		file, err := observeFile(request.BlenderPath, File{Path: request.BlenderPath, Kind: "file", Size: int64(len(peFixture())), SHA256: digest(peFixture())})
		return file, []File{}, func() {}, err
	}
	owner.alive = func(ProcessIdentity) (bool, error) { return true, nil }
	owner.run = func(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
		own := executionOwnership{SchemaVersion: 1, Claim: record.claim(), Keeper: ProcessIdentity{101, "1001"}, Worker: ProcessIdentity{102, "1002"}}
		if err := publish(own); err != nil {
			return workerOutcome{}, nil, err
		}
		worker := *installer
		claim := record.claim()
		worker.claim = &claim
		result, err := worker.Execute(ctx, record.Request)
		outcome := workerOutcome{Result: result, TaskMutation: "settled"}
		if errors.Is(err, errTaskMutationUnknown) || errors.Is(err, errNativeCleanupUnknown) {
			outcome.TaskMutation = "unknown"
		}
		if err == nil {
			outcome.Result, err = PublishTarget(ctx, record.Request, result)
		}
		if err == nil {
			outcome.inspectPublication(record.Request)
		}
		if err != nil {
			outcome.Error = err.Error()
		}
		return outcome, &treeExit{Kind: "tree-empty", Keeper: own.Keeper, ObservedAt: time.Now().UTC(), Worker: own.Worker, WorkerExitObserved: true}, nil
	}
	owner.launch = func(_ context.Context, request Request) (Result, error) {
		return owner.keep(context.Background(), request)
	}
	return owner, machine, request
}
func statusRequest(request Request) Request {
	return Request{Operation: "status", Platform: "windows", StateRoot: request.StateRoot, InstallationID: request.InstallationID, OperationID: request.OperationID}
}

func TestExecutionFreshStatusAndSuccessfulReplay(t *testing.T) {
	owner, machine, request := ownerFixture(t)
	installed, err := owner.Execute(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if installed.Execution == nil || installed.Execution.State != "terminal" || installed.Execution.TreeCleanup != "known" {
		t.Fatalf("missing exact terminal result: %+v", installed)
	}
	before := machine.probes
	fresh := newOwner(machine)
	fresh.alive = owner.alive
	observed, err := fresh.Execute(context.Background(), statusRequest(request))
	if err != nil || observed.Execution.Token != installed.Execution.Token || observed.State != "installed" {
		t.Fatalf("fresh status=%+v err=%v", observed, err)
	}
	replay, err := owner.Execute(context.Background(), request)
	if err != nil || replay.Execution.Token != installed.Execution.Token || machine.probes != before {
		t.Fatalf("replay=%+v err=%v probes=%d", replay, err, machine.probes)
	}
	if err := host.RejectPendingSetup(request.StateRoot); err != nil {
		t.Fatal("terminal owner retained fence", err)
	}
	file := filepath.Join(request.StateRoot, "installations", string(request.InstallationID), "runtime", "blender-box.exe")
	if err := os.WriteFile(file, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Execute(context.Background(), request); err == nil {
		t.Fatal("replay accepted changed installed file")
	}
}

func TestExecutionPartialResumeRejectsStaleStop(t *testing.T) {
	owner, _, request := ownerFixture(t)
	owner.installer.checkpoint = func(stage string) error {
		if stage == "prepared" {
			return fmt.Errorf("portable interruption")
		}
		return nil
	}
	first, err := owner.Execute(context.Background(), request)
	if err == nil || first.State != "partial" || first.Execution == nil || first.Execution.TreeCleanup != "known" {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	owner.installer.checkpoint = nil
	second, err := owner.Execute(context.Background(), request)
	if err != nil || second.State != "installed" || second.Execution.Token == first.Execution.Token {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	stop := statusRequest(request)
	stop.Operation = "stop"
	stop.Apply = true
	stop.ExecutionToken = first.Execution.Token
	if _, err := owner.Execute(context.Background(), stop); err == nil || !strings.Contains(err.Error(), "stale-execution") {
		t.Fatalf("stale stop accepted: %v", err)
	}
	observed, err := owner.Execute(context.Background(), statusRequest(request))
	if err != nil || observed.Execution.CancelRequested {
		t.Fatalf("stale stop touched successor: %+v %v", observed, err)
	}
}

func TestExecutionStopPublishesWhileWorkerHoldsMaintenance(t *testing.T) {
	owner, _, request := ownerFixture(t)
	entered := make(chan struct{})
	resume := make(chan struct{})
	owner.installer.checkpoint = func(stage string) error {
		if stage == "prepared" {
			close(entered)
			<-resume
			return fmt.Errorf("cooperative interruption")
		}
		return nil
	}
	finished := make(chan Result, 1)
	go func() { result, _ := owner.Execute(context.Background(), request); finished <- result }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("worker never entered maintenance")
	}
	result, err := owner.Execute(context.Background(), statusRequest(request))
	if err != nil {
		close(resume)
		t.Fatal(err)
	}
	stop := statusRequest(request)
	stop.Operation = "stop"
	stop.Apply = true
	stop.ExecutionToken = result.Execution.Token
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	stopped, err := owner.Execute(ctx, stop)
	close(resume)
	if err != nil || !stopped.Execution.CancelRequested || stopped.Execution.TreeCleanup != "unknown" {
		t.Fatalf("stop waited for worker or claimed cleanup: %+v %v", stopped, err)
	}
	select {
	case final := <-finished:
		if final.Execution.TreeCleanup != "known" {
			t.Fatalf("cleanup=%+v", final)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not finish")
	}
}

func TestExecutionKeeperLossRetainsFenceAndRuntime(t *testing.T) {
	owner, machine, request := ownerFixture(t)
	ownedRun := owner.run
	owner.run = func(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
		outcome, _, err := ownedRun(ctx, record, publish)
		return outcome, nil, errors.Join(err, errNativeCleanupUnknown)
	}
	result, err := owner.Execute(context.Background(), request)
	if err == nil || result.Execution.TreeCleanup != "unknown" || result.Completion != "unknown" {
		t.Fatalf("keeper loss=%+v %v", result, err)
	}
	owner.alive = func(ProcessIdentity) (bool, error) { return false, nil }
	before := machine.probes
	again, _ := owner.Execute(context.Background(), request)
	if again.Execution.Token != result.Execution.Token || machine.probes != before {
		t.Fatal("unknown execution was resumed")
	}
	if err := host.RejectPendingSetup(request.StateRoot); err == nil {
		t.Fatal("unknown execution lost pending fence")
	}
	if !machine.current.Exists {
		t.Fatal("unknown execution removed owned task")
	}
}

func TestExecutionTaskTransportAmbiguityRetainsFence(t *testing.T) {
	owner, _, request := ownerFixture(t)
	run := owner.run
	owner.run = func(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
		outcome, exit, err := run(ctx, record, publish)
		outcome.TaskMutation = "unknown"
		outcome.Error = errTaskMutationUnknown.Error()
		return outcome, exit, err
	}
	result, _ := owner.Execute(context.Background(), request)
	if result.Completion != "unknown" || result.Execution.TaskMutation != "unknown" || result.Execution.TreeCleanup != "known" {
		t.Fatalf("service ambiguity lost: %+v", result)
	}
	if err := host.RejectPendingSetup(request.StateRoot); err == nil {
		t.Fatal("tree-empty cleared ambiguous service mutation")
	}
	remove := request
	remove.Operation = "remove"
	remove.OperationID = OperationID("bbxo_" + strings.Repeat("b", 32))
	remove.ExpectedPlan = ""
	if _, err := owner.Execute(context.Background(), remove); err == nil {
		t.Fatal("removal accepted ambiguous task mutation")
	}
}

func TestExecutionMalformedJournalNeverReleasesFence(t *testing.T) {
	for _, fault := range []string{"duplicate", "unknown-field", "root", "token", "terminal", "fence"} {
		t.Run(fault, func(t *testing.T) {
			owner, _, request := ownerFixture(t)
			run := owner.run
			owner.run = func(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
				outcome, _, err := run(ctx, record, publish)
				return outcome, nil, err
			}
			result, _ := owner.Execute(context.Background(), request)
			path := filepath.Join(request.StateRoot, "setup-operations", string(request.OperationID), result.Execution.Token, "request.json")
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch fault {
			case "duplicate":
				data = bytes.Replace(data, []byte(`"schema_version":1`), []byte(`"schema_version":1,"schema_version":1`), 1)
			case "unknown-field":
				data = append([]byte(`{"surprise":true,`), data[1:]...)
			case "root":
				data = bytes.Replace(data, []byte(`"root_identity":"`), []byte(`"root_identity":"changed`), 1)
			case "token":
				data = bytes.ReplaceAll(data, []byte(result.Execution.Token), []byte("bbxe_"+strings.Repeat("c", 32)))
			case "terminal":
				path = filepath.Join(filepath.Dir(path), "terminal.json")
				data = []byte(`{}`)
			case "fence":
				path = filepath.Join(request.StateRoot, "pending-setup.json")
				data = []byte(`{}`)
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := owner.Execute(context.Background(), statusRequest(request)); err == nil {
				t.Fatal("malformed authority accepted")
			}
			if _, err := owner.Execute(context.Background(), request); err == nil {
				t.Fatal("malformed execution resumed")
			}
			if err := host.RejectPendingSetup(request.StateRoot); err == nil {
				t.Fatal("malformed fence cleared")
			}
		})
	}
}

func TestExecutionAdmissionPreservesActiveRunAndUnrelatedFiles(t *testing.T) {
	owner, machine, request := ownerFixture(t)
	if err := os.Mkdir(request.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(request.StateRoot, "host-lock.json")
	data := []byte("retained active Run authority")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Execute(context.Background(), request); err == nil {
		t.Fatal("active Run admitted setup")
	}
	observed, _ := os.ReadFile(path)
	if !bytes.Equal(observed, data) || machine.probes != 0 {
		t.Fatal("active Run authority changed")
	}
	if _, err := os.Stat(filepath.Join(request.StateRoot, "setup-operations")); !os.IsNotExist(err) {
		t.Fatal("active Run created setup journal")
	}
}

func TestExecutionPublicationOwnedByWorkerAndRetryUsesNewToken(t *testing.T) {
	owner, _, request := ownerFixture(t)
	if err := os.Chmod(filepath.Dir(request.StateRoot), 0700); err != nil {
		t.Fatal(err)
	}
	request.TargetOut = filepath.Join(filepath.Dir(request.StateRoot), "target.json")
	request.ExpectedPlan = ""
	previewRequest := request
	previewRequest.Apply = false
	preview, err := owner.Execute(context.Background(), previewRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(request.TargetOut); !os.IsNotExist(err) {
		t.Fatal("preview published target")
	}
	request.ExpectedPlan = preview.Plan.PlanSHA256
	if err := os.WriteFile(request.TargetOut, []byte("operator"), 0600); err != nil {
		t.Fatal(err)
	}
	failed, err := owner.Execute(context.Background(), request)
	if err == nil || failed.TargetPublication.Status != "failed" || failed.State != "installed" || failed.Completion != "known" {
		t.Fatalf("publication=%+v %v", failed, err)
	}
	if err := os.Remove(request.TargetOut); err != nil {
		t.Fatal(err)
	}
	installed, err := owner.Execute(context.Background(), request)
	if err != nil || installed.TargetPublication.Status != "published" || installed.Execution.Token == failed.Execution.Token {
		t.Fatalf("publication retry=%+v %v", installed, err)
	}
	bytes, err := os.ReadFile(request.TargetOut)
	if err != nil || len(bytes) == 0 {
		t.Fatal("worker did not publish")
	}
	replay, err := owner.Execute(context.Background(), request)
	if err != nil || replay.Execution.Token != installed.Execution.Token {
		t.Fatalf("published result not replayed: %+v %v", replay, err)
	}
}

func TestKeeperRequiresCompleteEOFFromPublicInternalRole(t *testing.T) {
	owner, _, request := ownerFixture(t)
	encoded, _ := json.Marshal(request)
	read, write := io.Pipe()
	defer read.Close()
	defer write.Close()
	inputContext, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := owner.serveKeeper(inputContext, read); done <- err }()
	if _, err := write.Write(encoded); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Fatalf("accepted request without EOF: %v", err)
	default:
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("lost EOF=%v", err)
	}
	if _, err := os.Stat(request.StateRoot); !os.IsNotExist(err) {
		t.Fatal("incomplete request dispatched setup")
	}
	result, err := owner.serveKeeper(context.Background(), bytes.NewReader(encoded))
	if err != nil || result.State != "installed" {
		t.Fatalf("complete EOF result=%s err=%v", result.State, err)
	}
}

func TestExecutionDeadlineSurvivesCallerLossAfterOwnership(t *testing.T) {
	owner, _, request := ownerFixture(t)
	caller, cancel := context.WithCancel(context.Background())
	defer cancel()
	owned, continueWorker := make(chan struct{}), make(chan struct{})
	keeperDone := make(chan Result, 1)
	run := owner.run
	owner.run = func(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
		return run(ctx, record, func(identity executionOwnership) error {
			if err := publish(identity); err != nil {
				return err
			}
			close(owned)
			<-continueWorker
			if ctx.Err() != nil {
				t.Error("caller loss canceled keeper context")
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > executionTimeout || time.Until(deadline) <= 0 || !record.Deadline.Equal(deadline) {
				t.Error("keeper lacks independent deadline")
			}
			return nil
		})
	}
	owner.launch = func(ctx context.Context, request Request) (Result, error) {
		go func() { result, _ := owner.keep(context.Background(), request); keeperDone <- result }()
		<-ctx.Done()
		return emptyResult(request), ctx.Err()
	}
	callerDone := make(chan error, 1)
	go func() { _, err := owner.Execute(caller, request); callerDone <- err }()
	select {
	case <-owned:
	case <-time.After(5 * time.Second):
		t.Fatal("ownership was not published")
	}
	cancel()
	if err := <-callerDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller loss=%v", err)
	}
	close(continueWorker)
	select {
	case result := <-keeperDone:
		if result.State != "installed" || result.Execution.TreeCleanup != "known" {
			t.Fatalf("keeper=%+v", result)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("independent keeper did not finish")
	}
	fresh, err := owner.Status(context.Background(), statusRequest(request))
	if err != nil || fresh.State != "installed" {
		t.Fatalf("fresh status=%+v %v", fresh, err)
	}
}

func TestExecutionTaskMutationErrorCannotBeReconciledByTaskAbsence(t *testing.T) {
	for _, operation := range []string{"install", "remove"} {
		t.Run(operation, func(t *testing.T) {
			owner, machine, request := ownerFixture(t)
			if operation == "remove" {
				if _, err := owner.Execute(context.Background(), request); err != nil {
					t.Fatal(err)
				}
				request.Operation = "remove"
				request.OperationID = OperationID("bbxo_" + strings.Repeat("d", 32))
				request.ExpectedPlan = ""
			}
			machine.taskMutationErr = fmt.Errorf("Task Scheduler response lost after submission")
			result, err := owner.Execute(context.Background(), request)
			if err == nil || result.Execution == nil || result.Execution.TaskMutation != "unknown" || result.Execution.TreeCleanup != "known" || result.Completion != "unknown" {
				t.Fatalf("mutation completion=%+v %v", result.Execution, err)
			}
			receiptPath := filepath.Join(request.StateRoot, "installations", string(request.InstallationID), "receipt.json")
			receipt, err := readReceipt(receiptPath)
			if err != nil {
				t.Fatal(err)
			}
			if receipt.Pending == nil || receipt.Pending.Path != "task" {
				t.Fatal("lost pending task mutation")
			}
			before, _ := os.ReadFile(receiptPath)
			machine.current = taskObservation{}
			machine.taskMutationErr = nil
			_, _ = owner.Status(context.Background(), statusRequest(request))
			_, _ = owner.Execute(context.Background(), request)
			after, _ := os.ReadFile(receiptPath)
			if !bytes.Equal(before, after) {
				t.Fatal("fresh task absence rewrote unresolved mutation")
			}
			if err := host.RejectPendingSetup(request.StateRoot); err == nil {
				t.Fatal("task absence cleared pending setup fence")
			}
		})
	}
}

func TestExecutionProvenNoStartReleasesFenceAndResumes(t *testing.T) {
	owner, _, request := ownerFixture(t)
	run := owner.run
	owner.run = func(_ context.Context, record executionRequest, _ func(executionOwnership) error) (workerOutcome, *treeExit, error) {
		outcome := workerOutcome{Result: record.Preview, TaskMutation: "settled", Error: "CreateProcess refused before spawn"}
		outcome.Result.State = "partial"
		return outcome, &treeExit{Kind: "not-started", Keeper: ProcessIdentity{101, "1001"}, ObservedAt: time.Now().UTC()}, nil
	}
	first, err := owner.Execute(context.Background(), request)
	if err == nil || first.Execution == nil || first.Execution.ProcessState != "not-started" || first.Execution.TreeCleanup != "known" {
		t.Fatalf("no-start=%+v %v", first.Execution, err)
	}
	if err := host.RejectPendingSetup(request.StateRoot); err != nil {
		t.Fatal("known no-start retained fence", err)
	}
	if _, err := os.Stat(filepath.Join(request.StateRoot, "installations", string(request.InstallationID))); !os.IsNotExist(err) {
		t.Fatal("no-start changed installation")
	}
	owner.run = run
	second, err := owner.Execute(context.Background(), request)
	if err != nil || second.State != "installed" || first.Execution.Token == second.Execution.Token {
		t.Fatalf("retry=%+v %v", second.Execution, err)
	}
}

func TestExecutionTerminalFenceRecoveredByExactStopBeforeRunAdmission(t *testing.T) {
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
	before, _ := os.ReadFile(filepath.Join(request.StateRoot, "pending-setup.json"))
	observed, err := fresh.Status(context.Background(), statusRequest(request))
	if err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(request.StateRoot, "pending-setup.json"))
	if !bytes.Equal(before, after) || observed.Execution.FenceState != "held" || observed.Execution.TreeCleanup != "known" {
		t.Fatal("status altered pending terminal fence")
	}
	service := host.NewService(host.Dependencies{})
	claim := orchestrator.LockClaim{SchemaVersion: 1, RunID: "bbx_01SRUNIDENTITY0000000000", RequestID: "req_01SREQUESTIDENTITY000000", ControllerID: "ctl_test", Deadline: time.Now().Add(time.Minute), RequestHash: strings.Repeat("a", 64), TaskName: "fixture-task"}
	if err := service.Acquire(context.Background(), request.StateRoot, host.AcquireRequest{SchemaVersion: 1, Claim: claim}); err == nil {
		t.Fatal("terminal but held fence admitted Run")
	}
	stop := statusRequest(request)
	stop.Operation = "stop"
	stop.Apply = true
	stop.ExecutionToken = observed.Execution.Token
	stopped, err := fresh.Stop(context.Background(), stop)
	if err != nil || stopped.Execution.FenceState != "released" {
		t.Fatalf("terminal stop=%+v %v", stopped.Execution, err)
	}
	if err := service.Acquire(context.Background(), request.StateRoot, host.AcquireRequest{SchemaVersion: 1, Claim: claim}); err != nil {
		t.Fatal("settled stop did not reopen Run admission", err)
	}
}
