package windowsinstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/host"
)

type launcherMachine struct {
	machine
	taskCall func(context.Context, string, taskSpec) (taskObservation, error)
}

func (m launcherMachine) task(ctx context.Context, action string, spec taskSpec) (taskObservation, error) {
	return m.taskCall(ctx, action, spec)
}

// The fake Scheduler starts an independent keeper only after Run is submitted.
func scheduledOwnerFixture(t *testing.T, fault string) (*owner, *fakeMachine, Request, <-chan struct{}) {
	t.Helper()
	o, m, r := ownerFixture(t)
	var mu sync.Mutex
	var alive atomic.Bool
	o.alive = func(ProcessIdentity) (bool, error) { return alive.Load(), nil }
	workerDone := make(chan struct{})
	started := false
	t.Cleanup(func() {
		if started {
			select {
			case <-workerDone:
			case <-time.After(5 * time.Second):
				t.Error("fake scheduled keeper did not exit")
			}
		}
	})
	o.installer.machine = launcherMachine{machine: m, taskCall: func(ctx context.Context, action string, spec taskSpec) (taskObservation, error) {
		if spec.Marker == "" {
			return m.task(ctx, action, spec)
		}
		mu.Lock()
		defer mu.Unlock()
		task, err := m.task(ctx, action, spec)
		if err != nil {
			return task, err
		}
		if fault == action+"-response-lost" {
			return task, fmt.Errorf("lost %s response", action)
		}
		if action == "run" {
			started = true
			alive.Store(true)
			go func() {
				defer close(workerDone)
				defer alive.Store(false)
				var record executionRequest
				// Run's receipt publication races the scheduled action by design.
				claim, err := host.ReadSetupClaim(r.StateRoot)
				if err == nil {
					err = readExecutionJSON(filepath.Join(r.StateRoot, "setup-operations", string(r.OperationID), claim.ExecutionToken, "request.json"), &record)
				}
				if err != nil {
					t.Error(err)
					return
				}
				independent, cancel := context.WithDeadline(context.Background(), record.Deadline)
				defer cancel()
				if fault == "run-started-response-lost" {
					cancel()
				}
				release, err := o.admitKeeper(independent, record, ProcessIdentity{101, "1001"})
				if err != nil {
					if fault != "run-started-response-lost" || !errors.Is(err, context.Canceled) {
						t.Error(err)
					}
					return
				}
				_, _ = o.keepAdmitted(independent, record)
				release()
				mu.Lock()
				task := m.launchers[spec.Name]
				task.Running = false
				if fault == "replacement" {
					task.Fingerprint = digest([]byte("replacement"))
				}
				m.launchers[spec.Name] = task
				mu.Unlock()
			}()
		}
		if action == "run" && fault == "run-started-response-lost" {
			return task, fmt.Errorf("Run started but response was lost")
		}
		return task, nil
	}}
	o.schedule = o.launchExecution
	o.launch = func(ctx context.Context, request Request) (Result, error) { return o.keep(ctx, request) }
	return o, m, r, workerDone
}

func TestScheduledKeeperCompletesAndDeletesOnlyItsLauncher(t *testing.T) {
	o, m, r, _ := scheduledOwnerFixture(t, "")
	result, err := o.Execute(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if result.Completion != "known" || result.Execution.LauncherCleanup != "known" || result.Execution.FenceState != "released" {
		t.Fatalf("incomplete result: %+v", result.Execution)
	}
	if !m.current.Exists {
		t.Fatal("launcher cleanup deleted installation task")
	}
	if m.launchers[launcherName(result.Execution.Token)].Exists {
		t.Fatal("temporary launcher remained")
	}
	if err := host.RejectPendingSetup(r.StateRoot); err != nil {
		t.Fatal(err)
	}
}

func TestLauncherMutationAmbiguityNeverSettlesFromAbsence(t *testing.T) {
	for _, fault := range []string{"create-response-lost", "run-response-lost", "delete-response-lost", "replacement"} {
		t.Run(fault, func(t *testing.T) {
			o, m, r, _ := scheduledOwnerFixture(t, fault)
			result, err := o.Execute(context.Background(), r)
			if err == nil || result.Execution == nil || result.Completion != "unknown" || result.Execution.LauncherCleanup != "unknown" {
				t.Fatalf("result=%+v error=%v", result.Execution, err)
			}
			token := result.Execution.Token
			m.launchers[launcherName(token)] = taskObservation{}
			status, _ := o.Status(context.Background(), statusRequest(r))
			if status.Completion != "unknown" || status.Execution.FenceState != "held" {
				t.Fatal("absence settled launcher")
			}
			stop := statusRequest(r)
			stop.Operation = "stop"
			stop.Apply = true
			stop.ExecutionToken = token
			_, _ = o.Stop(context.Background(), stop)
			if host.RejectPendingSetup(r.StateRoot) == nil {
				t.Fatal("ambiguous launcher released fence")
			}
			again, _ := o.Execute(context.Background(), r)
			if again.Execution == nil || again.Execution.Token != token {
				t.Fatal("ambiguous launcher admitted successor")
			}
		})
	}
}

func admittedFixture(t *testing.T) (*owner, *fakeMachine, Request, executionRequest) {
	t.Helper()
	o, m, r := ownerFixture(t)
	var record executionRequest
	o.schedule = func(_ context.Context, received executionRequest) (Result, error) {
		record = received
		return received.Preview, nil
	}
	if _, err := o.Execute(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return o, m, r, record
}
func grantFixture(t *testing.T, o *owner, m *fakeMachine, r executionRequest) {
	t.Helper()
	task, err := m.task(context.Background(), "create", r.launcherTask())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = m.task(context.Background(), "run", r.launcherTask())
	for _, state := range []string{"submitted", "registered", "run-submitted", "started"} {
		hash := task.Fingerprint
		if state == "submitted" {
			hash = ""
		}
		if err := o.publishLauncher(r, state, hash, nil); err != nil {
			t.Fatal(err)
		}
	}
}
func TestKeeperRejectsMissingGrantExpiredAndDuplicateStarts(t *testing.T) {
	for _, fault := range []string{"missing-receipt", "expired", "duplicate", "changed-task", "cancelled", "input-changed"} {
		t.Run(fault, func(t *testing.T) {
			o, m, r, record := admittedFixture(t)
			self := ProcessIdentity{101, "1001"}
			if fault != "missing-receipt" {
				grantFixture(t, o, m, record)
			}
			switch fault {
			case "expired":
				record.Deadline = time.Now().Add(-time.Second)
			case "duplicate":
				if err := o.publishLauncher(record, "keeper", objectDigest(record.launcherTask()), &self); err != nil {
					t.Fatal(err)
				}
			case "changed-task":
				task := m.launchers[record.Launcher]
				task.Matches = false
				m.launchers[record.Launcher] = task
			case "cancelled":
				if err := publishExecutionJSON(filepath.Join(record.directory(), "cancel.json"), r.StateRoot, executionCancel{1, record.claim()}, nil); err != nil {
					t.Fatal(err)
				}
			case "input-changed":
				if err := os.WriteFile(record.Bootstrap.Path, []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			if fault == "missing-receipt" {
				cancel()
			} else {
				defer cancel()
			}
			release, err := o.admitKeeper(ctx, record, self)
			if err == nil {
				release()
				t.Fatal("invalid keeper admitted")
			}
			if _, err := os.Stat(filepath.Join(record.directory(), "ownership.json")); !os.IsNotExist(err) {
				t.Fatal("refused keeper owned worker")
			}
			if host.RejectPendingSetup(r.StateRoot) == nil {
				t.Fatal("refused keeper released fence")
			}
		})
	}
}
func TestWorkerTerminalRequiresExternalLauncherCleanup(t *testing.T) {
	o, m, r, record := admittedFixture(t)
	grantFixture(t, o, m, record)
	release, err := o.admitKeeper(context.Background(), record, ProcessIdentity{101, "1001"})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = o.keepAdmitted(context.Background(), record)
	release()
	status, err := o.Status(context.Background(), statusRequest(r))
	if err != nil {
		t.Fatal(err)
	}
	if status.Execution.TreeCleanup != "known" || status.Completion != "unknown" || status.Execution.LauncherCleanup != "unknown" {
		t.Fatalf("terminal prematurely settled: %+v", status.Execution)
	}
	stop := statusRequest(r)
	stop.Operation = "stop"
	stop.Apply = true
	stop.ExecutionToken = record.Token
	if _, err := o.Stop(context.Background(), stop); err == nil {
		t.Fatal("live keeper deleted")
	}
	o.alive = func(ProcessIdentity) (bool, error) { return false, nil }
	if _, err := o.Stop(context.Background(), stop); err == nil {
		t.Fatal("active task deleted")
	}
	task := m.launchers[record.Launcher]
	task.Running = false
	m.launchers[record.Launcher] = task
	stopped, err := o.Stop(context.Background(), stop)
	if err != nil {
		t.Fatal(err)
	}
	if stopped.Completion != "known" || stopped.Execution.LauncherCleanup != "known" || stopped.Execution.FenceState != "released" {
		t.Fatalf("cleanup incomplete: %+v", stopped.Execution)
	}
	if _, err := o.Stop(context.Background(), stop); err != nil {
		t.Fatal("settled stop not idempotent", err)
	}
}
func TestKeeperReceiptWaitHonorsCancellation(t *testing.T) {
	o, _, _, record := admittedFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := o.admitKeeper(ctx, record, ProcessIdentity{101, "1001"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("wait ignored cancellation: %v", err)
	}
}

func TestScheduledKeeperSurvivesWaitingCallerCancellation(t *testing.T) {
	o, m, r, done := scheduledOwnerFixture(t, "")
	owned, resume := make(chan struct{}), make(chan struct{})
	run := o.run
	o.run = func(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
		return run(ctx, record, func(identity executionOwnership) error {
			if err := publish(identity); err != nil {
				return err
			}
			close(owned)
			<-resume
			if err := ctx.Err(); err != nil {
				t.Errorf("caller cancelled independent keeper: %v", err)
			}
			return nil
		})
	}
	caller, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { _, err := o.Execute(caller, r); finished <- err }()
	select {
	case <-owned:
	case <-time.After(5 * time.Second):
		t.Fatal("keeper never owned worker")
	}
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation: %v", err)
	}
	close(resume)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("keeper did not finish after caller loss")
	}
	result, err := o.Status(context.Background(), statusRequest(r))
	if err != nil {
		t.Fatal(err)
	}
	if result.Completion != "unknown" || result.Execution.TreeCleanup != "known" || result.Execution.LauncherCleanup != "unknown" || result.Execution.FenceState != "held" {
		t.Fatalf("caller loss lost separate cleanup facts: %+v", result.Execution)
	}
	if !m.launchers[launcherName(result.Execution.Token)].Exists {
		t.Fatal("keeper deleted its launcher")
	}
	stop := statusRequest(r)
	stop.Operation = "stop"
	stop.Apply = true
	stop.ExecutionToken = result.Execution.Token
	final, err := o.Stop(context.Background(), stop)
	if err != nil {
		t.Fatal(err)
	}
	if final.Completion != "known" || final.Execution.FenceState != "released" || final.Execution.LauncherCleanup != "known" {
		t.Fatalf("reconnected cleanup: %+v", final.Execution)
	}
}

func TestStartedKeeperCannotAdmitWorkerAfterLostRunReceipt(t *testing.T) {
	o, _, r, done := scheduledOwnerFixture(t, "run-started-response-lost")
	result, err := o.Execute(context.Background(), r)
	if err == nil || result.Completion != "unknown" {
		t.Fatalf("Run loss: %+v %v", result, err)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("unreceipted keeper did not refuse")
	}
	observed, err := o.observe(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if observed.ownership != nil || observed.terminal != nil || observed.launcher["keeper"].State != "" || !observed.fenced {
		t.Fatal("unreceipted Run admitted worker or released fence")
	}
}
