package windowsinstall

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/host"
)

func TestExecutionPublicationReceiptFailureRecovery(t *testing.T) {
	for _, test := range []struct {
		name, fault string
		treeExited  bool
	}{
		{"missing-target", "missing", true},
		{"changed-target", "changed", true},
		{"missing-tree-exit", "missing", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			owner, machine, request := ownerFixture(t)
			if err := os.Chmod(filepath.Dir(request.StateRoot), 0700); err != nil {
				t.Fatal(err)
			}
			request.TargetOut = filepath.Join(filepath.Dir(request.StateRoot), "target.json")
			request.ExpectedPlan = ""
			changed := []byte("operator changed destination\n")
			var wantError string
			run := owner.run
			owner.run = func(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
				outcome, exit, err := run(ctx, record, publish)
				if err != nil || outcome.Result.TargetPublication.Status != "published" || outcome.PublicationFile == nil {
					t.Fatalf("initial publication=%+v error=%v", outcome.Result.TargetPublication, err)
				}
				if test.fault == "missing" {
					if err := os.Remove(record.Request.TargetOut); err != nil {
						t.Fatal(err)
					}
					_, missing := os.Lstat(record.Request.TargetOut)
					if !os.IsNotExist(missing) {
						t.Fatal("target still exists", missing)
					}
					wantError = missing.Error()
				} else {
					if err := os.WriteFile(record.Request.TargetOut, changed, 0600); err != nil {
						t.Fatal(err)
					}
					wantError = "owned file changed bytes: " + record.Request.TargetOut
				}
				before := outcome.Result
				outcome.inspectPublication(record.Request)
				if outcome.Result.TargetPublication.Status != "failed" || outcome.Result.TargetPublication.Error != wantError || outcome.Error != wantError || outcome.PublicationFile != nil {
					t.Errorf("receipt failure publication=%+v receipt=%+v error=%q", outcome.Result.TargetPublication, outcome.PublicationFile, outcome.Error)
				}
				unchanged := outcome.Result
				unchanged.TargetPublication = before.TargetPublication
				if !reflect.DeepEqual(before, unchanged) || outcome.Result.State != "installed" || outcome.Result.Completion != "known" || outcome.TaskMutation != "settled" {
					t.Error("receipt inspection changed installation or task facts")
				}
				if err := validateWorkerOutcome(record, outcome); err != nil {
					t.Error("classified receipt failure rejected", err)
				}
				if !test.treeExited {
					exit = nil
				}
				return outcome, exit, err
			}
			failed, err := owner.Execute(context.Background(), request)
			if err == nil || err.Error() != wantError || failed.State != "installed" || failed.TargetPublication.Status != "failed" || failed.TargetPublication.Error != wantError || failed.Execution == nil || failed.Execution.TaskMutation != "settled" {
				t.Fatalf("receipt failure state=%s publication=%+v execution=%+v error=%v", failed.State, failed.TargetPublication, failed.Execution, err)
			}
			fresh := newOwner(machine)
			observed, err := fresh.Status(context.Background(), statusRequest(request))
			if err == nil || err.Error() != wantError || observed.State != failed.State || observed.Completion != failed.Completion || observed.TargetPublication != failed.TargetPublication || !reflect.DeepEqual(observed.Execution, failed.Execution) {
				t.Fatalf("fresh status state=%s publication=%+v execution=%+v error=%v", observed.State, observed.TargetPublication, observed.Execution, err)
			}
			owner.run = run
			if !test.treeExited {
				if failed.Completion != "unknown" || failed.Execution.TreeCleanup != "unknown" || failed.Execution.FenceState != "held" || host.RejectPendingSetup(request.StateRoot) == nil {
					t.Fatalf("missing tree proof released authority: %+v", failed.Execution)
				}
				fencePath := filepath.Join(request.StateRoot, "pending-setup.json")
				before, err := os.ReadFile(fencePath)
				if err != nil {
					t.Fatal(err)
				}
				machine.taskCalls = nil
				again, err := owner.Execute(context.Background(), request)
				if err == nil || err.Error() != wantError || again.Execution == nil || again.Execution.Token != failed.Execution.Token || len(machine.taskCalls) != 0 {
					t.Fatalf("unsettled publication retried: %+v %v", again.Execution, err)
				}
				after, err := os.ReadFile(fencePath)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("unsettled retry changed pending fence", err)
				}
				return
			}
			if failed.Completion != "known" || failed.Execution.TreeCleanup != "known" || failed.Execution.FenceState != "released" {
				t.Fatalf("settled receipt failure lost cleanup: %+v", failed.Execution)
			}
			if err := host.RejectPendingSetup(request.StateRoot); err != nil {
				t.Fatal("settled receipt failure retained fence", err)
			}
			receiptPath := filepath.Join(request.StateRoot, "installations", string(request.InstallationID), "receipt.json")
			before, err := readReceipt(receiptPath)
			if err != nil {
				t.Fatal(err)
			}
			machine.taskCalls = nil
			retried, retryErr := owner.Execute(context.Background(), request)
			if retried.State != "installed" || retried.Completion != "known" || retried.Execution == nil || retried.Execution.Token == failed.Execution.Token || retried.InstallationID != failed.InstallationID || retried.OperationID != failed.OperationID {
				t.Fatalf("receipt retry state=%s publication=%+v execution=%+v error=%v", retried.State, retried.TargetPublication, retried.Execution, retryErr)
			}
			after, err := readReceipt(receiptPath)
			if err != nil {
				t.Fatal(err)
			}
			if before.InstallationID != after.InstallationID || before.OperationID != after.OperationID || before.RootIdentity != after.RootIdentity || before.IntentSHA256 != after.IntentSHA256 || before.TaskFingerprint != after.TaskFingerprint || !reflect.DeepEqual(before.Files, after.Files) {
				t.Fatal("receipt retry changed installation authority or runtime identities")
			}
			for _, action := range machine.taskCalls {
				if action != "inspect" {
					t.Fatalf("receipt retry mutated task: %s", action)
				}
			}
			if test.fault == "missing" {
				if retryErr != nil || retried.TargetPublication.Status != "published" {
					t.Fatalf("missing target not republished: %+v %v", retried.TargetPublication, retryErr)
				}
				if _, err := publicationFile(request, retried); err != nil {
					t.Fatal("republished target differs from result", err)
				}
			} else {
				if retryErr == nil || retried.TargetPublication.Status != "failed" {
					t.Fatalf("changed target adopted: %+v %v", retried.TargetPublication, retryErr)
				}
				data, err := os.ReadFile(request.TargetOut)
				if err != nil || !bytes.Equal(data, changed) {
					t.Fatal("retry overwrote changed target", err)
				}
			}
		})
	}
}

func TestExecutionPublishedWithoutReceiptRetainsFence(t *testing.T) {
	owner, _, request := ownerFixture(t)
	if err := os.Chmod(filepath.Dir(request.StateRoot), 0700); err != nil {
		t.Fatal(err)
	}
	request.TargetOut = filepath.Join(filepath.Dir(request.StateRoot), "target.json")
	request.ExpectedPlan = ""
	run := owner.run
	owner.run = func(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
		outcome, exit, err := run(ctx, record, publish)
		if err != nil || outcome.Result.TargetPublication.Status != "published" || outcome.PublicationFile == nil {
			t.Fatalf("initial publication=%+v %v", outcome.Result.TargetPublication, err)
		}
		outcome.PublicationFile = nil
		return outcome, exit, err
	}
	result, err := owner.Execute(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "invalid target publication receipt") || result.State != "unknown" || result.Completion != "unknown" || result.Execution == nil || result.Execution.TaskMutation != "unknown" || result.Execution.FenceState != "held" {
		t.Fatalf("malformed publication accepted: state=%s execution=%+v error=%v", result.State, result.Execution, err)
	}
	if err := host.RejectPendingSetup(request.StateRoot); err == nil {
		t.Fatal("malformed published outcome released fence")
	}
}
