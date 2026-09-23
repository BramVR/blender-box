package host

import (
	"context"
	"encoding/json"
	"github.com/BramVR/blender-box/internal/orchestrator"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMaintenanceNeverWaitsForLaunchUnderOperation(t *testing.T) {
	root := privateTempDir(t)
	release, err := acquireLaunch(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	called := false
	err = WithMaintenance(context.Background(), root, func() error { called = true; return nil })
	if err == nil || !strings.Contains(err.Error(), "launch-in-progress") || called {
		t.Fatalf("fence=%v called=%v", err, called)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	unlock, err := acquireOperation(ctx, root)
	if err != nil {
		t.Fatal("maintenance retained operation while launch held")
	}
	unlock()
}
func TestMaintenanceReadOnlyRefusesUnresolvedAuthority(t *testing.T) {
	root := filepath.Join(t.TempDir(), "absent")
	if err := InspectMaintenance(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("preview created root")
	}
	for _, name := range []string{"host-lock.json", "pending-request.json", "runs/unfinished", "receipts/corrupt.json"} {
		t.Run(name, func(t *testing.T) {
			root := privateTempDir(t)
			path := filepath.Join(root, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
			if err := InspectMaintenance(root); err == nil {
				t.Fatal("unresolved authority accepted")
			}
			if _, err := os.Stat(filepath.Join(root, ".operation.lock")); !os.IsNotExist(err) {
				t.Fatal("inspection created lock")
			}
		})
	}
}
func TestMaintenanceAcceptsOnlyFullySettledReceipt(t *testing.T) {
	root := privateTempDir(t)
	if err := os.Mkdir(filepath.Join(root, "receipts"), 0700); err != nil {
		t.Fatal(err)
	}
	claim := testHostClaim(time.Now(), "M")
	receipt := orchestrator.RunReceipt{SchemaVersion: 1, Claim: claim, State: orchestrator.StateComplete, Cleanup: orchestrator.CleanupState{SessionStopped: true, PayloadRemoved: true, RunRootRemoved: true, LockReleased: true}, Evidence: orchestrator.EvidenceManifest{SchemaVersion: 1, Files: []orchestrator.EvidenceFile{}}}
	data, _ := json.Marshal(receipt)
	path := filepath.Join(root, "receipts", string(claim.RunID)+".json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := InspectMaintenance(root); err != nil {
		t.Fatal(err)
	}
	receipt.Cleanup.LockReleased = false
	data, _ = json.Marshal(receipt)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := InspectMaintenance(root); err == nil {
		t.Fatal("unsettled receipt accepted without Host Lock")
	}
}

func TestPendingSetupFencesRunAdmissionAndUnrelatedMaintenance(t *testing.T) {
	root := privateTempDir(t)
	claim := SetupClaim{SchemaVersion: 1, InstallationID: "bbxi_" + strings.Repeat("a", 32), OperationID: "bbxo_" + strings.Repeat("b", 32), ExecutionToken: "bbxe_" + strings.Repeat("c", 32), RequestSHA256: strings.Repeat("d", 64), RootIdentity: "fake-root", OwnerSID: "fake-owner", Deadline: time.Now().Add(time.Minute).UTC()}
	if err := WithMaintenance(context.Background(), root, func() error { return PublishSetupClaim(root, claim) }); err != nil {
		t.Fatal(err)
	}
	service := NewService(Dependencies{})
	if err := service.Acquire(context.Background(), root, AcquireRequest{SchemaVersion: 1, Claim: testHostClaim(time.Now(), "S")}); err == nil {
		t.Fatal("pending setup admitted Run")
	}
	if err := WithMaintenance(context.Background(), root, func() error { t.Fatal("unrelated maintenance entered"); return nil }); err == nil {
		t.Fatal("pending setup admitted maintenance")
	}
	if err := WithSetupMaintenance(context.Background(), root, &claim, func() error { return nil }); err != nil {
		t.Fatal("exact worker denied", err)
	}
	changed := claim
	changed.ExecutionToken = "bbxe_" + strings.Repeat("e", 32)
	if err := WithSetupMaintenance(context.Background(), root, &changed, func() error { return nil }); err == nil {
		t.Fatal("foreign worker admitted")
	}
	if err := os.WriteFile(filepath.Join(root, "pending-setup.json"), []byte(`{"schema_version":1,"schema_version":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := service.Acquire(context.Background(), root, AcquireRequest{SchemaVersion: 1, Claim: testHostClaim(time.Now(), "T")}); err == nil {
		t.Fatal("malformed setup fence admitted Run")
	}
	if err := InspectMaintenance(root); err == nil {
		t.Fatal("malformed setup fence appeared ready")
	}
}

func TestPendingSetupFencesValidatedPendingRunsOnBothPlatforms(t *testing.T) {
	for _, platform := range []string{"windows", "linux"} {
		t.Run(platform, func(t *testing.T) {
			root := privateTempDir(t)
			daemon := &fakeDaemon{}
			service := NewService(Dependencies{Platform: platform, Tasks: &fakeTaskLauncher{}, Daemon: daemon})
			request := stageHostTestRun(t, service, root, time.Now().UTC(), false)
			if _, err := service.Start(context.Background(), root, request); err != nil {
				t.Fatal(err)
			}
			before := mustRead(t, receiptPath(root, request.Claim.RunID))
			if err := os.WriteFile(filepath.Join(root, "pending-setup.json"), []byte(`{}`), 0600); err != nil {
				t.Fatal(err)
			}
			if err := service.ExecutePending(context.Background(), root); err == nil || !strings.Contains(err.Error(), "active or unresolved setup execution") {
				t.Fatalf("pending setup fence: %v", err)
			}
			if len(daemon.starts) != 0 {
				t.Fatal("pending setup allowed daemon launch")
			}
			if string(before) != string(mustRead(t, receiptPath(root, request.Claim.RunID))) {
				t.Fatal("pending setup refusal changed Run receipt")
			}
		})
	}
}
