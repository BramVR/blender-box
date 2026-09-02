package orchestrator

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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
	viewportPNG := []byte("fake-png-evidence")
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
		Payload: payload.Payload{
			SchemaVersion: 1,
			Scenario: payload.Scenario{
				Script:             "scenario.py",
				ReadTimeoutSeconds: 600,
				CaptureViewport:    true,
			},
		},
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
}

func evidenceFile(path string, kind string, content []byte) EvidenceFile {
	hash := sha256.Sum256(content)
	return EvidenceFile{
		Path:   path,
		Type:   kind,
		Size:   int64(len(content)),
		SHA256: fmt.Sprintf("%x", hash),
	}
}
