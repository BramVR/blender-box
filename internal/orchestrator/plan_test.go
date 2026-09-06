package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/BramVR/blender-box/internal/capture"
	"github.com/BramVR/blender-box/internal/payload"
	"github.com/BramVR/blender-box/internal/target"
)

func TestPlanReturnsCanonicalCaptureAndEvidenceRequirements(t *testing.T) {
	loaded := loadCapturePayload(t)
	selected := target.Target{
		SchemaVersion:           1,
		SSHAlias:                "windows-test",
		SSHUser:                 "test-user",
		WorkRoot:                `C:\BlenderBoxTest`,
		InteractiveUser:         "test-user",
		TaskName:                "BlenderBoxTest",
		BlenderExecutable:       `C:\Program Files\Blender Foundation\Blender 5.2\blender.exe`,
		SessionBrokerExecutable: `C:\BlenderBoxTest\bin\blendersessiond.exe`,
		HostExecutable:          `C:\BlenderBoxTest\bin\blender-box.exe`,
	}

	plan, err := New(nil).Plan(PlanIntent{Target: selected, Payload: loaded})
	if err != nil {
		t.Fatal(err)
	}
	if plan.SchemaVersion != 1 || plan.Status != "pass" || plan.PayloadSchemaVersion != 2 || plan.FileCount != 1 {
		t.Fatalf("plan = %+v", plan)
	}
	wantKinds := []capture.Kind{capture.Viewport, capture.BlenderWindow, capture.Desktop}
	if len(plan.Captures) != len(wantKinds) {
		t.Fatalf("captures = %+v", plan.Captures)
	}
	for index, kind := range wantKinds {
		if plan.Captures[index].Kind != kind || plan.Captures[index].Path == "" || plan.Captures[index].Capability == "" {
			t.Fatalf("capture %d = %+v", index, plan.Captures[index])
		}
	}
	if !plan.Captures[2].PrivacySensitive {
		t.Fatal("desktop capture is not marked privacy-sensitive")
	}
	if len(plan.ExpectedEvidence) != 4 || plan.ExpectedEvidence[0] != EvidenceScenarioResult {
		t.Fatalf("expected evidence = %v", plan.ExpectedEvidence)
	}
}

func TestDoctorFailsWhenHostDoesNotSupportARequestedCapture(t *testing.T) {
	loaded := loadCapturePayload(t)
	selected := validPlanTarget()
	host := &fakeHost{inspection: HostInspection{
		SchemaVersion: 1,
		Status:        "pass",
		Captures: []CaptureSupport{
			{Kind: capture.Viewport, Capability: "capture-viewport-v1", Supported: true},
			{Kind: capture.BlenderWindow, Capability: "capture-blender-window-v1", Supported: true},
			{Kind: capture.Desktop, Capability: "capture-desktop-v1", Supported: false},
		},
	}}

	result, err := New(host).Doctor(context.Background(), PlanIntent{Target: selected, Payload: loaded})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "fail" || result.Plan.Status != "pass" || len(result.Host.Captures) != 3 {
		t.Fatalf("doctor = %+v", result)
	}
	if len(host.inspectCaptures) != 3 || host.inspectCaptures[2] != capture.Desktop {
		t.Fatalf("inspected captures = %v", host.inspectCaptures)
	}
}

func loadCapturePayload(t *testing.T) payload.Payload {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "scenario.py"), []byte("print('capture')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	document := `{"schema_version":2,"files":[{"source":"scenario.py","destination":"scenario.py"}],"scenario":{"script":"scenario.py","capture_viewport":true,"capture_blender_window":true,"capture_desktop":true}}`
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

func validPlanTarget() target.Target {
	return target.Target{
		SchemaVersion:           1,
		SSHAlias:                "windows-test",
		SSHUser:                 "test-user",
		WorkRoot:                `C:\BlenderBoxTest`,
		InteractiveUser:         "test-user",
		TaskName:                "BlenderBoxTest",
		BlenderExecutable:       `C:\Program Files\Blender Foundation\Blender 5.2\blender.exe`,
		SessionBrokerExecutable: `C:\BlenderBoxTest\bin\blendersessiond.exe`,
		HostExecutable:          `C:\BlenderBoxTest\bin\blender-box.exe`,
	}
}
