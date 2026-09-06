package linux

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/capture"
	"github.com/BramVR/blender-box/internal/linuxruntime"
	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/uiaction"
)

func TestLinuxPlanAndDoctorReturnTypedViewportSupport(t *testing.T) {
	ready := linuxruntime.CheckResult{SchemaVersion: 1, Status: "pass", BlenderVersion: "5.2.0"}
	for _, id := range []string{"host.linux", "host.desktop", "daemon.runtime", "host.unit", "work-root.access", "blender.executable"} {
		ready.Checks = append(ready.Checks, linuxruntime.CheckEvidence{ID: id, Required: true, Passed: true})
	}
	encoded, err := json.Marshal(ready)
	if err != nil {
		t.Fatal(err)
	}
	for _, schema := range []int{1, 2} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			ssh := &recordingSSH{output: encoded}
			runner := orchestrator.New(NewAdapter(ssh), filepath.Join(t.TempDir(), "private"))
			loaded := scenarioPayload(t)
			loaded.SchemaVersion = schema
			intent := orchestrator.PlanIntent{Target: linuxTarget(t), Payload: loaded}
			plan, err := runner.Plan(intent)
			if err != nil || plan.Status != "pass" || plan.PayloadSchemaVersion != schema || len(plan.Captures) != 1 || plan.Captures[0].Kind != capture.Viewport || ssh.calls != 0 {
				t.Fatalf("viewport plan: %+v %v, contacts=%d", plan, err, ssh.calls)
			}
			result, err := runner.Doctor(context.Background(), intent)
			if err != nil || result.SchemaVersion != 1 || result.Status != "pass" || result.Host.SchemaVersion != 1 || len(result.Host.Captures) != 3 || ssh.calls != 1 {
				t.Fatalf("viewport diagnosis: %+v %v, contacts=%d", result, err, ssh.calls)
			}
			for _, support := range result.Host.Captures {
				if support.Supported != (support.Kind == capture.Viewport) {
					t.Fatalf("incorrect Linux support: %+v", support)
				}
			}
		})
	}
}

func TestLinuxUnsupportedRequirementsRefuseBeforeHostContact(t *testing.T) {
	for _, kind := range []string{"blender-window", "desktop", "ui-actions"} {
		t.Run(kind, func(t *testing.T) {
			loaded := scenarioPayload(t)
			loaded.SchemaVersion = 2
			requirements := orchestrator.HostRequirements{PayloadSchemaVersion: 2}
			switch kind {
			case "blender-window":
				loaded.Scenario.CaptureBlenderWindow = true
				requirements.Captures = []capture.Kind{capture.BlenderWindow}
			case "desktop":
				loaded.Scenario.CaptureDesktop = true
				requirements.Captures = []capture.Kind{capture.Desktop}
			case "ui-actions":
				loaded.SchemaVersion = 3
				var batch uiaction.Batch
				if err := json.Unmarshal([]byte(`{"schema_version":1,"timeout_seconds":5,"actions":[{"type":"key","key":"A"}]}`), &batch); err != nil {
					t.Fatal(err)
				}
				loaded.Scenario.UIActions = &batch
				requirements.UIActions = true
			}
			if err := loaded.Validate(); err != nil {
				t.Fatal(err)
			}
			ssh := &recordingSSH{}
			adapter := NewAdapter(ssh)
			runner := orchestrator.New(adapter, filepath.Join(t.TempDir(), "private"))
			selected := linuxTarget(t)
			intent := orchestrator.PlanIntent{Target: selected, Payload: loaded}
			_, planErr := runner.Plan(intent)
			_, doctorErr := runner.Doctor(context.Background(), intent)
			_, inspectErr := adapter.Inspect(context.Background(), selected, requirements)
			_, runErr := runner.Run(context.Background(), orchestrator.RunIntent{
				RunID: "bbx_unsupported-linux-run-123456", RequestID: "req_unsupported-linux-request-123456",
				ControllerID: "fake-controller", Deadline: time.Now().Add(time.Minute).UTC(),
				Target: selected, Payload: loaded, EvidenceDir: filepath.Join(t.TempDir(), "evidence"),
			})
			for command, err := range map[string]error{"plan": planErr, "doctor": doctorErr, "inspect": inspectErr, "run": runErr} {
				if err == nil || !strings.Contains(err.Error(), "Linux targets do not support") {
					t.Fatalf("%s accepted unsupported %s: %v", command, kind, err)
				}
			}
			if !orchestrator.IsPreflightError(runErr) || ssh.calls != 0 {
				t.Fatalf("unsupported request crossed preflight: %v, contacts=%d", runErr, ssh.calls)
			}
		})
	}
}

func TestLinuxStartRetainsOnlyFullyDecodedNegativeSessionAuthority(t *testing.T) {
	claim := orchestrator.LockClaim{SchemaVersion: 1, RunID: "bbx_linux-start-receipt-123456", RequestID: "req_linux-start-receipt-123456", ControllerID: "fake-controller", Deadline: time.Now().Add(time.Minute).UTC(), RequestHash: strings.Repeat("a", 64), TaskName: "blender-box.service"}
	for _, replay := range []bool{false, true} {
		for _, malformed := range []string{"schema", "ui-journal", "unknown-field", "trailing-json"} {
			t.Run(fmt.Sprintf("%s-replay-%t", malformed, replay), func(t *testing.T) {
				receipt := orchestrator.RunReceipt{SchemaVersion: 1, Claim: claim, State: orchestrator.StateRunning, SessionID: "bss_linux-observed-session-123456"}
				if malformed == "schema" {
					receipt.SchemaVersion = 99
				} else if malformed == "ui-journal" {
					receipt.UIActions = &uiaction.Journal{SchemaVersion: 99}
				}
				data, err := json.Marshal(receipt)
				if err != nil {
					t.Fatal(err)
				}
				if malformed == "unknown-field" {
					data = append(data[:len(data)-1], []byte(`,"unknown":true}`)...)
				} else if malformed == "trailing-json" {
					data = append(data, []byte(` {}`)...)
				}
				ssh := &recordingSSH{}
				ssh.hook = func([]byte) []byte {
					if replay && ssh.calls == 1 {
						starting, _ := json.Marshal(orchestrator.RunReceipt{SchemaVersion: 1, Claim: claim, State: orchestrator.StateStarting})
						return starting
					}
					return data
				}
				adapter := NewAdapter(ssh)
				adapter.pollInterval = 0
				observed, err := adapter.Start(context.Background(), linuxTarget(t), orchestrator.RunRequest{Claim: claim})
				if err == nil {
					t.Fatal("malformed receipt accepted")
				}
				if malformed == "schema" || malformed == "ui-journal" {
					if !observed.Claim.Equal(claim) || observed.SessionID != receipt.SessionID {
						t.Fatalf("fully decoded negative authority lost: %+v %v", observed, err)
					}
				} else if observed.Claim != (orchestrator.LockClaim{}) || observed.SessionID != "" {
					t.Fatalf("partial authority escaped: %+v %v", observed, err)
				}
			})
		}
	}
}
