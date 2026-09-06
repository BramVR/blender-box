package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/capture"
	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/uiaction"
	"github.com/BramVR/blender-box/internal/windows"
)

func recoverySSH(t *testing.T, call func(string, []byte) ([]byte, error)) *fakeSSH {
	t.Helper()
	return &fakeSSH{runResult: func(arguments []string, input []byte) ([]byte, error) {
		command := decodePowerShellCommand(t, arguments)
		for _, name := range []string{"capabilities", "acquire", "stage", "start", "status", "fetch", "settle"} {
			if strings.Contains(command, "'host' '"+name+"'") {
				return call(name, input)
			}
		}
		return call("check", input)
	}}
}

func recoveryCapabilities() ([]byte, error) {
	response := host.CapabilitiesResponse{SchemaVersion: 1, Status: "pass", UIActions: &orchestrator.UIActionSupport{Capability: uiaction.Capability, Supported: true}}
	for _, definition := range capture.Definitions() {
		response.Captures = append(response.Captures, orchestrator.CaptureSupport{Kind: definition.Kind, Capability: definition.Capability, Supported: true})
	}
	return json.Marshal(response)
}

func recoveryUIPayload(t *testing.T) string {
	t.Helper()
	path := cliPayload(t)
	if err := os.WriteFile(path, []byte(`{"schema_version":3,"files":[{"source":"scenario.py","destination":"scenario.py"}],"scenario":{"script":"scenario.py","capture_blender_window":true,"ui_actions":{"schema_version":1,"timeout_seconds":10,"actions":[{"type":"text","text":"test"}]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunJSONRetainsMalformedRecoverySession(t *testing.T) {
	for _, at := range []string{"start", "recovery"} {
		for _, pin := range []string{"missing", "same", "different"} {
			t.Run(at+"-"+pin, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "private")
				t.Setenv("BLENDER_BOX_CONFIG_DIR", root)
				targetPath := writeTarget(t, t.TempDir())
				selected, err := target.Load(targetPath)
				if err != nil {
					t.Fatal(err)
				}
				var runner *orchestrator.Runner
				var receipt orchestrator.RunReceipt
				var operations []string
				pinning := false
				malformed := func() ([]byte, error) {
					observed := receipt
					if pin != "missing" {
						if pin == "different" {
							receipt.SessionID = "bss_concurrent-other-session-123456"
						}
						pinning = true
						_, err := runner.Status(context.Background(), selected, receipt.Claim.RunID)
						pinning = false
						if err != nil {
							t.Fatal(err)
						}
					}
					observed.SchemaVersion = 99
					return json.Marshal(observed)
				}
				ssh := recoverySSH(t, func(operation string, input []byte) ([]byte, error) {
					label := operation
					if pinning {
						label = "concurrent-status"
					}
					operations = append(operations, label)
					switch operation {
					case "check":
						return passingChecks(), nil
					case "capabilities":
						return recoveryCapabilities()
					case "acquire", "stage":
						return json.Marshal(host.Acknowledgement{SchemaVersion: 1, Status: map[string]string{"acquire": "acquired", "stage": "staged"}[operation]})
					case "start":
						var request orchestrator.RunRequest
						if err := json.Unmarshal(input, &request); err != nil {
							t.Fatal(err)
						}
						receipt = orchestrator.RunReceipt{SchemaVersion: 1, Claim: request.Claim, State: orchestrator.StateRunning, SessionID: "bss_observed-recovery-session-123456"}
						if at == "start" {
							return malformed()
						}
						return nil, errors.New("Start transport failed")
					case "status":
						if pinning || receipt.Cleanup.Known() || at == "start" {
							return json.Marshal(receipt)
						}
						return malformed()
					case "settle":
						var request host.SettleRequest
						if err := json.Unmarshal(input, &request); err != nil {
							t.Fatal(err)
						}
						if request.Receipt.SessionID != receipt.SessionID {
							t.Errorf("settlement lost observed Session: %q", request.Receipt.SessionID)
						}
						receipt.Cleanup = orchestrator.CleanupState{SessionStopped: true, PayloadRemoved: true, RunRootRemoved: true, LockReleased: true}
						receipt.State = orchestrator.StateFailed
						return json.Marshal(host.SettleResponse{SchemaVersion: 1, Cleanup: receipt.Cleanup})
					}
					return nil, errors.New("unexpected operation")
				})
				runner = orchestrator.New(windows.NewAdapter(ssh), root)
				payloadPath := cliPayload(t)
				want := []string{"check"}
				if at == "recovery" {
					payloadPath = recoveryUIPayload(t)
					want = append(want, "capabilities")
				}
				want = append(want, "acquire", "stage", "start")
				if at == "recovery" {
					want = append(want, "status")
				}
				if pin != "missing" {
					want = append(want, "concurrent-status")
				}
				if pin == "same" {
					want = append(want, "settle", "status")
				}
				var stdout, stderr bytes.Buffer
				code := Run(context.Background(), []string{"run", "--target", targetPath, "--payload", payloadPath, "--evidence-dir", filepath.Join(t.TempDir(), "evidence"), "--json"}, strings.NewReader(""), &stdout, &stderr, Dependencies{Runner: runner})
				var result orchestrator.RunResult
				if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if code != 1 || !slices.Equal(operations, want) || strings.Contains(result.Error, "insufficient recovery authority") != (pin != "same") || (pin == "same" && !result.Cleanup.Known()) {
					t.Fatalf("code=%d operations=%v result=%+v stderr=%s", code, operations, result, &stderr)
				}
				if pin == "missing" {
					if _, err := os.Stat(filepath.Join(root, "runs", string(result.RunID)+".session.json")); !os.IsNotExist(err) {
						t.Fatalf("malformed receipt published pin: %v", err)
					}
				}
			})
		}
	}
}

func TestRunJSONDoesNotRepinAfterDeferredSettlement(t *testing.T) {
	for _, losePin := range []bool{false, true} {
		for _, hostFails := range []bool{false, true} {
			t.Run(fmt.Sprintf("lost-%t-error-%t", losePin, hostFails), func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "private")
				t.Setenv("BLENDER_BOX_CONFIG_DIR", root)
				var receipt orchestrator.RunReceipt
				var operations []string
				ssh := recoverySSH(t, func(operation string, input []byte) ([]byte, error) {
					operations = append(operations, operation)
					switch operation {
					case "check":
						return passingChecks(), nil
					case "acquire", "stage":
						return json.Marshal(host.Acknowledgement{SchemaVersion: 1, Status: map[string]string{"acquire": "acquired", "stage": "staged"}[operation]})
					case "start":
						var request orchestrator.RunRequest
						if err := json.Unmarshal(input, &request); err != nil {
							t.Fatal(err)
						}
						receipt = orchestrator.RunReceipt{SchemaVersion: 1, Claim: request.Claim, State: orchestrator.StateRunning, SessionID: "bss_deferred-settle-session-123456"}
						return json.Marshal(receipt)
					case "status":
						receipt.State = orchestrator.StateComplete
						digest := sha256.Sum256([]byte(`{}`))
						receipt.Evidence = orchestrator.EvidenceManifest{SchemaVersion: 1, Files: []orchestrator.EvidenceFile{{Path: "scenario-result.json", Type: orchestrator.EvidenceScenarioResult, Size: 2, SHA256: fmt.Sprintf("%x", digest)}}}
						return json.Marshal(receipt)
					case "fetch":
						return nil, errors.New("evidence fetch failed")
					case "settle":
						if losePin {
							if err := os.Remove(filepath.Join(root, "runs", string(receipt.Claim.RunID)+".session.json")); err != nil {
								t.Fatal(err)
							}
						}
						if hostFails {
							return nil, errors.New("settlement transport failed")
						}
						receipt.Cleanup = orchestrator.CleanupState{SessionStopped: true, PayloadRemoved: true, RunRootRemoved: true, LockReleased: true}
						return json.Marshal(host.SettleResponse{SchemaVersion: 1, Cleanup: receipt.Cleanup})
					}
					return nil, errors.New("unexpected operation")
				})
				var stdout, stderr bytes.Buffer
				code := Run(context.Background(), []string{"run", "--target", writeTarget(t, t.TempDir()), "--payload", cliPayload(t), "--evidence-dir", filepath.Join(t.TempDir(), "evidence"), "--json"}, strings.NewReader(""), &stdout, &stderr, Dependencies{Runner: orchestrator.New(windows.NewAdapter(ssh), root)})
				want := []string{"check", "acquire", "stage", "start", "status", "fetch", "settle"}
				if !losePin {
					want = append(want, "status")
				}
				if code != 1 || !slices.Equal(operations, want) || strings.Contains(stdout.String(), "insufficient recovery authority") != losePin || !strings.Contains(stdout.String(), "evidence fetch failed") || strings.Contains(stdout.String(), "settlement transport failed") != hostFails {
					t.Fatalf("code=%d operations=%v stdout=%s stderr=%s", code, operations, &stdout, &stderr)
				}
				if losePin {
					if _, err := os.Stat(filepath.Join(root, "runs", string(receipt.Claim.RunID)+".session.json")); !os.IsNotExist(err) {
						t.Fatalf("failed JSON recovery recreated pin: %v", err)
					}
				}
			})
		}
	}
}

func TestRunJSONPinsValidStartBeforeUIBatchMismatch(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private")
	t.Setenv("BLENDER_BOX_CONFIG_DIR", root)
	var receipt orchestrator.RunReceipt
	var operations []string
	ssh := recoverySSH(t, func(operation string, input []byte) ([]byte, error) {
		operations = append(operations, operation)
		switch operation {
		case "check":
			return passingChecks(), nil
		case "capabilities":
			return recoveryCapabilities()
		case "acquire", "stage":
			return json.Marshal(host.Acknowledgement{SchemaVersion: 1, Status: map[string]string{"acquire": "acquired", "stage": "staged"}[operation]})
		case "start":
			var request orchestrator.RunRequest
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			receipt = orchestrator.RunReceipt{SchemaVersion: 1, Claim: request.Claim, State: orchestrator.StateRunning, SessionID: "bss_ui-mismatch-session-123456"}
			receipt.UIActions = &uiaction.Journal{SchemaVersion: 1, Receipts: []uiaction.Receipt{{Index: 0, Kind: uiaction.Click, Outcome: uiaction.Pending, SessionID: string(receipt.SessionID)}}}
			return json.Marshal(receipt)
		case "status":
			if receipt.Cleanup.Known() {
				return json.Marshal(receipt)
			}
			if _, err := os.Stat(filepath.Join(root, "runs", string(receipt.Claim.RunID)+".session.json")); err != nil {
				t.Errorf("valid Start identity was not pinned before UI semantic failure: %v", err)
			}
			return nil, errors.New("recovery transport failed")
		case "settle":
			var request host.SettleRequest
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			if request.Receipt.SessionID != receipt.SessionID {
				t.Errorf("UI semantic failure lost Session: %q", request.Receipt.SessionID)
			}
			receipt.Cleanup = orchestrator.CleanupState{SessionStopped: true, PayloadRemoved: true, RunRootRemoved: true, LockReleased: true}
			receipt.State = orchestrator.StateFailed
			return json.Marshal(host.SettleResponse{SchemaVersion: 1, Cleanup: receipt.Cleanup})
		}
		return nil, errors.New("unexpected operation")
	})
	var stdout, stderr bytes.Buffer
	code := Run(context.Background(), []string{"run", "--target", writeTarget(t, t.TempDir()), "--payload", recoveryUIPayload(t), "--evidence-dir", filepath.Join(t.TempDir(), "evidence"), "--json"}, strings.NewReader(""), &stdout, &stderr, Dependencies{Runner: orchestrator.New(windows.NewAdapter(ssh), root)})
	var result orchestrator.RunResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if code != 1 || !slices.Equal(operations, []string{"check", "capabilities", "acquire", "stage", "start", "status", "settle", "status"}) || !result.Cleanup.Known() || !strings.Contains(result.Error, "UI action differs from declared batch") {
		t.Fatalf("code=%d operations=%v result=%+v stderr=%s", code, operations, result, &stderr)
	}
}
