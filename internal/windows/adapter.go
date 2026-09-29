package windows

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/capture"
	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/pairing"
	"github.com/BramVR/blender-box/internal/payload"
	sshtransport "github.com/BramVR/blender-box/internal/ssh"
	"github.com/BramVR/blender-box/internal/target"
)

type Adapter struct {
	ssh          SSH
	pollInterval time.Duration
}

func NewAdapter(ssh SSH) *Adapter {
	return &Adapter{ssh: ssh, pollInterval: 250 * time.Millisecond}
}

func (adapter *Adapter) Inspect(ctx context.Context, selected target.Target, requirements orchestrator.HostRequirements) (orchestrator.HostInspection, error) {
	result, err := Check(ctx, adapter.ssh, selected)
	var failure *sshtransport.Failure
	if errors.As(err, &failure) {
		return orchestrator.HostInspection{SchemaVersion: 1, Status: "fail", Problems: []orchestrator.HostProblem{{Class: string(failure.Class), Check: "ssh.connection", Message: failure.Detail, Next: failure.Next()}}}, nil
	}
	if err != nil {
		return orchestrator.HostInspection{}, err
	}
	if result.Status != "pass" {
		return orchestrator.HostInspection{SchemaVersion: 1, Status: "fail", Problems: checkProblems(result.Checks, selected.Windows().WorkRoot)}, nil
	}
	legacy := make([]orchestrator.CaptureSupport, 0, len(requirements.Captures))
	for _, kind := range requirements.Captures {
		if kind != capture.Viewport {
			legacy = nil
			break
		}
		definition, _ := capture.Describe(kind)
		legacy = append(legacy, orchestrator.CaptureSupport{Kind: kind, Capability: definition.Capability, Supported: true})
	}
	if requirements.PayloadSchemaVersion == 1 && legacy != nil {
		return orchestrator.HostInspection{SchemaVersion: 1, Status: "pass", Captures: legacy}, nil
	}
	var capabilities host.CapabilitiesResponse
	capabilityRequest := host.CapabilitiesRequest{SchemaVersion: 1}
	if requirements.UIActions {
		capabilityRequest.UIActions = true
		capabilityRequest.BlenderExecutable = selected.Windows().BlenderExecutable
		capabilityRequest.SessionBrokerExecutable = selected.Windows().SessionBrokerExecutable
	}
	if err := adapter.invokeJSON(ctx, selected, "capabilities", capabilityRequest, &capabilities); err != nil {
		return orchestrator.HostInspection{}, err
	}
	if err := validateCapabilities(capabilities); err != nil {
		return orchestrator.HostInspection{}, err
	}
	return orchestrator.HostInspection{SchemaVersion: 1, Status: "pass", Captures: capabilities.Captures, UIActions: capabilities.UIActions}, nil
}

var problemClassByCheck = map[string]string{
	"host.console-user":  "interactive-desktop-unavailable",
	"host.ssh-user":      "account-mismatch",
	"blender.executable": "runtime-incompatible",
	"daemon.executable":  "runtime-incompatible",
	"host.executable":    "runtime-incompatible",
}

var nextStepByProblemClass = map[string]string{
	"interactive-desktop-unavailable": "sign in to the host desktop as the target's interactive user and leave that session signed in",
	"account-mismatch":                "connect as the same Windows account that owns the interactive desktop, then pair or import that target again",
	"runtime-incompatible":            "on the host, run `blender-box setup inspect --platform windows --state-root STATE_ROOT` and reinstall the runtime it reports",
	"setup-incomplete":                "on the host, run `blender-box setup inspect --platform windows --state-root STATE_ROOT` and apply the reviewed plan",
}

func checkProblems(checks []CheckEvidence, stateRoot string) []orchestrator.HostProblem {
	var problems []orchestrator.HostProblem
	for _, check := range checks {
		if !check.Required || check.Passed {
			continue
		}
		class, known := problemClassByCheck[check.ID]
		if !known {
			class = "setup-incomplete"
		}
		problems = append(problems, orchestrator.HostProblem{Class: class, Check: check.ID, Message: check.Message, Next: strings.ReplaceAll(nextStepByProblemClass[class], "STATE_ROOT", stateRoot)})
	}
	return problems
}

// RevokePairing asks the host to remove exactly this pairing's key, authenticated by that key.
func (adapter *Adapter) RevokePairing(ctx context.Context, selected target.Target, request pairing.RevokeRequest) (pairing.RevokeResult, error) {
	var result json.RawMessage
	if err := adapter.invokeJSON(ctx, selected, "pair-revoke", request, &result); err != nil {
		return pairing.RevokeResult{}, err
	}
	return pairing.ParseRevokeResult(result, request.PairID)
}

// Probe opens a fresh paired SSH connection and runs a no-op command.
func (adapter *Adapter) Probe(ctx context.Context, selected target.Target) error {
	if err := selected.Validate(); err != nil {
		return err
	}
	if adapter.ssh == nil {
		return fmt.Errorf("SSH transport is unavailable")
	}
	_, err := adapter.ssh.Run(ctx, selected.Connection(), []string{"exit", "0"}, nil)
	return err
}

func validateCapabilities(result host.CapabilitiesResponse) error {
	if result.SchemaVersion != 1 || result.Status != "pass" || len(result.Captures) != len(capture.Definitions()) {
		return fmt.Errorf("host returned invalid capture capabilities")
	}
	seen := make(map[capture.Kind]struct{}, len(result.Captures))
	for _, support := range result.Captures {
		definition, exists := capture.Describe(support.Kind)
		if !exists || support.Capability != definition.Capability {
			return fmt.Errorf("host returned invalid capture capabilities")
		}
		if _, duplicate := seen[support.Kind]; duplicate {
			return fmt.Errorf("host returned duplicate capture capability %q", support.Kind)
		}
		seen[support.Kind] = struct{}{}
	}
	return nil
}

func (adapter *Adapter) Acquire(ctx context.Context, selected target.Target, claim orchestrator.LockClaim) error {
	var result host.Acknowledgement
	if err := adapter.invokeJSON(ctx, selected, "acquire", host.AcquireRequest{SchemaVersion: 1, Claim: claim}, &result); err != nil {
		return err
	}
	return validateAcknowledgement(result, "acquired")
}

func (adapter *Adapter) Stage(ctx context.Context, selected target.Target, claim orchestrator.LockClaim, loaded payload.Payload) error {
	if err := loaded.Validate(); err != nil {
		return err
	}
	request := host.StageRequest{SchemaVersion: 1, Claim: claim, Files: make([]host.StageFile, 0, len(loaded.Files))}
	for _, file := range loaded.Files {
		request.Files = append(request.Files, host.StageFile{
			Destination: file.Destination,
			Size:        file.Size,
			SHA256:      file.SHA256,
			Contents:    file.Contents(),
		})
	}
	var result host.Acknowledgement
	if err := adapter.invokeJSON(ctx, selected, "stage", request, &result); err != nil {
		return err
	}
	return validateAcknowledgement(result, "staged")
}

func (adapter *Adapter) Start(ctx context.Context, selected target.Target, request orchestrator.RunRequest) (orchestrator.RunReceipt, error) {
	var receipt orchestrator.RunReceipt
	if err := adapter.invokeJSON(ctx, selected, "start", request, &receipt); err != nil {
		return orchestrator.RunReceipt{}, err
	}
	if err := receipt.ValidateForClaim(request.Claim); err != nil {
		return receipt, fmt.Errorf("start receipt: %w", err)
	}
	for receipt.SessionID == "" {
		if terminalState(receipt.State) {
			return orchestrator.RunReceipt{}, fmt.Errorf("interactive task ended before returning a Session identity: %s", receipt.Error)
		}
		timer := time.NewTimer(adapter.pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return orchestrator.RunReceipt{}, ctx.Err()
		case <-timer.C:
		}
		var replayed orchestrator.RunReceipt
		if err := adapter.invokeJSON(ctx, selected, "start", request, &replayed); err != nil {
			return orchestrator.RunReceipt{}, err
		}
		if err := replayed.ValidateForClaim(request.Claim); err != nil {
			return replayed, fmt.Errorf("start receipt: %w", err)
		}
		receipt = replayed
	}
	return receipt, nil
}

func (adapter *Adapter) Observe(ctx context.Context, selected target.Target, runID orchestrator.RunID) (orchestrator.RunReceipt, error) {
	var receipt orchestrator.RunReceipt
	err := adapter.invokeJSON(ctx, selected, "status", host.StatusRequest{SchemaVersion: 1, RunID: runID}, &receipt)
	return receipt, err
}

func (adapter *Adapter) Fetch(ctx context.Context, selected target.Target, receipt orchestrator.RunReceipt, file orchestrator.EvidenceFile) ([]byte, error) {
	var response host.FetchResponse
	if err := adapter.invokeJSON(ctx, selected, "fetch", host.FetchRequest{SchemaVersion: 1, Receipt: receipt, File: file}, &response); err != nil {
		return nil, err
	}
	if response.SchemaVersion != 1 {
		return nil, fmt.Errorf("host fetch returned unsupported schema version %d", response.SchemaVersion)
	}
	return response.Contents, nil
}

func (adapter *Adapter) Settle(ctx context.Context, selected target.Target, receipt orchestrator.RunReceipt) (orchestrator.CleanupState, error) {
	var response host.SettleResponse
	if err := adapter.invokeJSON(ctx, selected, "settle", host.SettleRequest{
		SchemaVersion:           1,
		Receipt:                 receipt,
		SessionBrokerExecutable: selected.Windows().SessionBrokerExecutable,
		SessionName:             orchestrator.SessionNameForRun(receipt.Claim.RunID),
	}, &response); err != nil {
		return orchestrator.CleanupState{}, err
	}
	if response.SchemaVersion != 1 {
		return orchestrator.CleanupState{}, fmt.Errorf("host settle returned unsupported schema version %d", response.SchemaVersion)
	}
	return response.Cleanup, nil
}

func (adapter *Adapter) invokeJSON(ctx context.Context, selected target.Target, operation string, input any, output any) error {
	if selected.Platform() != "windows" {
		return fmt.Errorf("Windows command requires windows platform")
	}
	if err := selected.Validate(); err != nil {
		return err
	}
	if adapter.ssh == nil {
		return fmt.Errorf("SSH transport is unavailable")
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode host %s request: %w", operation, err)
	}
	script := fmt.Sprintf(
		"$ErrorActionPreference = 'Stop'\n& %s %s %s %s %s\nexit $LASTEXITCODE",
		powerShellLiteral(selected.Windows().HostExecutable),
		powerShellLiteral("host"),
		powerShellLiteral(operation),
		powerShellLiteral("--state-root"),
		powerShellLiteral(selected.Windows().WorkRoot),
	)
	arguments := []string{
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-EncodedCommand",
		encodePowerShell(script),
	}
	response, err := adapter.ssh.Run(ctx, selected.Connection(), arguments, encoded)
	if err != nil {
		return fmt.Errorf("host %s: %w", operation, err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(response)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return fmt.Errorf("decode host %s response: %w", operation, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode host %s response: trailing JSON value", operation)
		}
		return fmt.Errorf("decode host %s response: %w", operation, err)
	}
	return nil
}

func validateAcknowledgement(result host.Acknowledgement, expected string) error {
	if result.SchemaVersion != 1 || result.Status != expected {
		return fmt.Errorf("host returned invalid %s acknowledgement", expected)
	}
	return nil
}

func terminalState(state orchestrator.RunState) bool {
	switch state {
	case orchestrator.StateComplete, orchestrator.StateFailed, orchestrator.StateTimedOut, orchestrator.StateCleanupFailed:
		return true
	default:
		return false
	}
}
