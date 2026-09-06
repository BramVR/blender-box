package linux

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/capture"
	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/payload"
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
	if requirements.UIActions {
		return orchestrator.HostInspection{}, fmt.Errorf("Linux targets do not support UI actions")
	}
	for _, kind := range requirements.Captures {
		if kind != capture.Viewport {
			return orchestrator.HostInspection{}, fmt.Errorf("Linux targets do not support %s capture", kind)
		}
	}
	result, err := Check(ctx, adapter.ssh, selected)
	if err != nil {
		return orchestrator.HostInspection{}, err
	}
	if result.Status != "pass" {
		var failures []string
		for _, check := range result.Checks {
			if check.Required && !check.Passed {
				failures = append(failures, check.ID+": "+check.Message)
			}
		}
		return orchestrator.HostInspection{}, fmt.Errorf("Linux host check failed: %s", strings.Join(failures, "; "))
	}
	inspection := orchestrator.HostInspection{SchemaVersion: 1, Status: result.Status}
	for _, definition := range capture.Definitions() {
		inspection.Captures = append(inspection.Captures, orchestrator.CaptureSupport{Kind: definition.Kind, Capability: definition.Capability, Supported: result.Status == "pass" && definition.Kind == capture.Viewport})
	}
	return inspection, nil
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
			return orchestrator.RunReceipt{}, fmt.Errorf("Linux service ended before returning a Session identity: %s", receipt.Error)
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
	runtime := selected.Linux().Daemon
	var response host.SettleResponse
	if err := adapter.invokeJSON(ctx, selected, "settle", host.SettleRequest{
		SchemaVersion:           2,
		Linux:                   &runtime,
		Receipt:                 receipt,
		SessionBrokerExecutable: selected.Linux().Daemon.PythonExecutable,
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
	if selected.Platform() != "linux" {
		return fmt.Errorf("Linux command requires linux platform")
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
	arguments := []string{Quote(selected.Linux().HostExecutable) + " host " + Quote(operation) + " --state-root " + Quote(selected.Linux().WorkRoot)}
	response, err := adapter.ssh.Run(ctx, selected.SSHAlias(), arguments, encoded)
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

func Quote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
