package windows

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/target"
)

const (
	setupOwnerOperationRevision = "windows-setup-owner-v1"
	setupOwnerStateDirectory    = "setup-owner"
	setupOwnerDeadline          = 4 * time.Minute
	setupOwnerPollInterval      = 100 * time.Millisecond
	maxSetupOwnerResponse       = 256 << 10
)

type setupOwnerRequest struct {
	SchemaVersion     int                      `json:"schema_version"`
	AttemptID         string                   `json:"attempt_id"`
	LaunchID          string                   `json:"launch_id"`
	DeadlineUTC       time.Time                `json:"deadline_utc"`
	OperationRevision string                   `json:"operation_revision"`
	Script            setupOwnerScriptArtifact `json:"script"`
}

type setupOwnerScriptArtifact struct {
	ArtifactID string `json:"artifact_id"`
	Size       int    `json:"size"`
	SHA256     string `json:"sha256"`
}

type setupOwnerView struct {
	SchemaVersion   int                `json:"schema_version"`
	AttemptID       string             `json:"attempt_id"`
	LaunchID        string             `json:"launch_id"`
	RequestSHA256   string             `json:"request_sha256"`
	Status          string             `json:"status"`
	Command         string             `json:"command,omitempty"`
	Outcome         string             `json:"outcome,omitempty"`
	Process         string             `json:"process,omitempty"`
	Cleanup         string             `json:"cleanup,omitempty"`
	ExitCode        *int               `json:"exit_code,omitempty"`
	Stdout          string             `json:"stdout,omitempty"`
	Stderr          string             `json:"stderr,omitempty"`
	StdoutTruncated bool               `json:"stdout_truncated,omitempty"`
	StderrTruncated bool               `json:"stderr_truncated,omitempty"`
	FinishedAt      string             `json:"finished_at,omitempty"`
	Message         string             `json:"message,omitempty"`
	Reason          string             `json:"reason,omitempty"`
	Receipt         *setupOwnerReceipt `json:"receipt,omitempty"`
}

type setupOwnerReceipt struct {
	SchemaVersion      int    `json:"schema_version"`
	AttemptID          string `json:"attempt_id"`
	LaunchID           string `json:"launch_id"`
	RequestSHA256      string `json:"request_sha256"`
	KeeperPID          int    `json:"keeper_pid"`
	KeeperCreationTime string `json:"keeper_creation_time"`
	RootPID            int    `json:"root_pid"`
	RootCreationTime   string `json:"root_creation_time"`
	JobScope           string `json:"job_scope"`
	OwnedAt            string `json:"owned_at"`
}

type setupOwnerFailure struct {
	cause         error
	cleanupProved bool
}

func (failure *setupOwnerFailure) Error() string {
	return failure.cause.Error()
}

func (failure *setupOwnerFailure) Unwrap() error {
	return failure.cause
}

func setupOwnerCleanupProved(err error) bool {
	var failure *setupOwnerFailure
	return errors.As(err, &failure) && failure.cleanupProved
}

func setupOwnerID(prefix string) (string, error) {
	var identity [32]byte
	if _, err := cryptorand.Read(identity[:]); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(identity[:]), nil
}

func setupOwnerRoot(selected target.Target) string {
	return selected.WorkRoot + `\` + setupOwnerStateDirectory
}

func setupOwnerScriptPath(selected target.Target, attemptID string) string {
	return setupOwnerRoot(selected) + `\setup-attempts\` + attemptID + `\` + attemptID + `.ps1`
}

func runOwnedSetup(ctx context.Context, ssh SetupSSH, selected target.Target, attemptID, launchID string, script []byte) ([]byte, error) {
	scriptHash := sha256.Sum256(script)
	requestDeadline := time.Now().UTC().Add(setupOwnerDeadline)
	if callerDeadline, ok := ctx.Deadline(); ok && callerDeadline.Before(requestDeadline) {
		requestDeadline = callerDeadline.UTC()
	}
	request := setupOwnerRequest{
		SchemaVersion:     1,
		AttemptID:         attemptID,
		LaunchID:          launchID,
		DeadlineUTC:       requestDeadline,
		OperationRevision: setupOwnerOperationRevision,
		Script: setupOwnerScriptArtifact{
			ArtifactID: attemptID + ".ps1",
			Size:       len(script),
			SHA256:     hex.EncodeToString(scriptHash[:]),
		},
	}
	rawRequest, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("encode setup owner request: %w", err)
	}
	operationCtx, cancel := context.WithDeadline(ctx, request.DeadlineUTC)
	defer cancel()
	requestHash := sha256.Sum256(rawRequest)
	requestSHA256 := hex.EncodeToString(requestHash[:])
	view, launchErr := invokeSetupOwner(operationCtx, ssh, selected, "launch", nil, rawRequest)
	structuredLaunchError := launchErr == nil && view.Status == "error"
	if structuredLaunchError {
		launchErr = validateSetupOwnerError(view, "setup-owner launch")
	}
	if launchErr != nil {
		if operationCtx.Err() != nil {
			return nil, stopOwnedSetup(operationCtx, ssh, selected, request, requestSHA256, errors.Join(launchErr, operationCtx.Err()))
		}
		if structuredLaunchError {
			return nil, stopOwnedSetup(operationCtx, ssh, selected, request, requestSHA256, launchErr)
		}
		var statusErr error
		view, statusErr = readSetupOwnerStatus(operationCtx, ssh, selected, request, requestSHA256)
		if statusErr != nil {
			return nil, stopOwnedSetup(operationCtx, ssh, selected, request, requestSHA256, errors.Join(launchErr, fmt.Errorf("reconcile setup owner launch: %w", statusErr)))
		}
	}
	for {
		if err := validateSetupOwnerView(view, request, requestSHA256); err != nil {
			return nil, stopOwnedSetup(operationCtx, ssh, selected, request, requestSHA256, err)
		}
		if view.Status == "terminal" {
			break
		}
		if view.Status == "ownership_unverified" {
			return nil, stopOwnedSetup(operationCtx, ssh, selected, request, requestSHA256, fmt.Errorf("setup owner could not verify process ownership"))
		}
		if err := waitForSetupOwner(operationCtx); err != nil {
			return nil, stopOwnedSetup(operationCtx, ssh, selected, request, requestSHA256, err)
		}
		var err error
		view, err = readSetupOwnerStatus(operationCtx, ssh, selected, request, requestSHA256)
		if err != nil {
			return nil, stopOwnedSetup(operationCtx, ssh, selected, request, requestSHA256, err)
		}
	}
	if view.Outcome != "process_succeeded" || view.Process != "exited" || view.Cleanup != "tree_gone" || view.ExitCode == nil || *view.ExitCode != 0 || view.StdoutTruncated || view.StderrTruncated {
		cause := fmt.Errorf("setup owner terminal failed: outcome=%s process=%s cleanup=%s stderr=%s message=%s", view.Outcome, view.Process, view.Cleanup, view.Stderr, view.Message)
		if view.Cleanup == "tree_gone" {
			return nil, &setupOwnerFailure{cause: cause, cleanupProved: true}
		}
		return nil, stopOwnedSetup(operationCtx, ssh, selected, request, requestSHA256, cause)
	}
	return []byte(view.Stdout), nil
}

func readSetupOwnerStatus(ctx context.Context, ssh SetupSSH, selected target.Target, request setupOwnerRequest, requestSHA256 string) (setupOwnerView, error) {
	var lastErr error
	for {
		view, err := invokeSetupOwner(ctx, ssh, selected, "status", setupOwnerFence(request, requestSHA256), nil)
		if err == nil && view.Status != "error" {
			return view, nil
		}
		if err == nil {
			err = validateSetupOwnerError(view, "setup-owner status")
		}
		lastErr = err
		if err := waitForSetupOwner(ctx); err != nil {
			return setupOwnerView{}, errors.Join(lastErr, err)
		}
	}
}

func waitForSetupOwner(ctx context.Context) error {
	timer := time.NewTimer(setupOwnerPollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func validateSetupOwnerError(view setupOwnerView, command string) error {
	if view.SchemaVersion != 1 || view.Status != "error" || view.Command != command || view.Message == "" {
		return fmt.Errorf("setup owner returned an invalid error response")
	}
	if view.Reason != "" {
		return fmt.Errorf("%s: %s (reason=%s)", view.Command, view.Message, view.Reason)
	}
	return fmt.Errorf("%s: %s", view.Command, view.Message)
}

func stopOwnedSetup(ctx context.Context, ssh SetupSSH, selected target.Target, request setupOwnerRequest, requestSHA256 string, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	var lastErr error
	for {
		view, err := invokeSetupOwner(cleanupCtx, ssh, selected, "stop", setupOwnerFence(request, requestSHA256), nil)
		if err == nil && view.Status == "error" {
			err = validateSetupOwnerError(view, "setup-owner stop")
		}
		if err == nil {
			if err = validateSetupOwnerView(view, request, requestSHA256); err == nil && view.Status == "terminal" {
				if view.Cleanup == "tree_gone" {
					return &setupOwnerFailure{cause: cause, cleanupProved: true}
				}
				return &setupOwnerFailure{cause: errors.Join(cause, fmt.Errorf("cleanup not proved: status=%s outcome=%s process=%s cleanup=%s", view.Status, view.Outcome, view.Process, view.Cleanup))}
			}
			if err == nil {
				err = fmt.Errorf("cleanup not proved: status=%s outcome=%s process=%s cleanup=%s", view.Status, view.Outcome, view.Process, view.Cleanup)
			}
		}
		lastErr = err
		if err := waitForSetupOwner(cleanupCtx); err != nil {
			lastErr = errors.Join(lastErr, err)
			break
		}
	}
	return &setupOwnerFailure{cause: errors.Join(cause, fmt.Errorf("stop setup owner: %w", lastErr))}
}

func setupOwnerFence(request setupOwnerRequest, requestSHA256 string) []string {
	return []string{
		"--attempt-id", request.AttemptID,
		"--expect-request-sha256", requestSHA256,
		"--expect-launch-id", request.LaunchID,
	}
}

func invokeSetupOwner(ctx context.Context, ssh SetupSSH, selected target.Target, operation string, fence []string, input []byte) (setupOwnerView, error) {
	arguments := []string{"setup-owner", operation}
	arguments = append(arguments, fence...)
	arguments = append(arguments, "--json")
	command := setupOwnerCommand(selected, arguments, input)
	output, err := ssh.Run(ctx, selected.SSHAlias, powerShellArguments(command), nil)
	if err != nil {
		return setupOwnerView{}, fmt.Errorf("setup owner %s: %w", operation, err)
	}
	if len(output) == 0 || len(output) > maxSetupOwnerResponse {
		return setupOwnerView{}, fmt.Errorf("setup owner %s returned an invalid response size", operation)
	}
	var view setupOwnerView
	decoder := json.NewDecoder(bytes.NewReader(output))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&view); err != nil {
		return setupOwnerView{}, fmt.Errorf("decode setup owner %s response: %w", operation, err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return setupOwnerView{}, fmt.Errorf("decode setup owner %s response: trailing JSON", operation)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(output, &fields); err != nil {
		return setupOwnerView{}, fmt.Errorf("decode setup owner %s response fields: %w", operation, err)
	}
	if err := validateSetupOwnerResponseShape(view.Status, fields); err != nil {
		return setupOwnerView{}, fmt.Errorf("decode setup owner %s response: %w", operation, err)
	}
	return view, nil
}

func setupOwnerCommand(selected target.Target, arguments []string, input []byte) string {
	if len(input) == 0 {
		command := "$ErrorActionPreference = 'Stop'\n$env:BLENDERSESSIOND_STATE_DIR = " + powerShellLiteral(setupOwnerRoot(selected)) + "\n& " + powerShellLiteral(selected.SessionBrokerExecutable)
		for _, argument := range arguments {
			command += " " + powerShellLiteral(argument)
		}
		return command + "\nif ($LASTEXITCODE -notin @(0, 1)) { throw 'setup owner command returned an invalid exit code' }\nexit 0"
	}
	command := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$r = [Convert]::FromBase64String(%s)
$i = [Diagnostics.ProcessStartInfo]::new()
$i.FileName = %s
$i.Arguments = %s
$i.UseShellExecute = $false
$i.RedirectStandardInput = $true
$i.RedirectStandardOutput = $true
$i.RedirectStandardError = $true
$i.EnvironmentVariables['BLENDERSESSIOND_STATE_DIR'] = %s
$p = [Diagnostics.Process]::new()
$p.StartInfo = $i
if (-not $p.Start()) { throw 'setup owner process did not start' }
try {
    $s = $p.StandardInput.BaseStream
    try { $s.Write($r, 0, $r.Length); $s.Flush() } finally { $s.Close() }
    $o = [IO.MemoryStream]::new()
    $e = [IO.MemoryStream]::new()
    $ob = [byte[]]::new(4096)
    $eb = [byte[]]::new(4096)
    $od = $false
    $ed = $false
    $ot = $p.StandardOutput.BaseStream.ReadAsync($ob, 0, $ob.Length)
    $et = $p.StandardError.BaseStream.ReadAsync($eb, 0, $eb.Length)
    while (-not ($od -and $ed)) {
        $q = @()
        if (-not $od) { $q += $ot }
        if (-not $ed) { $q += $et }
        [void][Threading.Tasks.Task]::WaitAny([Threading.Tasks.Task[]]$q)
        if (-not $od -and $ot.IsCompleted) {
            $n = $ot.GetAwaiter().GetResult()
            if ($n -eq 0) { $od = $true } else {
                if ($o.Length + $n -gt %d) { throw 'setup owner stdout exceeded its limit' }
                $o.Write($ob, 0, $n)
                $ot = $p.StandardOutput.BaseStream.ReadAsync($ob, 0, $ob.Length)
            }
        }
        if (-not $ed -and $et.IsCompleted) {
            $n = $et.GetAwaiter().GetResult()
            if ($n -eq 0) { $ed = $true } else {
                if ($e.Length + $n -gt %d) { throw 'setup owner stderr exceeded its limit' }
                $e.Write($eb, 0, $n)
                $et = $p.StandardError.BaseStream.ReadAsync($eb, 0, $eb.Length)
            }
        }
    }
    $p.WaitForExit()
    [Console]::Out.Write([Text.Encoding]::UTF8.GetString($o.ToArray()))
    [Console]::Error.Write([Text.Encoding]::UTF8.GetString($e.ToArray()))
    if ($p.ExitCode -notin @(0, 1)) { throw 'setup owner command returned an invalid exit code' }
} catch {
    if (-not $p.HasExited) { $p.Kill(); $p.WaitForExit() }
    throw
} finally { $p.Dispose() }
exit 0`, powerShellLiteral(base64.StdEncoding.EncodeToString(input)), powerShellLiteral(selected.SessionBrokerExecutable), powerShellLiteral(strings.Join(arguments, " ")), powerShellLiteral(setupOwnerRoot(selected)), maxSetupOwnerResponse, maxSetupOwnerResponse)
	command = strings.ReplaceAll(command, "\n        ", "\n")
	return strings.ReplaceAll(command, "\n    ", "\n")
}

func validateSetupOwnerResponseShape(status string, fields map[string]json.RawMessage) error {
	if err := validateSetupOwnerStringFields(fields, "status"); err != nil {
		return err
	}
	common := []string{"schema_version", "attempt_id", "launch_id", "request_sha256", "status"}
	required := common
	var optional []string
	stringFields := []string{"attempt_id", "launch_id", "request_sha256"}
	switch status {
	case "accepted":
	case "owned", "ownership_unverified":
		required = append(required, "receipt")
	case "terminal":
		required = append(required, "outcome", "process", "cleanup", "exit_code", "stdout", "stderr", "stdout_truncated", "stderr_truncated", "finished_at")
		optional = append(optional, "message")
		stringFields = append(stringFields, "outcome", "process", "cleanup", "stdout", "stderr", "finished_at")
	case "error":
		required = []string{"schema_version", "status", "command", "message"}
		optional = append(optional, "reason")
		stringFields = []string{"command", "message"}
	default:
		return fmt.Errorf("invalid status %q", status)
	}
	allowed := make(map[string]struct{}, len(required)+len(optional))
	for _, field := range required {
		allowed[field] = struct{}{}
		if _, ok := fields[field]; !ok {
			return fmt.Errorf("missing %s", field)
		}
	}
	for _, field := range optional {
		allowed[field] = struct{}{}
	}
	for field := range fields {
		if _, ok := allowed[field]; !ok {
			return fmt.Errorf("unexpected %s", field)
		}
	}
	for _, field := range optional {
		if _, ok := fields[field]; ok {
			stringFields = append(stringFields, field)
		}
	}
	if err := validateSetupOwnerStringFields(fields, stringFields...); err != nil {
		return err
	}
	if status == "terminal" {
		for _, field := range []string{"stdout_truncated", "stderr_truncated"} {
			value := bytes.TrimSpace(fields[field])
			if !bytes.Equal(value, []byte("true")) && !bytes.Equal(value, []byte("false")) {
				return fmt.Errorf("%s must be a JSON boolean", field)
			}
		}
	}
	return nil
}

func validateSetupOwnerStringFields(fields map[string]json.RawMessage, names ...string) error {
	for _, name := range names {
		raw, ok := fields[name]
		if !ok {
			return fmt.Errorf("missing %s", name)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return fmt.Errorf("decode %s: %w", name, err)
		}
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s must be a JSON string", name)
		}
	}
	return nil
}

func validateSetupOwnerView(view setupOwnerView, request setupOwnerRequest, requestHash string) error {
	if view.SchemaVersion != 1 || view.AttemptID != request.AttemptID || view.LaunchID != request.LaunchID || view.RequestSHA256 != requestHash {
		return fmt.Errorf("setup owner returned a stale or invalid fence")
	}
	switch view.Status {
	case "accepted":
		if view.Receipt != nil {
			return fmt.Errorf("setup owner accepted state contains an unexpected receipt")
		}
	case "owned", "ownership_unverified":
		if err := validateSetupOwnerReceipt(view.Receipt, request, requestHash); err != nil {
			return err
		}
	case "terminal":
		if _, err := time.Parse(time.RFC3339Nano, view.FinishedAt); err != nil {
			return fmt.Errorf("setup owner terminal has an invalid completion time")
		}
	default:
		return fmt.Errorf("setup owner returned an invalid status %q", view.Status)
	}
	return nil
}

func validateSetupOwnerReceipt(receipt *setupOwnerReceipt, request setupOwnerRequest, requestHash string) error {
	if receipt == nil || receipt.SchemaVersion != 1 || receipt.AttemptID != request.AttemptID || receipt.LaunchID != request.LaunchID || receipt.RequestSHA256 != requestHash || receipt.KeeperPID <= 0 || receipt.RootPID <= 0 || receipt.KeeperCreationTime == "" || receipt.RootCreationTime == "" || receipt.JobScope != "unnamed-kill-on-close" {
		return fmt.Errorf("setup owner returned an invalid ownership receipt")
	}
	if _, err := time.Parse(time.RFC3339Nano, receipt.OwnedAt); err != nil {
		return fmt.Errorf("setup owner receipt has an invalid ownership time")
	}
	return nil
}
