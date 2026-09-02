package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/payload"
	"github.com/BramVR/blender-box/internal/target"
)

const (
	maxEvidenceFiles = 64
	maxEvidenceFile  = 16 << 20
	maxEvidenceTotal = 64 << 20
	pollInterval     = 250 * time.Millisecond
)

var (
	runIDPattern     = regexp.MustCompile(`^bbx_[A-Za-z0-9_-]{16,64}$`)
	requestIDPattern = regexp.MustCompile(`^req_[A-Za-z0-9_-]{16,64}$`)
	sessionIDPattern = regexp.MustCompile(`^bss_[A-Za-z0-9_-]{16,128}$`)
	hashPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type RunID string
type RequestID string
type SessionID string

type RunState string

const (
	StateAccepted      RunState = "accepted"
	StateStaged        RunState = "staged"
	StateStarting      RunState = "starting"
	StateRunning       RunState = "running"
	StateCalling       RunState = "calling"
	StateCollecting    RunState = "collecting"
	StateSettling      RunState = "settling"
	StateComplete      RunState = "complete"
	StateFailed        RunState = "failed"
	StateTimedOut      RunState = "timed-out"
	StateCleanupFailed RunState = "cleanup-failed"
)

func (state RunState) terminal() bool {
	switch state {
	case StateComplete, StateFailed, StateTimedOut, StateCleanupFailed:
		return true
	default:
		return false
	}
}

// LockClaim is the complete Host Lock authority. Every mutating adapter call carries it.
type LockClaim struct {
	SchemaVersion int       `json:"schema_version"`
	RunID         RunID     `json:"run_id"`
	RequestID     RequestID `json:"request_id"`
	ControllerID  string    `json:"controller_id"`
	Deadline      time.Time `json:"deadline"`
	RequestHash   string    `json:"request_hash"`
	TaskName      string    `json:"task_name"`
}

type RequestBody struct {
	SchemaVersion           int             `json:"schema_version"`
	SessionName             string          `json:"session_name"`
	BlenderExecutable       string          `json:"blender_executable"`
	SessionBrokerExecutable string          `json:"session_broker_executable"`
	Payload                 payload.Payload `json:"payload"`
}

type RunRequest struct {
	Claim LockClaim   `json:"claim"`
	Body  RequestBody `json:"body"`
}

type EvidenceFile struct {
	Path   string `json:"path"`
	Type   string `json:"type"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type EvidenceManifest struct {
	SchemaVersion int            `json:"schema_version"`
	Files         []EvidenceFile `json:"files"`
}

type CleanupState struct {
	SessionStopped bool `json:"session_stopped"`
	PayloadRemoved bool `json:"payload_removed"`
	RunRootRemoved bool `json:"run_root_removed"`
	LockReleased   bool `json:"lock_released"`
}

func (state CleanupState) Known() bool {
	return state.SessionStopped && state.PayloadRemoved && state.RunRootRemoved && state.LockReleased
}

type RunReceipt struct {
	SchemaVersion int              `json:"schema_version"`
	Claim         LockClaim        `json:"claim"`
	State         RunState         `json:"state"`
	SessionID     SessionID        `json:"session_id"`
	Evidence      EvidenceManifest `json:"evidence"`
	Cleanup       CleanupState     `json:"cleanup"`
	Error         string           `json:"error,omitempty"`
}

type RunIntent struct {
	RunID        RunID
	RequestID    RequestID
	ControllerID string
	Deadline     time.Time
	Target       target.Target
	Payload      payload.Payload
	EvidenceDir  string
}

type RunResult struct {
	SchemaVersion int              `json:"schema_version"`
	RunID         RunID            `json:"run_id"`
	RequestID     RequestID        `json:"request_id"`
	SessionID     SessionID        `json:"session_id"`
	State         RunState         `json:"state"`
	Evidence      EvidenceManifest `json:"evidence"`
	Cleanup       CleanupState     `json:"cleanup"`
}

// HostAdapter owns all host-side effects. The Runner owns ordering and authority propagation.
type HostAdapter interface {
	Inspect(context.Context, target.Target) error
	Acquire(context.Context, target.Target, LockClaim) error
	Stage(context.Context, target.Target, LockClaim, payload.Payload) error
	Start(context.Context, target.Target, RunRequest) (RunReceipt, error)
	Observe(context.Context, target.Target, RunID) (RunReceipt, error)
	Fetch(context.Context, target.Target, RunReceipt, EvidenceFile) ([]byte, error)
	Settle(context.Context, target.Target, RunReceipt) (CleanupState, error)
}

type Runner struct {
	host HostAdapter
}

func New(host HostAdapter) *Runner {
	return &Runner{host: host}
}

func (runner *Runner) Run(ctx context.Context, intent RunIntent) (_ RunResult, resultErr error) {
	request, err := buildRequest(intent)
	if err != nil {
		return RunResult{}, err
	}
	if err := runner.host.Inspect(ctx, intent.Target); err != nil {
		return RunResult{}, fmt.Errorf("inspect host: %w", err)
	}
	if err := runner.host.Acquire(ctx, intent.Target, request.Claim); err != nil {
		return RunResult{}, fmt.Errorf("acquire Host Lock: %w", err)
	}

	receipt := RunReceipt{SchemaVersion: 1, Claim: request.Claim, State: StateAccepted}
	settled := false
	defer func() {
		if settled {
			return
		}
		cleanup, settleErr := runner.host.Settle(context.WithoutCancel(ctx), intent.Target, receipt)
		if settleErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("settle Run: %w", settleErr))
			return
		}
		if !cleanup.Known() {
			resultErr = errors.Join(resultErr, fmt.Errorf("settle Run: cleanup state is not known"))
		}
	}()

	if err := runner.host.Stage(ctx, intent.Target, request.Claim, intent.Payload); err != nil {
		return RunResult{}, fmt.Errorf("stage Run Payload: %w", err)
	}
	receipt.State = StateStaged
	receipt, err = runner.host.Start(ctx, intent.Target, request)
	if err != nil {
		return RunResult{}, fmt.Errorf("start Run: %w", err)
	}
	if err := validateReceipt(receipt, request.Claim, false); err != nil {
		return RunResult{}, fmt.Errorf("start receipt: %w", err)
	}

	for !receipt.State.terminal() {
		if err := waitForPoll(ctx, intent.Deadline); err != nil {
			return RunResult{}, err
		}
		receipt, err = runner.host.Observe(ctx, intent.Target, intent.RunID)
		if err != nil {
			return RunResult{}, fmt.Errorf("observe Run: %w", err)
		}
		if err := validateReceipt(receipt, request.Claim, true); err != nil {
			return RunResult{}, fmt.Errorf("observe receipt: %w", err)
		}
	}
	if receipt.State != StateComplete {
		return RunResult{}, fmt.Errorf("Run ended in %s: %s", receipt.State, receipt.Error)
	}
	if err := runner.collectEvidence(ctx, intent, receipt); err != nil {
		return RunResult{}, err
	}

	cleanup, err := runner.host.Settle(context.WithoutCancel(ctx), intent.Target, receipt)
	if err != nil {
		return RunResult{}, fmt.Errorf("settle Run: %w", err)
	}
	settled = true
	if !cleanup.Known() {
		return RunResult{}, fmt.Errorf("settle Run: cleanup state is not known")
	}
	return RunResult{
		SchemaVersion: 1,
		RunID:         intent.RunID,
		RequestID:     intent.RequestID,
		SessionID:     receipt.SessionID,
		State:         receipt.State,
		Evidence:      receipt.Evidence,
		Cleanup:       cleanup,
	}, nil
}

func buildRequest(intent RunIntent) (RunRequest, error) {
	if !runIDPattern.MatchString(string(intent.RunID)) {
		return RunRequest{}, fmt.Errorf("invalid Run ID")
	}
	if !requestIDPattern.MatchString(string(intent.RequestID)) {
		return RunRequest{}, fmt.Errorf("invalid request ID")
	}
	if strings.TrimSpace(intent.ControllerID) == "" {
		return RunRequest{}, fmt.Errorf("controller ID is required")
	}
	if !intent.Deadline.After(time.Now()) {
		return RunRequest{}, fmt.Errorf("deadline must be in the future")
	}
	body := RequestBody{
		SchemaVersion:           1,
		SessionName:             sessionName(intent.RunID),
		BlenderExecutable:       intent.Target.BlenderExecutable,
		SessionBrokerExecutable: intent.Target.SessionBrokerExecutable,
		Payload:                 intent.Payload,
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return RunRequest{}, fmt.Errorf("encode request body: %w", err)
	}
	hash := sha256.Sum256(encoded)
	claim := LockClaim{
		SchemaVersion: 1,
		RunID:         intent.RunID,
		RequestID:     intent.RequestID,
		ControllerID:  intent.ControllerID,
		Deadline:      intent.Deadline.UTC(),
		RequestHash:   hex.EncodeToString(hash[:]),
		TaskName:      intent.Target.TaskName,
	}
	return RunRequest{Claim: claim, Body: body}, nil
}

func sessionName(runID RunID) string {
	hash := sha256.Sum256([]byte(runID))
	return "blender-box-" + hex.EncodeToString(hash[:8])
}

func validateReceipt(receipt RunReceipt, claim LockClaim, requireSession bool) error {
	if receipt.SchemaVersion != 0 && receipt.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema version %d", receipt.SchemaVersion)
	}
	if receipt.Claim != claim {
		return fmt.Errorf("Host Lock claim changed")
	}
	if requireSession && !sessionIDPattern.MatchString(string(receipt.SessionID)) {
		return fmt.Errorf("invalid Session identity")
	}
	return nil
}

func waitForPoll(ctx context.Context, deadline time.Time) error {
	wait := pollInterval
	if remaining := time.Until(deadline); remaining <= 0 {
		return fmt.Errorf("Run deadline exceeded")
	} else if remaining < wait {
		wait = remaining
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		if !time.Now().Before(deadline) {
			return fmt.Errorf("Run deadline exceeded")
		}
		return nil
	}
}

func (runner *Runner) collectEvidence(ctx context.Context, intent RunIntent, receipt RunReceipt) error {
	manifest := receipt.Evidence
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("evidence: unsupported schema version %d", manifest.SchemaVersion)
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > maxEvidenceFiles {
		return fmt.Errorf("evidence: invalid file count %d", len(manifest.Files))
	}
	var total int64
	for _, file := range manifest.Files {
		if err := validateEvidenceFile(file); err != nil {
			return fmt.Errorf("evidence %q: %w", file.Path, err)
		}
		total += file.Size
		if total > maxEvidenceTotal {
			return fmt.Errorf("evidence exceeds total size limit")
		}
		content, err := runner.host.Fetch(ctx, intent.Target, receipt, file)
		if err != nil {
			return fmt.Errorf("fetch evidence %q: %w", file.Path, err)
		}
		if int64(len(content)) != file.Size {
			return fmt.Errorf("evidence %q: size changed", file.Path)
		}
		hash := sha256.Sum256(content)
		if hex.EncodeToString(hash[:]) != file.SHA256 {
			return fmt.Errorf("evidence %q: SHA-256 changed", file.Path)
		}
		if err := writeEvidence(intent.EvidenceDir, file.Path, content); err != nil {
			return fmt.Errorf("store evidence %q: %w", file.Path, err)
		}
	}
	return nil
}

func validateEvidenceFile(file EvidenceFile) error {
	if file.Path == "" || strings.Contains(file.Path, `\`) || filepath.IsAbs(file.Path) {
		return fmt.Errorf("unsafe path")
	}
	clean := filepath.Clean(file.Path)
	if clean != file.Path || clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("unsafe path")
	}
	if file.Type == "" {
		return fmt.Errorf("type is required")
	}
	if file.Size < 0 || file.Size > maxEvidenceFile {
		return fmt.Errorf("invalid size %d", file.Size)
	}
	if !hashPattern.MatchString(file.SHA256) {
		return fmt.Errorf("invalid SHA-256")
	}
	return nil
}

func writeEvidence(root, relative string, content []byte) error {
	if root == "" {
		return fmt.Errorf("evidence directory is required")
	}
	destination := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".blender-box-evidence-*")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, destination)
}
