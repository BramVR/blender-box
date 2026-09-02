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
	"github.com/BramVR/blender-box/internal/safepath"
	"github.com/BramVR/blender-box/internal/target"
)

const (
	maxEvidenceFiles = 64
	maxEvidenceFile  = 16 << 20
	maxEvidenceTotal = 64 << 20
	pollInterval     = 250 * time.Millisecond
	defaultSettleTTL = 30 * time.Second
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

func (runID RunID) Validate() error {
	if !runIDPattern.MatchString(string(runID)) {
		return fmt.Errorf("invalid Run ID")
	}
	return nil
}

func (sessionID SessionID) Validate() error {
	if !sessionIDPattern.MatchString(string(sessionID)) {
		return fmt.Errorf("invalid Session identity")
	}
	return nil
}

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

func (claim LockClaim) Equal(other LockClaim) bool {
	return claimsEqual(claim, other)
}

func (claim LockClaim) Validate() error {
	if claim.SchemaVersion != 1 || !runIDPattern.MatchString(string(claim.RunID)) || !requestIDPattern.MatchString(string(claim.RequestID)) {
		return fmt.Errorf("invalid Run or request identity")
	}
	if strings.TrimSpace(claim.ControllerID) == "" || claim.Deadline.IsZero() || !hashPattern.MatchString(claim.RequestHash) || strings.TrimSpace(claim.TaskName) == "" {
		return fmt.Errorf("invalid Host Lock claim")
	}
	return nil
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

func (request RunRequest) Validate() error {
	if err := request.Claim.Validate(); err != nil {
		return err
	}
	if request.Body.SchemaVersion != 1 {
		return fmt.Errorf("unsupported request body schema version %d", request.Body.SchemaVersion)
	}
	if strings.TrimSpace(request.Body.SessionName) == "" || strings.TrimSpace(request.Body.BlenderExecutable) == "" || strings.TrimSpace(request.Body.SessionBrokerExecutable) == "" {
		return fmt.Errorf("request body is incomplete")
	}
	if !target.ValidateWindowsPath(request.Body.BlenderExecutable) || !target.ValidateWindowsPath(request.Body.SessionBrokerExecutable) {
		return fmt.Errorf("request body contains an unsafe Windows executable path")
	}
	if err := request.Body.Payload.ValidateManifest(); err != nil {
		return fmt.Errorf("invalid request payload: %w", err)
	}
	hash, err := requestBodyHash(request.Body)
	if err != nil {
		return err
	}
	if hash != request.Claim.RequestHash {
		return fmt.Errorf("request hash does not match body")
	}
	return nil
}

type EvidenceFile struct {
	Path          string `json:"path"`
	Type          string `json:"type"`
	Size          int64  `json:"size"`
	SHA256        string `json:"sha256"`
	CaptureMethod string `json:"capture_method,omitempty"`
	Width         int    `json:"width,omitempty"`
	Height        int    `json:"height,omitempty"`
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
	RequestHash   string           `json:"request_hash"`
	Deadline      time.Time        `json:"deadline"`
	SessionID     SessionID        `json:"session_id"`
	State         RunState         `json:"state"`
	Evidence      EvidenceManifest `json:"evidence"`
	Cleanup       CleanupState     `json:"cleanup"`
}

type StatusResult struct {
	SchemaVersion int              `json:"schema_version"`
	RunID         RunID            `json:"run_id"`
	RequestID     RequestID        `json:"request_id"`
	RequestHash   string           `json:"request_hash"`
	Deadline      time.Time        `json:"deadline"`
	SessionID     SessionID        `json:"session_id,omitempty"`
	State         RunState         `json:"state"`
	Evidence      EvidenceManifest `json:"evidence"`
	Cleanup       CleanupState     `json:"cleanup"`
	Error         string           `json:"error,omitempty"`
}

type StopResult struct {
	SchemaVersion int          `json:"schema_version"`
	RunID         RunID        `json:"run_id"`
	RequestID     RequestID    `json:"request_id"`
	RequestHash   string       `json:"request_hash"`
	Deadline      time.Time    `json:"deadline"`
	SessionID     SessionID    `json:"session_id,omitempty"`
	Status        string       `json:"status"`
	Cleanup       CleanupState `json:"cleanup"`
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
	host              HostAdapter
	settlementTimeout time.Duration
}

func New(host HostAdapter) *Runner {
	return &Runner{host: host, settlementTimeout: defaultSettleTTL}
}

// Status reads and validates the host-owned receipt for one exact Run ID.
func (runner *Runner) Status(ctx context.Context, selected target.Target, runID RunID) (StatusResult, error) {
	receipt, err := runner.recoverReceipt(ctx, selected, runID)
	if err != nil {
		return StatusResult{}, err
	}
	return statusFromReceipt(receipt), nil
}

func (runner *Runner) recoverReceipt(ctx context.Context, selected target.Target, runID RunID) (RunReceipt, error) {
	if err := runID.Validate(); err != nil {
		return RunReceipt{}, err
	}
	receipt, err := runner.host.Observe(ctx, selected, runID)
	if err != nil {
		return RunReceipt{}, fmt.Errorf("observe Run: %w", err)
	}
	if err := validateRecoveredReceipt(receipt, selected, runID); err != nil {
		return RunReceipt{}, fmt.Errorf("status receipt: %w", err)
	}
	return receipt, nil
}

// Stop settles only the exact authority recovered from the host-owned receipt.
func (runner *Runner) Stop(ctx context.Context, selected target.Target, runID RunID) (StopResult, error) {
	receipt, err := runner.recoverReceipt(ctx, selected, runID)
	if err != nil {
		return StopResult{}, err
	}
	cleanup, err := runner.settle(ctx, selected, receipt)
	if err != nil {
		return StopResult{}, fmt.Errorf("settle Run: %w", err)
	}
	if !cleanup.Known() {
		return StopResult{}, fmt.Errorf("settle Run: cleanup state is not known")
	}
	return StopResult{
		SchemaVersion: 1,
		RunID:         receipt.Claim.RunID,
		RequestID:     receipt.Claim.RequestID,
		RequestHash:   receipt.Claim.RequestHash,
		Deadline:      receipt.Claim.Deadline,
		SessionID:     receipt.SessionID,
		Status:        "settled",
		Cleanup:       cleanup,
	}, nil
}

func statusFromReceipt(receipt RunReceipt) StatusResult {
	return StatusResult{
		SchemaVersion: 1,
		RunID:         receipt.Claim.RunID,
		RequestID:     receipt.Claim.RequestID,
		RequestHash:   receipt.Claim.RequestHash,
		Deadline:      receipt.Claim.Deadline,
		SessionID:     receipt.SessionID,
		State:         receipt.State,
		Evidence:      receipt.Evidence,
		Cleanup:       receipt.Cleanup,
		Error:         receipt.Error,
	}
}

func (runner *Runner) Run(ctx context.Context, intent RunIntent) (_ RunResult, resultErr error) {
	request, err := buildRequest(intent)
	if err != nil {
		return RunResult{}, err
	}
	runCtx, cancelRun := context.WithDeadline(ctx, intent.Deadline)
	defer cancelRun()
	if err := runner.host.Inspect(runCtx, intent.Target); err != nil {
		return RunResult{}, fmt.Errorf("inspect host: %w", err)
	}
	receipt := RunReceipt{SchemaVersion: 1, Claim: request.Claim, State: StateAccepted}
	if err := runner.host.Acquire(runCtx, intent.Target, request.Claim); err != nil {
		acquireErr := fmt.Errorf("acquire Host Lock: %w", err)
		cleanup, settleErr := runner.settle(ctx, intent.Target, receipt)
		if settleErr != nil {
			return RunResult{}, errors.Join(acquireErr, fmt.Errorf("settle ambiguous Host Lock acquisition: %w", settleErr))
		}
		if !cleanup.Known() {
			return RunResult{}, errors.Join(acquireErr, fmt.Errorf("settle ambiguous Host Lock acquisition: cleanup state is not known"))
		}
		return RunResult{}, acquireErr
	}

	settled := false
	defer func() {
		if settled {
			return
		}
		cleanup, settleErr := runner.settle(ctx, intent.Target, receipt)
		if settleErr != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("settle Run: %w", settleErr))
			return
		}
		if !cleanup.Known() {
			resultErr = errors.Join(resultErr, fmt.Errorf("settle Run: cleanup state is not known"))
		}
	}()

	if err := runner.host.Stage(runCtx, intent.Target, request.Claim, intent.Payload); err != nil {
		return RunResult{}, fmt.Errorf("stage Run Payload: %w", err)
	}
	receipt.State = StateStaged
	startedReceipt, err := runner.host.Start(runCtx, intent.Target, request)
	if err != nil {
		return RunResult{}, fmt.Errorf("start Run: %w", err)
	}
	if err := validateReceipt(startedReceipt, request.Claim, "", receipt.State); err != nil {
		return RunResult{}, fmt.Errorf("start receipt: %w", err)
	}
	receipt = startedReceipt
	sessionID := receipt.SessionID

	for !receipt.State.terminal() {
		if err := waitForPoll(runCtx, intent.Deadline); err != nil {
			return RunResult{}, err
		}
		observedReceipt, err := runner.host.Observe(runCtx, intent.Target, intent.RunID)
		if err != nil {
			return RunResult{}, fmt.Errorf("observe Run: %w", err)
		}
		if err := validateReceipt(observedReceipt, request.Claim, sessionID, receipt.State); err != nil {
			return RunResult{}, fmt.Errorf("observe receipt: %w", err)
		}
		receipt = observedReceipt
	}
	if receipt.State != StateComplete {
		return RunResult{}, fmt.Errorf("Run ended in %s: %s", receipt.State, receipt.Error)
	}
	evidenceRoot, err := runner.collectEvidence(runCtx, intent, receipt)
	if err != nil {
		return RunResult{}, err
	}

	cleanup, err := runner.settle(ctx, intent.Target, receipt)
	if err != nil {
		return RunResult{}, fmt.Errorf("settle Run: %w", err)
	}
	if !cleanup.Known() {
		return RunResult{}, fmt.Errorf("settle Run: cleanup state is not known")
	}
	result := RunResult{
		SchemaVersion: 1,
		RunID:         intent.RunID,
		RequestID:     intent.RequestID,
		RequestHash:   request.Claim.RequestHash,
		Deadline:      request.Claim.Deadline,
		SessionID:     receipt.SessionID,
		State:         receipt.State,
		Evidence:      receipt.Evidence,
		Cleanup:       cleanup,
	}
	if err := publishBundleMetadata(evidenceRoot, result); err != nil {
		return RunResult{}, fmt.Errorf("publish Evidence Bundle metadata: %w", err)
	}
	settled = true
	return result, nil
}

func buildRequest(intent RunIntent) (RunRequest, error) {
	if err := intent.RunID.Validate(); err != nil {
		return RunRequest{}, err
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
	if err := intent.Payload.Validate(); err != nil {
		return RunRequest{}, fmt.Errorf("invalid Run Payload: %w", err)
	}
	body := RequestBody{
		SchemaVersion:           1,
		SessionName:             sessionName(intent.RunID),
		BlenderExecutable:       intent.Target.BlenderExecutable,
		SessionBrokerExecutable: intent.Target.SessionBrokerExecutable,
		Payload:                 intent.Payload,
	}
	requestHash, err := requestBodyHash(body)
	if err != nil {
		return RunRequest{}, err
	}
	claim := LockClaim{
		SchemaVersion: 1,
		RunID:         intent.RunID,
		RequestID:     intent.RequestID,
		ControllerID:  intent.ControllerID,
		Deadline:      intent.Deadline.UTC(),
		RequestHash:   requestHash,
		TaskName:      intent.Target.TaskName,
	}
	return RunRequest{Claim: claim, Body: body}, nil
}

func requestBodyHash(body RequestBody) (string, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("encode request body: %w", err)
	}
	hash := sha256.Sum256(encoded)
	return hex.EncodeToString(hash[:]), nil
}

func sessionName(runID RunID) string {
	hash := sha256.Sum256([]byte(runID))
	return "blender-box-" + hex.EncodeToString(hash[:8])
}

func validateReceipt(receipt RunReceipt, claim LockClaim, expectedSession SessionID, previousState RunState) error {
	if receipt.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema version %d", receipt.SchemaVersion)
	}
	if !claimsEqual(receipt.Claim, claim) {
		return fmt.Errorf("Host Lock claim changed")
	}
	if !knownState(receipt.State) {
		return fmt.Errorf("unknown Run state %q", receipt.State)
	}
	if !validTransition(previousState, receipt.State) {
		return fmt.Errorf("invalid Run state transition %q to %q", previousState, receipt.State)
	}
	if !sessionIDPattern.MatchString(string(receipt.SessionID)) {
		return fmt.Errorf("invalid Session identity")
	}
	if expectedSession != "" && receipt.SessionID != expectedSession {
		return fmt.Errorf("Session identity changed")
	}
	return nil
}

func validateRecoveredReceipt(receipt RunReceipt, selected target.Target, runID RunID) error {
	if receipt.SchemaVersion != 1 || receipt.Claim.SchemaVersion != 1 {
		return fmt.Errorf("unsupported schema version")
	}
	claim := receipt.Claim
	if claim.RunID != runID {
		return fmt.Errorf("Run ID changed")
	}
	if !requestIDPattern.MatchString(string(claim.RequestID)) || strings.TrimSpace(claim.ControllerID) == "" || claim.Deadline.IsZero() || !hashPattern.MatchString(claim.RequestHash) {
		return fmt.Errorf("invalid Host Lock claim")
	}
	if claim.TaskName != selected.TaskName {
		return fmt.Errorf("Scheduled Task identity changed")
	}
	if !knownState(receipt.State) {
		return fmt.Errorf("unknown Run state %q", receipt.State)
	}
	if stateRequiresSession(receipt.State) {
		if !sessionIDPattern.MatchString(string(receipt.SessionID)) {
			return fmt.Errorf("invalid Session identity")
		}
	} else if receipt.SessionID != "" && !sessionIDPattern.MatchString(string(receipt.SessionID)) {
		return fmt.Errorf("invalid Session identity")
	}
	if receipt.Evidence.SchemaVersion != 0 || len(receipt.Evidence.Files) != 0 {
		if err := validateEvidenceManifest(receipt.Evidence); err != nil {
			return err
		}
	}
	if receipt.State == StateComplete && receipt.Evidence.SchemaVersion != 1 {
		return fmt.Errorf("complete Run has no evidence manifest")
	}
	return nil
}

func stateRequiresSession(state RunState) bool {
	switch state {
	case StateRunning, StateCalling, StateCollecting, StateSettling, StateComplete:
		return true
	default:
		return false
	}
}

func claimsEqual(left, right LockClaim) bool {
	return left.SchemaVersion == right.SchemaVersion &&
		left.RunID == right.RunID &&
		left.RequestID == right.RequestID &&
		left.ControllerID == right.ControllerID &&
		left.Deadline.Equal(right.Deadline) &&
		left.RequestHash == right.RequestHash &&
		left.TaskName == right.TaskName
}

func knownState(state RunState) bool {
	_, exists := stateRank(state)
	return exists
}

func stateRank(state RunState) (int, bool) {
	switch state {
	case StateAccepted:
		return 0, true
	case StateStaged:
		return 1, true
	case StateStarting:
		return 2, true
	case StateRunning:
		return 3, true
	case StateCalling:
		return 4, true
	case StateCollecting:
		return 5, true
	case StateSettling:
		return 6, true
	case StateComplete:
		return 7, true
	case StateFailed, StateTimedOut, StateCleanupFailed:
		return 8, true
	default:
		return 0, false
	}
}

func validTransition(previous, next RunState) bool {
	previousRank, previousKnown := stateRank(previous)
	nextRank, nextKnown := stateRank(next)
	if !previousKnown || !nextKnown || previous.terminal() {
		return false
	}
	return nextRank >= previousRank
}

func (runner *Runner) settle(parent context.Context, target target.Target, receipt RunReceipt) (CleanupState, error) {
	timeout := runner.settlementTimeout
	if timeout <= 0 {
		timeout = defaultSettleTTL
	}
	settleCtx, cancel := context.WithTimeout(context.WithoutCancel(parent), timeout)
	defer cancel()
	return runner.host.Settle(settleCtx, target, receipt)
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

func (runner *Runner) collectEvidence(ctx context.Context, intent RunIntent, receipt RunReceipt) (string, error) {
	manifest := receipt.Evidence
	if err := validateEvidenceManifest(manifest); err != nil {
		return "", err
	}
	evidenceRoot, err := prepareEvidenceRoot(intent.EvidenceDir)
	if err != nil {
		return "", fmt.Errorf("prepare evidence directory: %w", err)
	}
	for _, file := range manifest.Files {
		content, err := runner.host.Fetch(ctx, intent.Target, receipt, file)
		if err != nil {
			return "", fmt.Errorf("fetch evidence %q: %w", file.Path, err)
		}
		if int64(len(content)) != file.Size {
			return "", fmt.Errorf("evidence %q: size changed", file.Path)
		}
		hash := sha256.Sum256(content)
		if hex.EncodeToString(hash[:]) != file.SHA256 {
			return "", fmt.Errorf("evidence %q: SHA-256 changed", file.Path)
		}
		if err := writeEvidence(evidenceRoot, file.Path, content); err != nil {
			return "", fmt.Errorf("store evidence %q: %w", file.Path, err)
		}
	}
	return evidenceRoot, nil
}

func publishBundleMetadata(root string, result RunResult) error {
	manifest, err := json.MarshalIndent(result.Evidence, "", "  ")
	if err != nil {
		return err
	}
	if err := writeEvidence(root, "manifest.json", append(manifest, '\n')); err != nil {
		return err
	}
	document, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	return writeEvidence(root, "evidence.json", append(document, '\n'))
}

func validateEvidenceManifest(manifest EvidenceManifest) error {
	if manifest.SchemaVersion != 1 {
		return fmt.Errorf("evidence: unsupported schema version %d", manifest.SchemaVersion)
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > maxEvidenceFiles {
		return fmt.Errorf("evidence: invalid file count %d", len(manifest.Files))
	}
	var total int64
	seen := make(map[string]struct{}, len(manifest.Files))
	for _, file := range manifest.Files {
		if err := validateEvidenceFile(file); err != nil {
			return fmt.Errorf("evidence %q: %w", file.Path, err)
		}
		key := safepath.WindowsKey(file.Path)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("evidence %q: duplicate path", file.Path)
		}
		seen[key] = struct{}{}
		total += file.Size
		if total > maxEvidenceTotal {
			return fmt.Errorf("evidence exceeds total size limit")
		}
	}
	return nil
}

func validateEvidenceFile(file EvidenceFile) error {
	if err := safepath.ValidateWindowsRelative("path", file.Path); err != nil {
		return err
	}
	if file.Type == "" {
		return fmt.Errorf("type is required")
	}
	if file.Type == "viewport" {
		if (file.CaptureMethod != "offscreen" && file.CaptureMethod != "window_grab") || file.Width < 1 || file.Height < 1 {
			return fmt.Errorf("viewport capture provenance is invalid")
		}
	} else if file.CaptureMethod != "" || file.Width != 0 || file.Height != 0 {
		return fmt.Errorf("capture provenance is only valid for captures")
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
	destination, err := evidenceDestination(root, relative)
	if err != nil {
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
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryName, destination); err != nil {
		return fmt.Errorf("publish evidence without replacement: %w", err)
	}
	return os.Remove(temporaryName)
}

func prepareEvidenceRoot(root string) (string, error) {
	if root == "" {
		return "", fmt.Errorf("evidence directory is required")
	}
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	parent := filepath.Dir(absoluteRoot)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return "", err
	}
	canonicalParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	canonicalRoot := filepath.Join(canonicalParent, filepath.Base(absoluteRoot))
	if err := os.Mkdir(canonicalRoot, 0o700); err != nil {
		if os.IsExist(err) {
			return "", fmt.Errorf("evidence directory already exists")
		}
		return "", err
	}
	return canonicalRoot, nil
}

func evidenceDestination(root, relative string) (string, error) {
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return "", err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("evidence root is a symlink")
	}
	if !rootInfo.IsDir() {
		return "", fmt.Errorf("evidence root is not a directory")
	}
	current := root
	components := strings.Split(filepath.ToSlash(filepath.Dir(relative)), "/")
	for _, component := range components {
		if component == "." || component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if os.IsNotExist(err) {
			if err := os.Mkdir(current, 0o755); err != nil {
				return "", err
			}
			info, err = os.Lstat(current)
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("evidence parent %q is a symlink", component)
		}
		if !info.IsDir() {
			return "", fmt.Errorf("evidence parent %q is not a directory", component)
		}
	}
	destination := filepath.Join(current, filepath.Base(relative))
	if _, err := os.Lstat(destination); err == nil {
		return "", fmt.Errorf("evidence destination already exists")
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	return destination, nil
}
