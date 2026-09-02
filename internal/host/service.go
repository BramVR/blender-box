package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/safepath"
	"github.com/BramVR/blender-box/internal/target"
)

const (
	maxStageFiles   = 64
	maxStageFile    = 8 << 20
	maxStageTotal   = 32 << 20
	maxEvidenceFile = 16 << 20
	maxScenarioJSON = 1 << 20
)

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

type TaskLauncher interface {
	Launch(context.Context, string) error
}

type Daemon interface {
	Start(context.Context, DaemonStart) (orchestrator.SessionID, error)
	Recover(context.Context, DaemonRecover) (orchestrator.SessionID, bool, error)
	WaitReady(context.Context, DaemonReady) error
	Call(context.Context, DaemonCall) (json.RawMessage, error)
	Stop(context.Context, DaemonStop) error
}

type DaemonStart struct {
	Executable        string
	Name              string
	BlenderExecutable string
	Environment       map[string]string
}

type DaemonCall struct {
	Executable         string
	Name               string
	SessionID          orchestrator.SessionID
	Command            string
	Parameters         json.RawMessage
	ReadTimeoutSeconds int
	Environment        map[string]string
}

type DaemonReady struct {
	Executable  string
	Name        string
	SessionID   orchestrator.SessionID
	Environment map[string]string
}

type DaemonRecover struct {
	Executable  string
	Name        string
	Environment map[string]string
}

type DaemonStop struct {
	Executable  string
	Name        string
	SessionID   orchestrator.SessionID
	Environment map[string]string
}

type Dependencies struct {
	Tasks  TaskLauncher
	Daemon Daemon
	Now    func() time.Time
}

type Service struct {
	tasks     TaskLauncher
	daemon    Daemon
	now       func() time.Time
	writeLock func(string, lockRecord) error
}

type lockRecord struct {
	SchemaVersion int                    `json:"schema_version"`
	Claim         orchestrator.LockClaim `json:"claim"`
	SessionID     orchestrator.SessionID `json:"session_id,omitempty"`
}

type stagedManifest struct {
	SchemaVersion int         `json:"schema_version"`
	Files         []StageFile `json:"files"`
}

func NewService(dependencies Dependencies) *Service {
	now := dependencies.Now
	if now == nil {
		now = time.Now
	}
	return &Service{tasks: dependencies.Tasks, daemon: dependencies.Daemon, now: now, writeLock: writeLockAtomic}
}

func (service *Service) Acquire(ctx context.Context, root string, request AcquireRequest) error {
	if request.SchemaVersion != 1 {
		return fmt.Errorf("unsupported acquire schema version")
	}
	if err := request.Claim.Validate(); err != nil {
		return err
	}
	if !request.Claim.Deadline.After(service.now()) {
		return fmt.Errorf("Run deadline has expired")
	}
	if err := validateRoot(root); err != nil {
		return err
	}
	release, err := acquireOperation(ctx, root)
	if err != nil {
		return err
	}
	defer release()
	if err := os.MkdirAll(filepath.Join(root, "receipts"), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(root, "runs"), 0o700); err != nil {
		return err
	}
	var existingReceipt orchestrator.RunReceipt
	receiptErr := readJSON(receiptPath(root, request.Claim.RunID), &existingReceipt, maxScenarioJSON)
	if receiptErr == nil {
		if existingReceipt.SchemaVersion != 1 || !existingReceipt.Claim.Equal(request.Claim) {
			return fmt.Errorf("Run receipt already exists for another request")
		}
		switch existingReceipt.State {
		case orchestrator.StateAccepted, orchestrator.StateStaged, orchestrator.StateStarting:
			if existingReceipt.SessionID != "" {
				return fmt.Errorf("Run receipt already has a Session identity")
			}
		default:
			return fmt.Errorf("Run receipt already exists in non-replayable state %q", existingReceipt.State)
		}
		existingLock, lockErr := service.readLock(root)
		if lockErr != nil {
			if _, statErr := os.Lstat(lockPath(root)); os.IsNotExist(statErr) {
				return fmt.Errorf("Run receipt already exists without an active Host Lock")
			}
			return lockErr
		}
		if !existingLock.Claim.Equal(request.Claim) || existingLock.SessionID != "" {
			return fmt.Errorf("host is locked by another Run")
		}
		return nil
	}
	if _, err := os.Lstat(receiptPath(root, request.Claim.RunID)); !os.IsNotExist(err) {
		return fmt.Errorf("existing Run receipt is invalid")
	}
	record := lockRecord{SchemaVersion: 1, Claim: request.Claim}
	encoded, err := json.Marshal(record)
	if err != nil {
		return err
	}
	created, err := writeFileExclusive(lockPath(root), encoded)
	if err != nil {
		if !os.IsExist(err) {
			return err
		}
		existing, readErr := service.readLock(root)
		if readErr != nil || !existing.Claim.Equal(request.Claim) || existing.SessionID != "" {
			return fmt.Errorf("host is locked by another Run")
		}
	}
	if !created {
		var receipt orchestrator.RunReceipt
		if err := readJSON(receiptPath(root, request.Claim.RunID), &receipt, maxScenarioJSON); err == nil && receipt.Claim.Equal(request.Claim) {
			return nil
		}
	}
	receipt := orchestrator.RunReceipt{SchemaVersion: 1, Claim: request.Claim, State: orchestrator.StateAccepted}
	return writeJSONAtomic(receiptPath(root, request.Claim.RunID), receipt)
}

func (service *Service) Stage(ctx context.Context, root string, request StageRequest) error {
	if request.SchemaVersion != 1 || len(request.Files) == 0 || len(request.Files) > maxStageFiles {
		return fmt.Errorf("invalid stage contract")
	}
	release, err := acquireOperation(ctx, root)
	if err != nil {
		return err
	}
	defer release()
	lock, err := service.authorizeClaim(root, request.Claim)
	if err != nil {
		return err
	}
	if lock.SessionID != "" {
		return fmt.Errorf("cannot stage after Session start")
	}
	seen := make(map[string]struct{}, len(request.Files))
	var total int64
	for _, file := range request.Files {
		if err := validateStageFile(file); err != nil {
			return err
		}
		key := safepath.WindowsKey(file.Destination)
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate staged destination")
		}
		seen[key] = struct{}{}
		total += file.Size
		if total > maxStageTotal {
			return fmt.Errorf("staged payload exceeds total limit")
		}
	}
	runsRoot := filepath.Join(root, "runs")
	if err := os.MkdirAll(runsRoot, 0o700); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp(runsRoot, ".stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err := writeJSONAtomic(filepath.Join(temporary, "ownership.json"), lock); err != nil {
		return err
	}
	payloadRoot := filepath.Join(temporary, "payload")
	for _, file := range request.Files {
		destination := filepath.Join(payloadRoot, filepath.FromSlash(file.Destination))
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(destination, file.Contents, 0o600); err != nil {
			return err
		}
	}
	manifest := stagedManifest{SchemaVersion: 1, Files: request.Files}
	for index := range manifest.Files {
		manifest.Files[index].Contents = nil
	}
	if err := writeJSONAtomic(filepath.Join(temporary, "staged.json"), manifest); err != nil {
		return err
	}
	for _, name := range []string{"daemon", "blender-resources", "blender-config", "blender-scripts", "blender-data", "blender-extensions", "evidence"} {
		if err := os.Mkdir(filepath.Join(temporary, name), 0o700); err != nil {
			return err
		}
	}
	finalRoot := runPath(root, request.Claim.RunID)
	if err := os.Rename(temporary, finalRoot); err != nil {
		return fmt.Errorf("publish staged Run: %w", err)
	}
	receipt := orchestrator.RunReceipt{SchemaVersion: 1, Claim: request.Claim, State: orchestrator.StateStaged}
	return writeJSONAtomic(receiptPath(root, request.Claim.RunID), receipt)
}

func (service *Service) Start(ctx context.Context, root string, request orchestrator.RunRequest) (orchestrator.RunReceipt, error) {
	if err := request.Validate(); err != nil {
		return orchestrator.RunReceipt{}, err
	}
	if !request.Claim.Deadline.After(service.now()) {
		return orchestrator.RunReceipt{}, fmt.Errorf("Run deadline has expired")
	}
	release, err := acquireOperation(ctx, root)
	if err != nil {
		return orchestrator.RunReceipt{}, err
	}
	defer release()
	lock, err := service.authorizeClaim(root, request.Claim)
	if err != nil {
		return orchestrator.RunReceipt{}, err
	}
	existing, statusErr := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if statusErr == nil {
		if !existing.Claim.Equal(request.Claim) {
			return orchestrator.RunReceipt{}, fmt.Errorf("stored receipt claim changed")
		}
		if lock.SessionID != "" || existing.State != orchestrator.StateAccepted && existing.State != orchestrator.StateStaged {
			if err := service.validateStoredRequest(root, request); err != nil {
				return orchestrator.RunReceipt{}, err
			}
			if lock.SessionID != "" && existing.SessionID == "" {
				existing.SessionID = lock.SessionID
				existing.State = orchestrator.StateCleanupFailed
				existing.Error = "Recovered a Session whose receipt publication was interrupted"
				if err := service.writeReceipt(root, existing); err != nil {
					return orchestrator.RunReceipt{}, err
				}
			} else if lock.SessionID != existing.SessionID {
				return orchestrator.RunReceipt{}, fmt.Errorf("stored receipt Session identity changed")
			}
			if existing.State == orchestrator.StateStarting && lock.SessionID == "" {
				if service.tasks == nil {
					return orchestrator.RunReceipt{}, fmt.Errorf("Scheduled Task launcher is unavailable")
				}
				if err := service.tasks.Launch(ctx, request.Claim.TaskName); err != nil {
					return orchestrator.RunReceipt{}, err
				}
			}
			return existing, nil
		}
	} else if lock.SessionID != "" {
		if err := service.validateStoredRequest(root, request); err != nil {
			return orchestrator.RunReceipt{}, err
		}
		recovered := orchestrator.RunReceipt{
			SchemaVersion: 1,
			Claim:         request.Claim,
			State:         orchestrator.StateCleanupFailed,
			SessionID:     lock.SessionID,
			Error:         "Recovered a Session whose receipt publication was interrupted",
		}
		if err := service.writeReceipt(root, recovered); err != nil {
			return orchestrator.RunReceipt{}, err
		}
		return recovered, nil
	} else {
		return orchestrator.RunReceipt{}, statusErr
	}
	if err := service.validateStagedRequest(root, request); err != nil {
		return orchestrator.RunReceipt{}, err
	}
	if err := writeJSONAtomic(filepath.Join(runPath(root, request.Claim.RunID), "request.json"), request); err != nil {
		return orchestrator.RunReceipt{}, err
	}
	if err := writeJSONAtomic(filepath.Join(root, "pending-request.json"), request); err != nil {
		return orchestrator.RunReceipt{}, err
	}
	receipt := orchestrator.RunReceipt{SchemaVersion: 1, Claim: request.Claim, State: orchestrator.StateStarting}
	if err := service.writeReceipt(root, receipt); err != nil {
		return orchestrator.RunReceipt{}, err
	}
	if service.tasks == nil {
		return orchestrator.RunReceipt{}, fmt.Errorf("Scheduled Task launcher is unavailable")
	}
	if err := service.tasks.Launch(ctx, request.Claim.TaskName); err != nil {
		return orchestrator.RunReceipt{}, err
	}
	return receipt, nil
}

func (service *Service) validateStoredRequest(root string, request orchestrator.RunRequest) error {
	var stored orchestrator.RunRequest
	if err := readJSON(filepath.Join(runPath(root, request.Claim.RunID), "request.json"), &stored, maxScenarioJSON); err != nil {
		return fmt.Errorf("read stored Run request: %w", err)
	}
	storedJSON, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if !bytes.Equal(storedJSON, requestJSON) {
		return fmt.Errorf("stored Run request changed")
	}
	return nil
}

func (service *Service) Status(root string, request StatusRequest) (orchestrator.RunReceipt, error) {
	if request.SchemaVersion != 1 || request.RunID.Validate() != nil {
		return orchestrator.RunReceipt{}, fmt.Errorf("invalid status contract")
	}
	var receipt orchestrator.RunReceipt
	path := receiptPath(root, request.RunID)
	if err := readJSON(path, &receipt, maxScenarioJSON); err != nil {
		if _, statErr := os.Lstat(path); statErr == nil || !os.IsNotExist(statErr) {
			return orchestrator.RunReceipt{}, err
		}
		lock, lockErr := service.readLock(root)
		if lockErr != nil || lock.SchemaVersion != 1 || lock.Claim.Validate() != nil || lock.Claim.RunID != request.RunID || lock.SessionID != "" && lock.SessionID.Validate() != nil {
			return orchestrator.RunReceipt{}, err
		}
		state := orchestrator.StateAccepted
		message := ""
		if lock.SessionID != "" {
			state = orchestrator.StateCleanupFailed
			message = "Recovered a Session whose receipt publication was interrupted"
		}
		return orchestrator.RunReceipt{SchemaVersion: 1, Claim: lock.Claim, State: state, SessionID: lock.SessionID, Error: message}, nil
	}
	return receipt, nil
}

func (service *Service) ExecutePending(ctx context.Context, root string) error {
	release, err := acquireOperation(ctx, root)
	if err != nil {
		return err
	}
	locked := true
	defer func() {
		if locked {
			release()
		}
	}()
	var request orchestrator.RunRequest
	if err := readJSON(filepath.Join(root, "pending-request.json"), &request, maxScenarioJSON); err != nil {
		return err
	}
	if err := request.Validate(); err != nil {
		return err
	}
	lock, err := service.authorizeClaim(root, request.Claim)
	if err != nil {
		return err
	}
	if lock.SessionID != "" {
		return fmt.Errorf("Host Lock already owns a Session")
	}
	if !request.Claim.Deadline.After(service.now()) {
		return service.failExecution(root, request, "Run deadline expired before Session start")
	}
	if service.daemon == nil {
		return service.failExecution(root, request, "Session daemon is unavailable")
	}
	runCtx, cancel := context.WithDeadline(ctx, request.Claim.Deadline)
	defer cancel()
	environment := runEnvironment(root, request.Claim.RunID)
	launchRelease, err := acquireLaunch(runCtx, root)
	if err != nil {
		if runCtx.Err() != nil {
			err = runCtx.Err()
		}
		return service.failExecutionWithCause(root, request, "Session launch lock failed", err)
	}
	locked = false
	release()
	sessionID, startErr := service.daemon.Start(runCtx, DaemonStart{
		Executable:        request.Body.SessionBrokerExecutable,
		Name:              request.Body.SessionName,
		BlenderExecutable: request.Body.BlenderExecutable,
		Environment:       environment,
	})
	launchRelease()
	reconcileCtx, cancelReconcile := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancelReconcile()
	release, err = acquireOperation(reconcileCtx, root)
	if err != nil {
		return err
	}
	locked = true
	receipt, err := service.activeReceipt(root, request, "")
	if errors.Is(err, errRunSettled) {
		return fmt.Errorf("Run was settled during Session start")
	}
	if err != nil {
		return err
	}
	if startErr != nil {
		if runCtx.Err() != nil {
			startErr = runCtx.Err()
		}
		return service.failReceiptWithCause(root, receipt, "Session start failed", startErr)
	}
	if err := sessionID.Validate(); err != nil {
		return service.failReceipt(root, receipt, "Session daemon returned an invalid identity")
	}
	lock.SessionID = sessionID
	if err := service.writeLock(lockPath(root), lock); err != nil {
		stopErr := service.daemon.Stop(reconcileCtx, DaemonStop{Executable: request.Body.SessionBrokerExecutable, Name: request.Body.SessionName, SessionID: sessionID, Environment: environment})
		if stopErr != nil {
			receipt := orchestrator.RunReceipt{SchemaVersion: 1, Claim: request.Claim, State: orchestrator.StateCleanupFailed, SessionID: sessionID, Error: "Session identity publication and exact rollback failed"}
			_ = service.writeReceipt(root, receipt)
			return fmt.Errorf("Session identity publication and exact rollback failed")
		}
		return service.failExecution(root, request, "Session identity publication failed; exact Session was rolled back")
	}
	receipt = orchestrator.RunReceipt{SchemaVersion: 1, Claim: request.Claim, State: orchestrator.StateRunning, SessionID: sessionID}
	if err := service.writeReceipt(root, receipt); err != nil {
		receipt.State = orchestrator.StateCleanupFailed
		receipt.Error = "Session started but its running receipt could not be published"
		_ = service.writeReceipt(root, receipt)
		return err
	}
	resultDirectory := filepath.Join(runPath(root, request.Claim.RunID), "evidence", "result")
	if err := os.MkdirAll(resultDirectory, 0o700); err != nil {
		return service.failReceipt(root, receipt, "Scenario evidence directory failed")
	}
	if request.Body.Payload.Scenario.CaptureViewport {
		if err := os.MkdirAll(filepath.Join(runPath(root, request.Claim.RunID), "evidence", "screenshots"), 0o700); err != nil {
			return service.failReceipt(root, receipt, "Viewport evidence directory failed")
		}
	}
	locked = false
	release()
	if err := service.daemon.WaitReady(runCtx, DaemonReady{
		Executable:  request.Body.SessionBrokerExecutable,
		Name:        request.Body.SessionName,
		SessionID:   sessionID,
		Environment: environment,
	}); err != nil {
		if runCtx.Err() != nil {
			err = runCtx.Err()
		}
		return service.failActiveExecution(ctx, root, request, sessionID, "Session readiness failed", err)
	}
	release, receipt, err = service.resumeActiveExecution(ctx, runCtx, root, request, sessionID, "Session readiness")
	if err != nil {
		return err
	}
	locked = true
	receipt.State = orchestrator.StateCalling
	if err := service.writeReceipt(root, receipt); err != nil {
		return err
	}
	locked = false
	release()

	result, err := service.callScenario(runCtx, root, request, sessionID, environment)
	if err != nil {
		if runCtx.Err() != nil {
			err = runCtx.Err()
		}
		return service.failActiveExecution(ctx, root, request, sessionID, "Scenario call failed", err)
	}
	release, receipt, err = service.resumeActiveExecution(ctx, runCtx, root, request, sessionID, "Scenario call")
	if err != nil {
		return err
	}
	locked = true
	resultPath := filepath.Join(runPath(root, request.Claim.RunID), "evidence", "result", "scenario-result.json")
	if err := os.WriteFile(resultPath, result, 0o600); err != nil {
		return service.failReceipt(root, receipt, "Scenario result write failed")
	}
	resultEvidence, err := evidenceFromFile(runPath(root, request.Claim.RunID), "result/scenario-result.json", "scenario-result")
	if err != nil {
		return service.failReceipt(root, receipt, "Scenario evidence validation failed")
	}
	receipt.State = orchestrator.StateCollecting
	receipt.Evidence = orchestrator.EvidenceManifest{SchemaVersion: 1, Files: []orchestrator.EvidenceFile{resultEvidence}}
	if err := service.writeReceipt(root, receipt); err != nil {
		return err
	}
	locked = false
	release()

	var viewport orchestrator.EvidenceFile
	if request.Body.Payload.Scenario.CaptureViewport {
		var captureErr error
		viewport, captureErr = service.captureViewport(runCtx, root, request, sessionID, environment)
		if captureErr != nil {
			if runCtx.Err() != nil {
				captureErr = runCtx.Err()
			}
			return service.failActiveExecution(ctx, root, request, sessionID, "Viewport capture failed", captureErr)
		}
	}
	release, receipt, err = service.resumeActiveExecution(ctx, runCtx, root, request, sessionID, "evidence collection")
	if err != nil {
		return err
	}
	locked = true
	if request.Body.Payload.Scenario.CaptureViewport {
		receipt.Evidence.Files = append(receipt.Evidence.Files, viewport)
	}
	receipt.State = orchestrator.StateComplete
	if err := service.writeReceipt(root, receipt); err != nil {
		return err
	}
	_ = os.Remove(filepath.Join(root, "pending-request.json"))
	return nil
}

var errRunSettled = errors.New("Run already settled")

func (service *Service) activeReceipt(root string, request orchestrator.RunRequest, sessionID orchestrator.SessionID) (orchestrator.RunReceipt, error) {
	receipt, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if err != nil {
		return orchestrator.RunReceipt{}, err
	}
	if receipt.Cleanup.Known() {
		return orchestrator.RunReceipt{}, errRunSettled
	}
	lock, err := service.authorizeClaim(root, request.Claim)
	if err != nil || lock.SessionID != sessionID || receipt.SessionID != sessionID || !receipt.Claim.Equal(request.Claim) {
		return orchestrator.RunReceipt{}, fmt.Errorf("active Run authority changed")
	}
	return receipt, nil
}

func (service *Service) resumeActiveExecution(ctx, runCtx context.Context, root string, request orchestrator.RunRequest, sessionID orchestrator.SessionID, phase string) (func(), orchestrator.RunReceipt, error) {
	reconcileCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	release, err := acquireOperation(reconcileCtx, root)
	if err != nil {
		return nil, orchestrator.RunReceipt{}, errors.Join(fmt.Errorf("%s reconciliation failed", phase), err)
	}
	receipt, err := service.activeReceipt(root, request, sessionID)
	if errors.Is(err, errRunSettled) {
		release()
		return nil, orchestrator.RunReceipt{}, fmt.Errorf("Run was settled during %s", phase)
	}
	if err != nil {
		release()
		return nil, orchestrator.RunReceipt{}, err
	}
	if err := runCtx.Err(); err != nil {
		failureErr := service.failReceiptWithCause(root, receipt, phase+" failed", err)
		release()
		return nil, orchestrator.RunReceipt{}, failureErr
	}
	return release, receipt, nil
}

func (service *Service) failActiveExecution(ctx context.Context, root string, request orchestrator.RunRequest, sessionID orchestrator.SessionID, message string, cause error) error {
	failureCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	release, err := acquireOperation(failureCtx, root)
	if err != nil {
		return errors.Join(fmt.Errorf("%s", message), err)
	}
	defer release()
	receipt, err := service.activeReceipt(root, request, sessionID)
	if errors.Is(err, errRunSettled) {
		return fmt.Errorf("%s", message)
	}
	if err != nil {
		return errors.Join(fmt.Errorf("%s", message), err)
	}
	return service.failReceiptWithCause(root, receipt, message, cause)
}

func (service *Service) Fetch(root string, request FetchRequest) ([]byte, error) {
	if request.SchemaVersion != 1 {
		return nil, fmt.Errorf("unsupported fetch schema version")
	}
	stored, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Receipt.Claim.RunID})
	if err != nil {
		return nil, err
	}
	if !stored.Claim.Equal(request.Receipt.Claim) || stored.SessionID == "" || stored.SessionID != request.Receipt.SessionID {
		return nil, fmt.Errorf("fetch authority does not match host receipt")
	}
	lock, err := service.authorizeClaim(root, stored.Claim)
	if err != nil || lock.SessionID != stored.SessionID {
		return nil, fmt.Errorf("fetch authority does not match Host Lock")
	}
	found := false
	for _, file := range stored.Evidence.Files {
		if file == request.File {
			found = true
			break
		}
	}
	if !found || safepath.ValidateWindowsRelative("evidence path", request.File.Path) != nil {
		return nil, fmt.Errorf("evidence file is not declared")
	}
	path := filepath.Join(runPath(root, stored.Claim.RunID), "evidence", filepath.FromSlash(request.File.Path))
	contents, err := readRegularFile(path, maxEvidenceFile)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(contents)
	if int64(len(contents)) != request.File.Size || hex.EncodeToString(hash[:]) != request.File.SHA256 {
		return nil, fmt.Errorf("evidence file changed")
	}
	return contents, nil
}

func (service *Service) Settle(ctx context.Context, root string, request SettleRequest) (orchestrator.CleanupState, error) {
	if request.SchemaVersion != 1 || request.Receipt.Claim.Validate() != nil || !target.ValidateWindowsPath(request.SessionBrokerExecutable) || request.SessionName != orchestrator.SessionNameForRun(request.Receipt.Claim.RunID) {
		return orchestrator.CleanupState{}, fmt.Errorf("invalid settle contract")
	}
	release, err := acquireOperation(ctx, root)
	if err != nil {
		return orchestrator.CleanupState{}, err
	}
	defer release()
	stored, err := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Receipt.Claim.RunID})
	if err != nil {
		lock, lockErr := service.authorizeClaim(root, request.Receipt.Claim)
		if lockErr != nil {
			return orchestrator.CleanupState{}, err
		}
		stored = orchestrator.RunReceipt{
			SchemaVersion: 1,
			Claim:         lock.Claim,
			State:         orchestrator.StateAccepted,
			SessionID:     lock.SessionID,
		}
	}
	if !stored.Claim.Equal(request.Receipt.Claim) {
		return orchestrator.CleanupState{}, fmt.Errorf("settle claim does not match host receipt")
	}
	if stored.Cleanup.Known() {
		cleanup, recovered, recoveryErr := service.recoverReleasedCleanup(root, stored)
		if recovered || recoveryErr != nil {
			return cleanup, recoveryErr
		}
	}
	lock, err := service.authorizeClaim(root, stored.Claim)
	if err != nil {
		cleanup, recovered, recoveryErr := service.recoverReleasedCleanup(root, stored)
		if recovered || recoveryErr != nil {
			return cleanup, recoveryErr
		}
		return orchestrator.CleanupState{}, fmt.Errorf("settle authority does not match Host Lock")
	}
	// The interactive task can write receipts. Physical authority still exists, so
	// repeat exact cleanup instead of trusting any persisted cleanup shortcut.
	stored.Cleanup = orchestrator.CleanupState{}
	if stored.State == orchestrator.StateStarting && stored.SessionID == "" && lock.SessionID != "" {
		stored.SessionID = lock.SessionID
	}
	if stored.SessionID != "" && lock.SessionID == "" {
		recovered, found, recoverErr := service.recoverUnpublishedSession(ctx, root, stored.Claim, request.SessionBrokerExecutable, request.SessionName)
		if recoverErr != nil {
			return orchestrator.CleanupState{}, recoverErr
		}
		if !found || recovered != stored.SessionID {
			return orchestrator.CleanupState{}, fmt.Errorf("settle could not verify unpublished Session identity")
		}
		lock.SessionID = recovered
		if err := service.writeLock(lockPath(root), lock); err != nil {
			return orchestrator.CleanupState{}, err
		}
	}
	if request.Receipt.SessionID != "" && request.Receipt.SessionID != stored.SessionID {
		return orchestrator.CleanupState{}, fmt.Errorf("settle Session identity does not match host receipt")
	}
	if lock.SessionID != stored.SessionID {
		return orchestrator.CleanupState{}, fmt.Errorf("settle authority does not match Host Lock")
	}
	if stored.SessionID == "" {
		recovered, found, recoverErr := service.recoverUnpublishedSession(ctx, root, stored.Claim, request.SessionBrokerExecutable, request.SessionName)
		if recoverErr != nil {
			return orchestrator.CleanupState{}, recoverErr
		}
		if found {
			lock.SessionID = recovered
			if err := service.writeLock(lockPath(root), lock); err != nil {
				return orchestrator.CleanupState{}, err
			}
			stored.SessionID = recovered
			stored.State = orchestrator.StateCleanupFailed
			stored.Error = "Recovered a Session whose Host Lock publication was interrupted"
			if err := service.writeReceipt(root, stored); err != nil {
				return orchestrator.CleanupState{}, err
			}
		} else if stored.State == orchestrator.StateStarting {
			launchRelease, acquired, launchErr := tryAcquireLaunch(root)
			if launchErr != nil {
				return orchestrator.CleanupState{}, launchErr
			}
			if !acquired {
				return orchestrator.CleanupState{}, fmt.Errorf("Session launch identity is not published yet")
			}
			launchRelease()
		}
	}
	if stored.SessionID != "" && !stored.Cleanup.SessionStopped {
		if service.daemon == nil {
			return orchestrator.CleanupState{}, fmt.Errorf("Session daemon is unavailable")
		}
		if err := service.daemon.Stop(ctx, DaemonStop{
			Executable:  request.SessionBrokerExecutable,
			Name:        request.SessionName,
			SessionID:   stored.SessionID,
			Environment: runEnvironment(root, stored.Claim.RunID),
		}); err != nil {
			return orchestrator.CleanupState{}, err
		}
	}
	stored.Cleanup.SessionStopped = true
	if err := service.writeReceipt(root, stored); err != nil {
		return orchestrator.CleanupState{}, err
	}
	runRoot := runPath(root, stored.Claim.RunID)
	if info, err := os.Lstat(runRoot); err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return orchestrator.CleanupState{}, fmt.Errorf("Run root ownership does not match")
		}
		ownershipPath := filepath.Join(runRoot, "ownership.json")
		var ownership lockRecord
		ownershipMissing := false
		if err := readJSON(ownershipPath, &ownership, maxScenarioJSON); err != nil {
			if _, statErr := os.Lstat(ownershipPath); !stored.Cleanup.SessionStopped || !os.IsNotExist(statErr) {
				return orchestrator.CleanupState{}, fmt.Errorf("Run root ownership does not match")
			}
			ownershipMissing = true
		} else if !ownership.Claim.Equal(stored.Claim) || ownership.SessionID != "" {
			return orchestrator.CleanupState{}, fmt.Errorf("Run root ownership does not match")
		}
		if ownershipMissing {
			entries, err := os.ReadDir(runRoot)
			if err != nil || len(entries) != 0 {
				return orchestrator.CleanupState{}, fmt.Errorf("Run root ownership does not match")
			}
			if err := os.Remove(runRoot); err != nil {
				return orchestrator.CleanupState{}, err
			}
		} else {
			if err := removeRunRootWithRetry(ctx, runRoot, os.RemoveAll, retryableRunRemoval, 100*time.Millisecond); err != nil {
				return orchestrator.CleanupState{}, err
			}
		}
	} else if !os.IsNotExist(err) {
		return orchestrator.CleanupState{}, err
	}
	stored.Cleanup.PayloadRemoved = true
	stored.Cleanup.RunRootRemoved = true
	currentLock, err := service.readLock(root)
	if err != nil || !currentLock.Claim.Equal(stored.Claim) || currentLock.SessionID != stored.SessionID {
		return orchestrator.CleanupState{}, fmt.Errorf("Host Lock changed before release")
	}
	if err := os.Remove(lockPath(root)); err != nil {
		return orchestrator.CleanupState{}, err
	}
	stored.Cleanup.LockReleased = true
	terminalizeSettledReceipt(&stored)
	if err := service.writeReceipt(root, stored); err != nil {
		return orchestrator.CleanupState{}, err
	}
	_ = os.Remove(filepath.Join(root, "pending-request.json"))
	return stored.Cleanup, nil
}

func (service *Service) recoverUnpublishedSession(ctx context.Context, root string, claim orchestrator.LockClaim, executable, name string) (orchestrator.SessionID, bool, error) {
	requestPath := filepath.Join(runPath(root, claim.RunID), "request.json")
	info, err := os.Lstat(requestPath)
	if os.IsNotExist(err) {
		return "", false, nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return "", false, fmt.Errorf("stored Run request is not a regular file")
	}
	if service.daemon == nil {
		return "", false, fmt.Errorf("Session daemon is unavailable")
	}
	// blendersessiond records the opaque identity before opening its Windows launch gate.
	return service.daemon.Recover(ctx, DaemonRecover{
		Executable:  executable,
		Name:        name,
		Environment: runEnvironment(root, claim.RunID),
	})
}

func (service *Service) recoverReleasedCleanup(root string, stored orchestrator.RunReceipt) (orchestrator.CleanupState, bool, error) {
	if !stored.Cleanup.SessionStopped {
		return orchestrator.CleanupState{}, false, nil
	}
	if _, err := os.Lstat(runPath(root, stored.Claim.RunID)); err == nil || !os.IsNotExist(err) {
		return orchestrator.CleanupState{}, false, nil
	}
	newerLock := false
	lockInfo, err := os.Lstat(lockPath(root))
	if err == nil {
		if !lockInfo.Mode().IsRegular() || lockInfo.Mode()&os.ModeSymlink != 0 {
			return orchestrator.CleanupState{}, true, fmt.Errorf("current Host Lock is invalid")
		}
		currentLock, readErr := service.readLock(root)
		if readErr != nil {
			return orchestrator.CleanupState{}, true, fmt.Errorf("inspect current Host Lock: %w", readErr)
		}
		if currentLock.SchemaVersion != 1 || currentLock.Claim.Validate() != nil || currentLock.SessionID != "" && currentLock.SessionID.Validate() != nil {
			return orchestrator.CleanupState{}, true, fmt.Errorf("current Host Lock is invalid")
		}
		if currentLock.Claim.Equal(stored.Claim) {
			return orchestrator.CleanupState{}, false, nil
		}
		newerLock = true
	} else if !os.IsNotExist(err) {
		return orchestrator.CleanupState{}, true, fmt.Errorf("inspect current Host Lock: %w", err)
	}
	stored.Cleanup.PayloadRemoved = true
	stored.Cleanup.RunRootRemoved = true
	stored.Cleanup.LockReleased = true
	terminalizeSettledReceipt(&stored)
	if err := service.writeReceipt(root, stored); err != nil {
		return orchestrator.CleanupState{}, true, err
	}
	if !newerLock {
		_ = os.Remove(filepath.Join(root, "pending-request.json"))
	}
	return stored.Cleanup, true, nil
}

func terminalizeSettledReceipt(receipt *orchestrator.RunReceipt) {
	switch receipt.State {
	case orchestrator.StateComplete, orchestrator.StateFailed, orchestrator.StateTimedOut, orchestrator.StateCleanupFailed:
		return
	default:
		receipt.State = orchestrator.StateFailed
		if receipt.Error == "" {
			receipt.Error = "Run stopped before completion"
		}
	}
}

func removeRunRootWithRetry(ctx context.Context, runRoot string, removeAll func(string) error, retryable func(error) bool, interval time.Duration) error {
	for {
		err := removeRunRootPreservingOwnership(runRoot, removeAll)
		if err == nil {
			return nil
		}
		if !retryable(err) {
			return err
		}
		if ctx.Err() != nil {
			return errors.Join(err, ctx.Err())
		}
		if interval <= 0 {
			continue
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(err, ctx.Err())
		case <-timer.C:
		}
	}
}

func retryableRunRemoval(err error) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	var errno syscall.Errno
	return errors.As(err, &errno) && errno == 32 // ERROR_SHARING_VIOLATION
}

func removeRunRootPreservingOwnership(runRoot string, removeAll func(string) error) error {
	entries, err := os.ReadDir(runRoot)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.EqualFold(entry.Name(), "ownership.json") {
			continue
		}
		if err := removeAll(filepath.Join(runRoot, entry.Name())); err != nil {
			return err
		}
	}
	ownershipPath := filepath.Join(runRoot, "ownership.json")
	if err := os.Remove(ownershipPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Remove(runRoot)
}

func (service *Service) callScenario(ctx context.Context, root string, request orchestrator.RunRequest, sessionID orchestrator.SessionID, environment map[string]string) ([]byte, error) {
	scriptPath := filepath.Join(runPath(root, request.Claim.RunID), "payload", filepath.FromSlash(request.Body.Payload.Scenario.Script))
	encodedPath, _ := json.Marshal(scriptPath)
	code := fmt.Sprintf("_bbx_path = %s\n_bbx_globals = {'bpy': bpy, '__file__': _bbx_path, '__name__': '__main__'}\nexec(compile(open(_bbx_path, encoding='utf-8').read(), _bbx_path, 'exec'), _bbx_globals)", encodedPath)
	parameters, _ := json.Marshal(map[string]string{"code": code})
	raw, err := service.daemon.Call(ctx, DaemonCall{
		Executable:         request.Body.SessionBrokerExecutable,
		Name:               request.Body.SessionName,
		SessionID:          sessionID,
		Command:            "execute_code",
		Parameters:         parameters,
		ReadTimeoutSeconds: request.Body.Payload.Scenario.ReadTimeoutSeconds,
		Environment:        environment,
	})
	if err != nil {
		return nil, err
	}
	var callResult struct {
		Executed bool   `json:"executed"`
		Result   string `json:"result"`
	}
	if err := decodeJSONBytes(raw, &callResult, maxProcessOutput); err != nil || !callResult.Executed || len(callResult.Result) > maxScenarioJSON {
		return nil, fmt.Errorf("invalid execute_code result")
	}
	result := []byte(strings.TrimSpace(callResult.Result))
	var contract map[string]json.RawMessage
	if err := decodeExtensibleJSON(result, &contract, maxScenarioJSON); err != nil {
		return nil, fmt.Errorf("Scenario Result did not pass")
	}
	var schemaVersion int
	var status string
	if json.Unmarshal(contract["schema_version"], &schemaVersion) != nil || json.Unmarshal(contract["status"], &status) != nil || schemaVersion != 1 || status != "pass" {
		return nil, fmt.Errorf("Scenario Result did not pass")
	}
	return append(result, '\n'), nil
}

func (service *Service) captureViewport(ctx context.Context, root string, request orchestrator.RunRequest, sessionID orchestrator.SessionID, environment map[string]string) (orchestrator.EvidenceFile, error) {
	path := filepath.Join(runPath(root, request.Claim.RunID), "evidence", "screenshots", "viewport.png")
	parameters, _ := json.Marshal(map[string]any{"filepath": path, "format": "png", "max_size": 1600})
	raw, err := service.daemon.Call(ctx, DaemonCall{
		Executable:         request.Body.SessionBrokerExecutable,
		Name:               request.Body.SessionName,
		SessionID:          sessionID,
		Command:            "get_viewport_screenshot",
		Parameters:         parameters,
		ReadTimeoutSeconds: 180,
		Environment:        environment,
	})
	if err != nil {
		return orchestrator.EvidenceFile{}, err
	}
	var capture struct {
		Success  bool   `json:"success"`
		Width    int    `json:"width"`
		Height   int    `json:"height"`
		Filepath string `json:"filepath"`
		Method   string `json:"method"`
		Error    string `json:"error,omitempty"`
	}
	if err := decodeExtensibleJSON(raw, &capture, maxScenarioJSON); err != nil || !capture.Success || capture.Width < 1 || capture.Height < 1 || capture.Filepath != path || (capture.Method != "offscreen" && capture.Method != "window_grab") {
		return orchestrator.EvidenceFile{}, fmt.Errorf("invalid viewport capture result")
	}
	contents, err := readRegularFile(path, maxEvidenceFile)
	if err != nil {
		return orchestrator.EvidenceFile{}, err
	}
	configuration, err := png.DecodeConfig(bytes.NewReader(contents))
	if err != nil || configuration.Width != capture.Width || configuration.Height != capture.Height {
		return orchestrator.EvidenceFile{}, fmt.Errorf("viewport capture is not the declared PNG")
	}
	file, err := evidenceFromFile(runPath(root, request.Claim.RunID), "screenshots/viewport.png", "viewport")
	if err != nil {
		return orchestrator.EvidenceFile{}, err
	}
	file.CaptureMethod = capture.Method
	file.Width = capture.Width
	file.Height = capture.Height
	return file, nil
}

func (service *Service) validateStagedRequest(root string, request orchestrator.RunRequest) error {
	var staged stagedManifest
	if err := readJSON(filepath.Join(runPath(root, request.Claim.RunID), "staged.json"), &staged, maxScenarioJSON); err != nil {
		return err
	}
	if staged.SchemaVersion != 1 || len(staged.Files) != len(request.Body.Payload.Files) {
		return fmt.Errorf("staged payload does not match request")
	}
	byDestination := make(map[string]StageFile, len(staged.Files))
	for _, file := range staged.Files {
		if err := safepath.ValidateWindowsRelative("staged destination", file.Destination); err != nil || file.Size < 0 || file.Size > maxStageFile || !hashPattern.MatchString(file.SHA256) {
			return fmt.Errorf("invalid staged payload manifest")
		}
		key := safepath.WindowsKey(file.Destination)
		if _, exists := byDestination[key]; exists {
			return fmt.Errorf("invalid staged payload manifest")
		}
		contents, err := readRegularFile(filepath.Join(runPath(root, request.Claim.RunID), "payload", filepath.FromSlash(file.Destination)), maxStageFile)
		if err != nil {
			return fmt.Errorf("published payload %q is invalid: %w", file.Destination, err)
		}
		hash := sha256.Sum256(contents)
		if int64(len(contents)) != file.Size || hex.EncodeToString(hash[:]) != file.SHA256 {
			return fmt.Errorf("published payload %q changed after transfer", file.Destination)
		}
		byDestination[key] = file
	}
	for _, file := range request.Body.Payload.Files {
		stagedFile, exists := byDestination[safepath.WindowsKey(file.Destination)]
		if !exists || stagedFile.Size != file.Size || stagedFile.SHA256 != file.SHA256 {
			return fmt.Errorf("staged payload does not match request")
		}
	}
	return nil
}

func validateStageFile(file StageFile) error {
	if err := safepath.ValidateWindowsRelative("staged destination", file.Destination); err != nil {
		return err
	}
	if file.Size < 0 || file.Size > maxStageFile || int64(len(file.Contents)) != file.Size || !hashPattern.MatchString(file.SHA256) {
		return fmt.Errorf("invalid staged file metadata")
	}
	hash := sha256.Sum256(file.Contents)
	if hex.EncodeToString(hash[:]) != file.SHA256 {
		return fmt.Errorf("staged file SHA-256 changed")
	}
	return nil
}

func (service *Service) authorizeClaim(root string, claim orchestrator.LockClaim) (lockRecord, error) {
	if err := claim.Validate(); err != nil {
		return lockRecord{}, err
	}
	lock, err := service.readLock(root)
	if err != nil {
		return lockRecord{}, err
	}
	if lock.SchemaVersion != 1 || !lock.Claim.Equal(claim) {
		return lockRecord{}, fmt.Errorf("Host Lock claim does not match")
	}
	return lock, nil
}

func (service *Service) readLock(root string) (lockRecord, error) {
	var lock lockRecord
	err := readJSON(lockPath(root), &lock, maxScenarioJSON)
	return lock, err
}

func (service *Service) writeReceipt(root string, receipt orchestrator.RunReceipt) error {
	return writeJSONAtomic(receiptPath(root, receipt.Claim.RunID), receipt)
}

func (service *Service) failExecution(root string, request orchestrator.RunRequest, message string) error {
	return service.failExecutionWithCause(root, request, message, nil)
}

func (service *Service) failExecutionWithCause(root string, request orchestrator.RunRequest, message string, cause error) error {
	receipt, _ := service.Status(root, StatusRequest{SchemaVersion: 1, RunID: request.Claim.RunID})
	if receipt.SchemaVersion == 0 {
		receipt = orchestrator.RunReceipt{SchemaVersion: 1, Claim: request.Claim}
	}
	return service.failReceiptWithCause(root, receipt, message, cause)
}

func (service *Service) failReceipt(root string, receipt orchestrator.RunReceipt, message string) error {
	return service.failReceiptWithCause(root, receipt, message, nil)
}

func (service *Service) failReceiptWithCause(root string, receipt orchestrator.RunReceipt, message string, cause error) error {
	if errors.Is(cause, context.DeadlineExceeded) {
		receipt.State = orchestrator.StateTimedOut
	} else {
		receipt.State = orchestrator.StateFailed
	}
	receipt.Error = message
	if err := service.writeReceipt(root, receipt); err != nil {
		return errors.Join(fmt.Errorf("%s", message), err)
	}
	if cause != nil {
		return fmt.Errorf("%s: %w", message, cause)
	}
	return fmt.Errorf("%s", message)
}

func runEnvironment(root string, runID orchestrator.RunID) map[string]string {
	runRoot := runPath(root, runID)
	return map[string]string{
		"BLENDERSESSIOND_STATE_DIR": filepath.Join(runRoot, "daemon"),
		"BLENDER_USER_RESOURCES":    filepath.Join(runRoot, "blender-resources"),
		"BLENDER_USER_CONFIG":       filepath.Join(runRoot, "blender-config"),
		"BLENDER_USER_SCRIPTS":      filepath.Join(runRoot, "blender-scripts"),
		"BLENDER_USER_DATAFILES":    filepath.Join(runRoot, "blender-data"),
		"BLENDER_USER_EXTENSIONS":   filepath.Join(runRoot, "blender-extensions"),
	}
}

func evidenceFromFile(runRoot, relative, kind string) (orchestrator.EvidenceFile, error) {
	path := filepath.Join(runRoot, "evidence", filepath.FromSlash(relative))
	contents, err := readRegularFile(path, maxEvidenceFile)
	if err != nil {
		return orchestrator.EvidenceFile{}, err
	}
	hash := sha256.Sum256(contents)
	return orchestrator.EvidenceFile{Path: relative, Type: kind, Size: int64(len(contents)), SHA256: hex.EncodeToString(hash[:])}, nil
}

func readRegularFile(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("evidence is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(contents)) > limit {
		return nil, fmt.Errorf("evidence exceeds file limit")
	}
	return contents, nil
}

func validateRoot(root string) error {
	if !filepath.IsAbs(root) {
		return fmt.Errorf("state root must be absolute")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("state root must be an existing regular directory")
	}
	return nil
}

func lockPath(root string) string { return filepath.Join(root, "host-lock.json") }
func runPath(root string, runID orchestrator.RunID) string {
	return filepath.Join(root, "runs", string(runID))
}
func receiptPath(root string, runID orchestrator.RunID) string {
	return filepath.Join(root, "receipts", string(runID)+".json")
}

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".blender-box-state-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if err := json.NewEncoder(temporary).Encode(value); err != nil {
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
	return replaceFile(name, path)
}

func writeLockAtomic(path string, lock lockRecord) error {
	return writeJSONAtomic(path, lock)
}

func writeFileExclusive(path string, contents []byte) (bool, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return false, err
	}
	cleanup := func(cause error) error {
		closeErr := file.Close()
		removeErr := os.Remove(path)
		return errors.Join(cause, closeErr, removeErr)
	}
	written, err := file.Write(contents)
	if err != nil {
		return true, cleanup(err)
	}
	if written != len(contents) {
		return true, cleanup(io.ErrShortWrite)
	}
	if err := file.Sync(); err != nil {
		return true, cleanup(err)
	}
	if err := file.Close(); err != nil {
		removeErr := os.Remove(path)
		return true, errors.Join(err, removeErr)
	}
	return true, nil
}

func readJSON(path string, value any, limit int64) error {
	contents, err := readRegularFile(path, limit)
	if err != nil {
		return err
	}
	return decodeJSONBytes(contents, value, limit)
}

func decodeJSONBytes(contents []byte, value any, limit int64) error {
	if int64(len(contents)) > limit {
		return fmt.Errorf("JSON exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("JSON has trailing value")
	}
	return nil
}

func decodeExtensibleJSON(contents []byte, value any, limit int64) error {
	if int64(len(contents)) > limit {
		return fmt.Errorf("JSON exceeds limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("JSON has trailing value")
	}
	return nil
}
