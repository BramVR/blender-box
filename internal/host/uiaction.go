package host

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/uiaction"
)

type UIActor interface {
	CheckUI(context.Context, string, string) error
	Perform(context.Context, AuthorizedAction) (uiaction.Receipt, error)
}
type AuthorizedAction struct {
	Claim       orchestrator.LockClaim
	SessionID   orchestrator.SessionID
	SessionName string
	Executable  string
	Environment map[string]string
	RunRoot     string
	Index       int
	Action      uiaction.Action
}

//go:embed ui_events.py
var uiEventsProgram string

func (r *Runtime) CheckUI(ctx context.Context, broker, blender string) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("UI events require Windows")
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := r.processes.Run(ctx, broker, []string{"capabilities", "--require", "blender-box-v1", "--require-capability", uiaction.Capability}, nil); err != nil {
		return fmt.Errorf("Session broker UI capability is unavailable")
	}
	out, err := r.processes.Run(ctx, blender, []string{"--help"}, nil)
	if err != nil || !strings.Contains(string(out), "--enable-event-simulate") {
		return fmt.Errorf("Blender event simulation is unavailable")
	}
	return nil
}

type uiAcknowledgement struct {
	SchemaVersion int                    `json:"schema_version"`
	Claim         orchestrator.LockClaim `json:"claim"`
	SessionID     orchestrator.SessionID `json:"session_id"`
	Nonce         string                 `json:"nonce"`
	Receipt       uiaction.Receipt       `json:"receipt"`
}

func (r *Runtime) Perform(ctx context.Context, request AuthorizedAction) (uiaction.Receipt, error) {
	receipt := uiaction.Receipt{Index: request.Index, Kind: request.Action.Kind(), SessionID: string(request.SessionID), Outcome: uiaction.Uncertain, ErrorCode: "delivery-unknown"}
	if request.Claim.Validate() != nil || request.SessionID.Validate() != nil || request.SessionName != orchestrator.SessionNameForRun(request.Claim.RunID) || !request.Claim.Deadline.After(time.Now()) {
		receipt.Outcome = uiaction.Rejected
		receipt.ErrorCode = "stale-session"
		return receipt, fmt.Errorf("UI action authority is invalid")
	}
	if ctx.Err() != nil {
		return receipt, uiFailure("UI action acknowledgement unavailable", ctx.Err())
	}
	if validateRoot(request.RunRoot) != nil || filepath.Base(request.RunRoot) != string(request.Claim.RunID) {
		return receipt, fmt.Errorf("UI action Run root is invalid")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return receipt, fmt.Errorf("UI acknowledgement identity unavailable")
	}
	nonce := fmt.Sprintf("%x", random)
	directory := filepath.Join(request.RunRoot, fmt.Sprintf(".ui-action-%d-%s", request.Index, nonce))
	if err := os.Mkdir(directory, 0o700); err != nil {
		return receipt, fmt.Errorf("UI acknowledgement directory unavailable")
	}
	path := filepath.Join(directory, "ack.json")
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		return receipt, fmt.Errorf("UI acknowledgement already exists")
	}
	data := map[string]any{"session_id": request.SessionID, "request_hash": request.Claim.RequestHash, "claim": request.Claim, "nonce": nonce, "ack_path": path, "index": request.Index, "action": request.Action}
	deadline := request.Claim.Deadline
	if actionDeadline, ok := ctx.Deadline(); ok && actionDeadline.Before(deadline) {
		deadline = actionDeadline
	}
	data["deadline"] = float64(deadline.UnixNano()) / 1e9
	encoded, _ := json.Marshal(data)
	code := fmt.Sprintf("import base64, json\n_bbx_ui_globals = {'bpy': bpy}\nexec(compile(base64.b64decode('%s'), '<blender-box-ui>', 'exec'), _bbx_ui_globals)\nprint(json.dumps(_bbx_ui_globals['ui_action'](json.loads(base64.b64decode('%s')))))", base64.StdEncoding.EncodeToString([]byte(uiEventsProgram)), base64.StdEncoding.EncodeToString(encoded))
	params, _ := json.Marshal(map[string]string{"code": code})
	raw, err := r.Call(ctx, DaemonCall{Executable: request.Executable, Name: request.SessionName, SessionID: request.SessionID, Command: "execute_code", Parameters: params, ReadTimeoutSeconds: uiaction.MaxActionSeconds, Environment: request.Environment})
	if err != nil {
		return receipt, uiFailure("UI action delivery acknowledgement unavailable", errors.Join(err, ctx.Err()))
	}
	var envelope struct {
		Executed bool   `json:"executed"`
		Result   string `json:"result"`
	}
	var reply struct {
		SchemaVersion int              `json:"schema_version"`
		Ready         bool             `json:"ready"`
		Receipt       uiaction.Receipt `json:"receipt"`
	}
	if decodeJSONBytes(raw, &envelope, maxProcessOutput) != nil || !envelope.Executed || decodeJSONBytes([]byte(strings.TrimSpace(envelope.Result)), &reply, 16<<10) != nil || reply.SchemaVersion != 1 {
		return receipt, fmt.Errorf("invalid UI action acknowledgement")
	}
	validReceipt := func(got uiaction.Receipt) bool {
		return got.Index == request.Index && got.Kind == request.Action.Kind() && got.SessionID == string(request.SessionID) && got.Validate(string(request.SessionID)) == nil && (got.Outcome != uiaction.Queued || got.EventCount == request.Action.EventCount())
	}
	if !validReceipt(reply.Receipt) {
		return receipt, fmt.Errorf("invalid UI action receipt")
	}
	if ctx.Err() != nil {
		return receipt, uiFailure("UI action acknowledgement unavailable", ctx.Err())
	}
	if reply.Ready {
		if reply.Receipt.Outcome != uiaction.Rejected && reply.Receipt.Outcome != uiaction.Uncertain {
			return receipt, fmt.Errorf("invalid terminal UI acknowledgement")
		}
		return reply.Receipt, nil
	}
	if reply.Receipt.Outcome != uiaction.Pending {
		return receipt, fmt.Errorf("invalid pending UI acknowledgement")
	}
	for {
		if ctx.Err() != nil {
			return receipt, uiFailure("UI action acknowledgement unavailable", ctx.Err())
		}
		if validateRoot(request.RunRoot) != nil || validateRoot(directory) != nil {
			return receipt, fmt.Errorf("UI acknowledgement directory changed")
		}
		if _, err := os.Lstat(path); err == nil {
			contents, readErr := readRegularFile(path, 16<<10)
			var ack uiAcknowledgement
			if readErr != nil || decodeJSONBytes(contents, &ack, 16<<10) != nil || ack.SchemaVersion != 1 || !ack.Claim.Equal(request.Claim) || ack.SessionID != request.SessionID || ack.Nonce != nonce || !validReceipt(ack.Receipt) || ack.Receipt.Outcome == uiaction.Pending {
				return receipt, fmt.Errorf("invalid UI action acknowledgement")
			}
			if ctx.Err() != nil {
				return receipt, uiFailure("UI action acknowledgement unavailable", ctx.Err())
			}
			return ack.Receipt, nil
		} else if !os.IsNotExist(err) {
			return receipt, fmt.Errorf("UI acknowledgement unavailable")
		}
		if err := waitRuntimePoll(ctx, 50*time.Millisecond); err != nil {
			return receipt, uiFailure("UI action acknowledgement unavailable", err)
		}
	}
}

func (service *Service) executeUIActions(ctx context.Context, root string, request orchestrator.RunRequest, sessionID orchestrator.SessionID, environment map[string]string) error {
	batch := request.Body.Payload.Scenario.UIActions
	batchCtx, cancel := context.WithTimeout(ctx, time.Duration(batch.TimeoutSeconds)*time.Second)
	defer cancel()
	release, receipt, err := service.resumeActiveExecution(ctx, batchCtx, root, request, sessionID, "UI batch start")
	if err != nil {
		return err
	}
	receipt.State = orchestrator.StateInteracting
	receipt.UIActions = &uiaction.Journal{SchemaVersion: 1, Receipts: []uiaction.Receipt{}}
	if err = service.writeReceipt(root, receipt); err != nil {
		release()
		return err
	}
	if request.Body.Payload.Scenario.CaptureBlenderWindow {
		pending, captureErr := service.captureBlenderWindow(batchCtx, root, request, sessionID, environment)
		if captureErr != nil {
			err = service.failReceiptWithCause(root, receipt, "UI before capture failed", contextFailure(errors.Join(captureErr, batchCtx.Err())))
			release()
			return err
		}
		pending.definition.EvidencePath = uiaction.BeforePath
		pending.definition.SourcePath = "evidence/" + uiaction.BeforePath
		file, publishErr := publishCapturePNG(runPath(root, request.Claim.RunID), pending, 3, sessionID)
		cleanupCaptureTemporary(runPath(root, request.Claim.RunID), pending.temporaryPath)
		if publishErr != nil {
			err = service.failReceipt(root, receipt, "UI before capture publication failed")
			release()
			return err
		}
		receipt.Evidence.Files = append(receipt.Evidence.Files, file)
		if err = service.writeReceipt(root, receipt); err != nil {
			release()
			return err
		}
	}
	release()
	for index, action := range batch.Actions {
		release, receipt, err = service.resumeActiveExecution(ctx, batchCtx, root, request, sessionID, "UI action admission")
		if err != nil {
			return err
		}
		if receipt.State != orchestrator.StateInteracting || receipt.UIActions == nil || len(receipt.UIActions.Receipts) != index {
			release()
			return fmt.Errorf("UI action journal cannot be replayed")
		}
		pending := uiaction.Receipt{Index: index, Kind: action.Kind(), SessionID: string(sessionID), Outcome: uiaction.Pending}
		receipt.UIActions.Receipts = append(receipt.UIActions.Receipts, pending)
		if err = service.writeReceipt(root, receipt); err != nil {
			release()
			return err
		}
		actionCtx, cancelAction := context.WithTimeout(batchCtx, uiaction.MaxActionSeconds*time.Second)
		result := pending
		var failureCause error
		if service.uiActor == nil {
			result.Outcome = uiaction.Rejected
			result.ErrorCode = "unsupported"
		} else {
			result, err = service.uiActor.Perform(actionCtx, AuthorizedAction{Claim: request.Claim, SessionID: sessionID, SessionName: request.Body.SessionName, Executable: request.Body.SessionBrokerExecutable, Environment: environment, RunRoot: runPath(root, request.Claim.RunID), Index: index, Action: action})
			if err != nil {
				result = pending
				result.Outcome = uiaction.Uncertain
				result.ErrorCode = "delivery-unknown"
				failureCause = contextFailure(errors.Join(err, actionCtx.Err()))
				if errors.Is(failureCause, context.DeadlineExceeded) {
					result.ErrorCode = "timed-out"
				} else if errors.Is(failureCause, context.Canceled) {
					result.ErrorCode = "cancelled"
				}
			}
		}
		cancelAction()
		receipt.UIActions.Receipts[index] = result
		if result.Index != index || result.Kind != action.Kind() || result.SessionID != string(sessionID) || (result.Outcome == uiaction.Pending || result.Outcome == uiaction.Queued && result.EventCount != action.EventCount()) || receipt.UIActions.Validate(string(sessionID)) != nil {
			receipt.UIActions.Receipts[index] = pending
			receipt.UIActions.MarkUncertain()
			result = receipt.UIActions.Receipts[index]
		}
		if result.Outcome != uiaction.Queued {
			if result.ErrorCode == "timed-out" {
				failureCause = context.DeadlineExceeded
			} else if result.ErrorCode == "cancelled" {
				failureCause = context.Canceled
			}
			err = service.failReceiptWithCause(root, receipt, "UI action batch failed", failureCause)
			release()
			return err
		}
		if err = service.writeReceipt(root, receipt); err != nil {
			release()
			return err
		}
		release()
	}
	release, receipt, err = service.resumeActiveExecution(ctx, batchCtx, root, request, sessionID, "UI batch acknowledgement")
	if err != nil {
		return err
	}
	defer release()
	if err := service.publishUIJournal(root, &receipt); err != nil {
		return service.failReceipt(root, receipt, "UI journal publication failed")
	}
	receipt.State = orchestrator.StateCollecting
	return service.writeReceipt(root, receipt)
}

func (service *Service) publishUIJournal(root string, receipt *orchestrator.RunReceipt) error {
	if receipt.UIActions == nil {
		return nil
	}
	receipt.UIActions.MarkUncertain()
	if err := receipt.UIActions.Validate(string(receipt.SessionID)); err != nil {
		return err
	}
	for _, file := range receipt.Evidence.Files {
		if file.Type == orchestrator.EvidenceUIActions {
			return nil
		}
	}
	path := filepath.Join(runPath(root, receipt.Claim.RunID), "evidence", "result", "ui-actions.json")
	if err := writeJSONAtomic(path, receipt.UIActions); err != nil {
		return err
	}
	file, err := evidenceFromFile(runPath(root, receipt.Claim.RunID), uiaction.EvidencePath, orchestrator.EvidenceUIActions, 3, receipt.SessionID)
	if err != nil {
		return err
	}
	receipt.Evidence.SchemaVersion = 3
	receipt.Evidence.Files = append(receipt.Evidence.Files, file)
	return nil
}

func contextFailure(cause error) error {
	if errors.Is(cause, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	if errors.Is(cause, context.Canceled) {
		return context.Canceled
	}
	return nil
}
func uiFailure(message string, cause error) error {
	if typed := contextFailure(cause); typed != nil {
		return fmt.Errorf("%s: %w", message, typed)
	}
	return errors.New(message)
}
