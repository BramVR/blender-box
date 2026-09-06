package orchestrator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BramVR/blender-box/internal/uiaction"
)

func (runner *Runner) recoverUIFailure(ctx context.Context, intent RunIntent, previous RunReceipt, root string) (RunResult, bool, error) {
	recoveryCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), runner.settlementTTL())
	defer cancel()
	receipt, observeErr := runner.recoverReceipt(recoveryCtx, intent.Target, intent.RunID)
	if observeErr != nil || !receipt.Claim.Equal(previous.Claim) || (previous.SessionID != "" && receipt.SessionID != previous.SessionID) {
		return RunResult{}, false, fmt.Errorf("UI failure receipt could not be recovered")
	}
	if err := uiaction.ValidateProgress(previous.UIActions, receipt.UIActions); err != nil {
		return RunResult{}, false, err
	}
	if err := validateUIBatchReceipt(receipt, intent.Payload.Scenario.UIActions); err != nil {
		return RunResult{}, false, err
	}
	available := EvidenceManifest{SchemaVersion: 3, Files: []EvidenceFile{}}
	var recoveryErr error
	for _, file := range receipt.Evidence.Files {
		one := receipt
		one.State = StateFailed
		one.Evidence = EvidenceManifest{SchemaVersion: 3, Files: []EvidenceFile{file}}
		if err := validateEvidenceManifest(one.Evidence, receipt.SessionID); err != nil {
			recoveryErr = errors.Join(recoveryErr, err)
			continue
		}
		if err := validatePartialEvidence(one.Evidence, intent.Payload.Scenario); err != nil {
			recoveryErr = errors.Join(recoveryErr, err)
			continue
		}
		local, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.Path)))
		if os.IsNotExist(err) {
			err = runner.collectEvidence(recoveryCtx, intent, one, root)
		} else if err == nil {
			digest := sha256.Sum256(local)
			if int64(len(local)) != file.Size || hex.EncodeToString(digest[:]) != file.SHA256 {
				err = fmt.Errorf("existing UI failure evidence changed")
			}
		}
		if err != nil {
			recoveryErr = errors.Join(recoveryErr, err)
			continue
		}
		available.Files = append(available.Files, file)
	}
	cleanup, err := runner.settle(ctx, intent.Target, receipt)
	if err != nil || !cleanup.Known() {
		return RunResult{}, false, errors.Join(recoveryErr, err, fmt.Errorf("UI failure cleanup is not known"))
	}
	terminal, err := runner.recoverReceipt(recoveryCtx, intent.Target, intent.RunID)
	if err != nil || !terminal.Claim.Equal(receipt.Claim) || terminal.SessionID != receipt.SessionID || !terminal.Cleanup.Known() {
		return RunResult{}, true, errors.Join(recoveryErr, fmt.Errorf("settled UI receipt could not be verified"))
	}
	if err := uiaction.ValidateProgress(receipt.UIActions, terminal.UIActions); err != nil {
		return RunResult{}, true, err
	}
	if err := validateUIBatchReceipt(terminal, intent.Payload.Scenario.UIActions); err != nil {
		return RunResult{}, true, err
	}
	recoveredJournal := false
	if terminal.UIActions != nil {
		hasJournal := false
		for _, file := range available.Files {
			hasJournal = hasJournal || file.Type == EvidenceUIActions
		}
		if !hasJournal {
			var encoded bytes.Buffer
			_ = json.NewEncoder(&encoded).Encode(terminal.UIActions)
			digest := sha256.Sum256(encoded.Bytes())
			for _, file := range terminal.Evidence.Files {
				if file.Type != EvidenceUIActions {
					continue
				}
				if file.Path != uiaction.EvidencePath || file.Size != int64(encoded.Len()) || file.SHA256 != hex.EncodeToString(digest[:]) {
					recoveryErr = errors.Join(recoveryErr, fmt.Errorf("recovered UI journal hash differs from host evidence"))
					break
				}
				if err := writeEvidence(root, file.Path, encoded.Bytes()); err != nil {
					recoveryErr = errors.Join(recoveryErr, err)
					break
				}
				available.Files = append(available.Files, file)
				recoveredJournal = true
			}
		}
	}
	result := RunResult{SchemaVersion: 1, RunID: terminal.Claim.RunID, RequestID: terminal.Claim.RequestID, RequestHash: terminal.Claim.RequestHash, Deadline: terminal.Claim.Deadline, SessionID: terminal.SessionID, State: terminal.State, Evidence: available, Cleanup: cleanup, Error: terminal.Error, UIActions: terminal.UIActions, UIJournalRecoveredFromReceipt: recoveredJournal}
	if err := publishBundleMetadata(root, result); err != nil {
		recoveryErr = errors.Join(recoveryErr, err)
	}
	return result, true, recoveryErr
}
