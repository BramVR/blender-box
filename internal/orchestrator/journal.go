package orchestrator

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/target"
)

const maxAuthoritySize = 16 << 10

type authorityError struct{ cause error }

func (failure *authorityError) Error() string { return failure.cause.Error() }
func (failure *authorityError) Unwrap() error { return failure.cause }
func IsAuthorityError(err error) bool         { var failure *authorityError; return errors.As(err, &failure) }
func authorityFailure(message string) error {
	return &authorityError{cause: fmt.Errorf("insufficient recovery authority: %s", message)}
}

type runAuthority struct {
	SchemaVersion int       `json:"schema_version"`
	Claim         LockClaim `json:"claim"`
	Fingerprint   string    `json:"target_fingerprint"`
}
type sessionPin struct {
	SchemaVersion int       `json:"schema_version"`
	RunID         RunID     `json:"run_id"`
	Claim         LockClaim `json:"claim"`
	Fingerprint   string    `json:"target_fingerprint"`
	SessionID     SessionID `json:"session_id"`
}
type journal struct{ root string }

func claimPath(runID RunID) string { return filepath.Join("runs", string(runID)+".json") }
func pinPath(runID RunID) string   { return filepath.Join("runs", string(runID)+".session.json") }

func (journal journal) record(selected target.Target, claim LockClaim) error {
	if err := selected.Validate(); err != nil {
		return err
	}
	if err := claim.Validate(); err != nil {
		return err
	}
	data, err := json.Marshal(runAuthority{SchemaVersion: 1, Claim: claim, Fingerprint: selected.Fingerprint()})
	if err != nil {
		return err
	}
	if len(data) > maxAuthoritySize-1024 {
		return authorityFailure("original Run claim exceeds size limit")
	}
	if err := privatefile.Publish(journal.root, claimPath(claim.RunID), data, false); err != nil {
		return authorityFailure("cannot publish original Run claim")
	}
	return nil
}
func (journal journal) load(selected target.Target, runID RunID) (runAuthority, SessionID, error) {
	if err := selected.Validate(); err != nil {
		return runAuthority{}, "", err
	}
	if err := runID.Validate(); err != nil {
		return runAuthority{}, "", err
	}
	data, err := privatefile.ReadDurable(journal.root, claimPath(runID), maxAuthoritySize)
	if err != nil {
		return runAuthority{}, "", authorityFailure("original Run claim is unavailable")
	}
	var record runAuthority
	if err := strictjson.Decode(data, &record); err != nil || record.SchemaVersion != 1 || record.Claim.Validate() != nil || record.Claim.RunID != runID || !hashPattern.MatchString(record.Fingerprint) {
		return runAuthority{}, "", authorityFailure("original Run claim is invalid")
	}
	if record.Fingerprint != selected.Fingerprint() {
		return runAuthority{}, "", &authorityError{cause: fmt.Errorf("target does not match original Run")}
	}
	data, err = privatefile.ReadDurable(journal.root, pinPath(runID), maxAuthoritySize)
	if os.IsNotExist(err) {
		return record, "", nil
	}
	if err != nil {
		return runAuthority{}, "", authorityFailure("Session pin is unavailable")
	}
	var pin sessionPin
	if err := strictjson.Decode(data, &pin); err != nil || pin.SchemaVersion != 1 || pin.RunID != runID || !pin.Claim.Equal(record.Claim) || pin.Fingerprint != record.Fingerprint || pin.SessionID.Validate() != nil {
		return runAuthority{}, "", authorityFailure("Session pin is invalid")
	}
	return record, pin.SessionID, nil
}
func (journal journal) accept(selected target.Target, receipt RunReceipt) error {
	record, session, err := journal.load(selected, receipt.Claim.RunID)
	if err != nil {
		return err
	}
	if !record.Claim.Equal(receipt.Claim) {
		return authorityFailure("Host Lock claim changed")
	}
	if session != "" && session != receipt.SessionID {
		return authorityFailure("Session identity changed")
	}
	if receipt.SessionID == "" {
		return nil
	}
	if receipt.SessionID.Validate() != nil {
		return authorityFailure("Session identity is invalid")
	}
	if session != "" {
		return nil
	}
	data, err := json.Marshal(sessionPin{SchemaVersion: 1, RunID: record.Claim.RunID, Claim: record.Claim, Fingerprint: record.Fingerprint, SessionID: receipt.SessionID})
	if err != nil {
		return authorityFailure("cannot encode Session pin")
	}
	if err := privatefile.Publish(journal.root, pinPath(record.Claim.RunID), data, false); err != nil {
		if os.IsExist(err) {
			_, pinned, loadErr := journal.load(selected, record.Claim.RunID)
			if loadErr == nil && pinned == receipt.SessionID {
				return nil
			}
		}
		return authorityFailure("cannot publish Session pin")
	}
	return nil
}

func (journal journal) settlement(selected target.Target, receipt RunReceipt) (RunReceipt, error) {
	record, session, err := journal.load(selected, receipt.Claim.RunID)
	if err != nil {
		return RunReceipt{}, err
	}
	if !record.Claim.Equal(receipt.Claim) {
		return RunReceipt{}, authorityFailure("Host Lock claim changed")
	}
	if receipt.SessionID != "" && session != receipt.SessionID {
		return RunReceipt{}, authorityFailure("Session identity is not pinned")
	}
	receipt.SessionID = session
	return receipt, nil
}
