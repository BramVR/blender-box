package pairing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/BramVR/blender-box/internal/privatefile"
	sshtransport "github.com/BramVR/blender-box/internal/ssh"
	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/target"
)

// Remote is the host side of client revocation, reached with the paired key itself.
type Remote interface {
	RevokePairing(ctx context.Context, paired target.Target, request RevokeRequest) (RevokeResult, error)
	// Probe opens a fresh paired SSH connection and runs a no-op; nil means the key still authenticates.
	Probe(ctx context.Context, paired target.Target) error
}

const (
	Revoked = "revoked"
	// KeyRejected means the host returned no revocation result but a fresh paired connection is
	// rejected; local state is forgotten, yet host removal of the line stays unconfirmed.
	KeyRejected            = "key-rejected"
	HostRevokedUnconfirmed = "host-revoked-unconfirmed"
	Unconfirmed            = "unconfirmed"
)

const (
	hostRevoked         = "revoked"
	hostAlreadyRejected = "already-rejected"
)

type RevokeOutcome struct {
	SchemaVersion int    `json:"schema_version"`
	PairID        string `json:"pair_id"`
	State         string `json:"state"`
	Host          string `json:"host,omitempty"`
	Failure       string `json:"failure,omitempty"`
	Next          string `json:"next,omitempty"`
}

type ForgetResult struct {
	SchemaVersion int    `json:"schema_version"`
	PairID        string `json:"pair_id,omitempty"`
	RemoteAccess  string `json:"remote_access"`
	Next          string `json:"next,omitempty"`
}

// revocation records what the host said, so a retry after a lost probe repeats only the probe.
// Result is present exactly when Host is "revoked".
type revocation struct {
	SchemaVersion int           `json:"schema_version"`
	PairID        string        `json:"pair_id"`
	Host          string        `json:"host"`
	Result        *RevokeResult `json:"result,omitempty"`
}

// Revoke removes remote access through the host, then proves a fresh paired connection is
// rejected before it forgets local state. Any outcome other than "revoked" returns an error.
func (client Client) Revoke(ctx context.Context, name string, remote Remote) (RevokeOutcome, error) {
	value, err := client.read(name)
	if err != nil {
		return RevokeOutcome{}, err
	}
	receipt, err := client.readReceipt(value)
	if errors.Is(err, os.ErrNotExist) {
		return RevokeOutcome{}, fmt.Errorf("pairing has no accepted enrollment receipt; run pair forget %s", name)
	}
	if err != nil {
		return RevokeOutcome{}, err
	}
	pairID := receipt.PairID
	record, err := client.readRevocation(name)
	if errors.Is(err, os.ErrNotExist) {
		fingerprint, _ := sshkey.Fingerprint(receipt.PublicKey)
		result, revokeErr := remote.RevokePairing(ctx, receipt.Target, RevokeRequest{SchemaVersion: 1, PairID: pairID, ClientPublicKeyHash: fingerprint})
		switch {
		case revokeErr == nil:
			record = revocation{1, pairID, hostRevoked, &result}
		case failureClass(revokeErr) == sshtransport.AuthRejected:
			record = revocation{1, pairID, hostAlreadyRejected, nil}
		default:
			outcome := RevokeOutcome{1, pairID, Unconfirmed, "", string(failureClass(revokeErr)), fmt.Sprintf("retry pair revoke %s once the host is reachable, or remove the key on the host with `%s`", name, hostCommand(value.Offer.Installed, "revoke", pairID))}
			return outcome, fmt.Errorf("revocation unconfirmed; local pairing state kept: %w", revokeErr)
		}
		if record, err = client.publishRevocation(name, record); err != nil {
			return RevokeOutcome{}, err
		}
	} else if err != nil {
		return RevokeOutcome{}, err
	}
	if record.PairID != pairID {
		return RevokeOutcome{}, fmt.Errorf("revocation record names a different pair")
	}
	outcome := RevokeOutcome{SchemaVersion: 1, PairID: pairID, Host: record.Host}
	probeErr := remote.Probe(ctx, receipt.Target)
	switch {
	case probeErr == nil:
		outcome.State = HostRevokedUnconfirmed
		outcome.Next = fmt.Sprintf("check the host for another authorized copy of this key, then repeat pair revoke %s", name)
		return outcome, fmt.Errorf("host reported revocation but a fresh paired connection still authenticates; local pairing state kept")
	case failureClass(probeErr) == sshtransport.AuthRejected:
		if _, err := client.forget(name, value, true, &receipt, record); err != nil {
			return RevokeOutcome{}, fmt.Errorf("fresh paired connection rejected; local cleanup incomplete, repeat pair forget %s: %w", name, err)
		}
		outcome.State = Revoked
		if record.Host == hostAlreadyRejected {
			outcome.State = KeyRejected
			outcome.Next = fmt.Sprintf("the host returned no revocation result in this attempt, but a fresh paired connection is rejected; confirm on the host with `%s`", hostCommand(value.Offer.Installed, "status", pairID))
		}
		return outcome, nil
	default:
		outcome.State = HostRevokedUnconfirmed
		outcome.Failure = string(failureClass(probeErr))
		outcome.Next = fmt.Sprintf("repeat pair revoke %s; only the fresh-connection rejection check repeats", name)
		return outcome, fmt.Errorf("fresh paired connection not proven rejected; local pairing state kept: %w", probeErr)
	}
}

// Forget removes local pairing state without contacting the host. It refuses while an accepted
// receipt has no host-confirmed revocation, unless keepRemoteAccess acknowledges the remaining key.
func (client Client) Forget(ctx context.Context, name string, keepRemoteAccess bool) (ForgetResult, error) {
	if err := ctx.Err(); err != nil {
		return ForgetResult{}, err
	}
	// Without an exported intent only the preparation remains; its key is a placeholder.
	value, err := client.read(name)
	exported := err == nil
	if errors.Is(err, os.ErrNotExist) {
		value, err = client.readPreparation(name)
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ForgetResult{}, err
	}
	var receipt *EnrollmentReceipt
	if exported {
		accepted, err := client.readReceipt(value)
		if err == nil {
			receipt = &accepted
		} else if !errors.Is(err, os.ErrNotExist) {
			return ForgetResult{}, err
		}
	}
	record, err := client.readRevocation(name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return ForgetResult{}, err
	}
	if receipt != nil && record.Host != hostRevoked && !keepRemoteAccess {
		return ForgetResult{}, fmt.Errorf("pair %s still has accepted remote access; run `blender-box pair revoke %s`, or on the host run `%s` and then pass --keep-remote-access", receipt.PairID, name, hostCommand(value.Offer.Installed, "revoke", receipt.PairID))
	}
	return client.forget(name, value, exported, receipt, record)
}

// forget deletes in an order a retry can resume: the target and receipt first, then the
// credential while the intent that names it still exists, then the remaining records.
func (client Client) forget(name string, value pending, exported bool, receipt *EnrollmentReceipt, record revocation) (ForgetResult, error) {
	result := ForgetResult{SchemaVersion: 1, PairID: value.Intent.PairID, RemoteAccess: "none"}
	if record.PairID != "" {
		result.PairID = record.PairID
	}
	switch {
	case record.Host == hostRevoked:
		result.RemoteAccess = "revoked"
	case receipt != nil:
		result.RemoteAccess = "not-revoked"
		result.Next = fmt.Sprintf("remove the key on the host with `%s`", hostCommand(value.Offer.Installed, "revoke", receipt.PairID))
	case exported:
		result.RemoteAccess = "unconfirmed"
		result.Next = fmt.Sprintf("the host may have applied the enrollment request; check with `%s`", hostCommand(value.Offer.Installed, "status", value.Intent.PairID))
	}
	store := target.Store{Root: client.Root}
	if receipt != nil {
		saved, err := store.ShowDurable(name)
		if err == nil && saved.Fingerprint() == receipt.Target.Fingerprint() {
			_, err = store.Forget(name)
		}
		if err := missingIsDone(err); err != nil {
			return ForgetResult{}, err
		}
	}
	if err := missingIsDone(privatefile.Remove(client.Root, recordPath(name, "receipt"), MaxDocumentSize)); err != nil {
		return ForgetResult{}, err
	}
	if exported {
		fingerprint, err := sshkey.Fingerprint(value.Intent.PublicKey)
		if err != nil {
			return ForgetResult{}, err
		}
		if err := sshkey.Remove(client.Root, fingerprint); err != nil {
			return ForgetResult{}, err
		}
	}
	for _, remove := range []func() error{
		func() error { return privatefile.Remove(client.Root, recordPath(name, "intent"), MaxDocumentSize) },
		func() error { return privatefile.Remove(client.Root, recordPath(name, "preparation"), MaxDocumentSize) },
		func() error { return privatefile.Remove(client.Root, seedPath(name), MaxDocumentSize) },
		func() error { return privatefile.RemoveDirectory(client.Root, filepath.Dir(seedPath(name))) },
		func() error { return privatefile.Remove(client.Root, recordPath(name, "revocation"), MaxDocumentSize) },
	} {
		if err := missingIsDone(remove()); err != nil {
			return ForgetResult{}, err
		}
	}
	if err := privatefile.RemoveDirectory(client.Root, filepath.Join("pairings", name)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ForgetResult{}, fmt.Errorf("no local pairing state named %s: %w", name, err)
		}
		return ForgetResult{}, fmt.Errorf("remove pairing directory: %w", err)
	}
	return result, nil
}

func (client Client) readReceipt(value pending) (EnrollmentReceipt, error) {
	data, err := privatefile.ReadDurable(client.Root, recordPath(value.Name, "receipt"), MaxDocumentSize)
	if err != nil {
		return EnrollmentReceipt{}, err
	}
	var receipt EnrollmentReceipt
	if err := strictjson.Decode(data, &receipt); err != nil {
		return EnrollmentReceipt{}, err
	}
	if _, err := matchReceipt(value, receipt); err != nil {
		return EnrollmentReceipt{}, err
	}
	return receipt, nil
}

func (client Client) readRevocation(name string) (revocation, error) {
	data, err := privatefile.ReadDurable(client.Root, recordPath(name, "revocation"), MaxDocumentSize)
	if err != nil {
		return revocation{}, err
	}
	var record revocation
	if err := strictjson.Decode(data, &record); err != nil {
		return revocation{}, err
	}
	confirmed := record.Host == hostRevoked && record.Result != nil && record.Result.SchemaVersion == 1 && record.Result.PairID == record.PairID && record.Result.State == "revoked"
	rejected := record.Host == hostAlreadyRejected && record.Result == nil
	if record.SchemaVersion != 1 || !idPattern.MatchString(record.PairID) || !confirmed && !rejected {
		return revocation{}, fmt.Errorf("invalid revocation record")
	}
	return record, nil
}

func (client Client) publishRevocation(name string, record revocation) (revocation, error) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return revocation{}, err
	}
	publishErr := privatefile.Publish(client.Root, recordPath(name, "revocation"), encoded, false)
	winner, err := client.readRevocation(name)
	if err != nil {
		if publishErr != nil {
			return revocation{}, publishErr
		}
		return revocation{}, err
	}
	return winner, nil
}

func failureClass(err error) sshtransport.FailureClass {
	var failure *sshtransport.Failure
	if errors.As(err, &failure) {
		return failure.Class
	}
	return ""
}

func missingIsDone(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func hostCommand(installed target.Target, operation, pairID string) string {
	root := installed.Windows().WorkRoot
	if installed.Platform() == "linux" {
		root = installed.Linux().WorkRoot
	}
	command := fmt.Sprintf("blender-box pair %s --state-root %s --pair %s", operation, root, pairID)
	if operation == "revoke" {
		command += " --apply"
	}
	return command
}
