package pairing

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
	"runtime"
	"time"

	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/target"
)

const MaxDocumentSize = 64 << 10
const OfferDigestDomain = "blender-box-pairing-offer-v1\x00"
const IntentDigestDomain = "blender-box-pairing-intent-v1\x00"
const EnrollmentDigestDomain = "blender-box-pairing-enrollment-v1\x00"

type ServerSSH struct {
	Host          string `json:"host"`
	Port          uint16 `json:"port"`
	User          string `json:"user"`
	HostPublicKey string `json:"host_public_key"`
}
type HostOffer struct {
	SchemaVersion   int           `json:"schema_version"`
	BootstrapID     string        `json:"bootstrap_id"`
	Expires         time.Time     `json:"expires"`
	Platform        string        `json:"platform"`
	Connection      ServerSSH     `json:"connection"`
	Installed       target.Target `json:"installed"`
	InstallationID  string        `json:"installation_id"`
	RootIdentity    string        `json:"root_identity"`
	AccountIdentity string        `json:"account_identity"`
}
type EnrollmentIntent struct {
	SchemaVersion int       `json:"schema_version"`
	PairID        string    `json:"pair_id"`
	OperationID   string    `json:"operation_id"`
	OfferHash     string    `json:"offer_hash"`
	PublicKey     string    `json:"public_key"`
	Expires       time.Time `json:"expires"`
}
type EnrollmentReceipt struct {
	SchemaVersion int           `json:"schema_version"`
	PairID        string        `json:"pair_id"`
	OperationID   string        `json:"operation_id"`
	IntentSHA     string        `json:"intent_sha"`
	Platform      string        `json:"platform"`
	ScopeSHA      string        `json:"scope_sha"`
	Target        target.Target `json:"target"`
	PublicKey     string        `json:"public_key"`
}
type TrustedOffer struct{ value HostOffer }
type TrustedReceipt struct{ value EnrollmentReceipt }
type Client struct {
	Root       string
	Now        func() time.Time
	checkpoint func(string) error
	publish    func(string, string, []byte, bool) error
}
type pending struct {
	SchemaVersion int              `json:"schema_version"`
	Name          string           `json:"name"`
	Offer         HostOffer        `json:"offer"`
	Intent        EnrollmentIntent `json:"intent"`
}
type PairView struct {
	SchemaVersion int    `json:"schema_version"`
	PairID        string `json:"pair_id"`
	Access        string `json:"access"`
	Readiness     string `json:"readiness"`
	Next          string `json:"next"`
}

var idPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$`)
var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

func digest(domain string, value any) string {
	encoded, _ := json.Marshal(value)
	sum := sha256.Sum256(append([]byte(domain), encoded...))
	return hex.EncodeToString(sum[:])
}
func OfferDigest(value HostOffer) string           { return digest(OfferDigestDomain, value) }
func IntentDigest(value EnrollmentIntent) string   { return digest(IntentDigestDomain, value) }
func ReceiptDigest(value EnrollmentReceipt) string { return digest(EnrollmentDigestDomain, value) }
func direct(server ServerSSH, fingerprint string) target.DirectSSH {
	return target.DirectSSH{Host: server.Host, Port: server.Port, User: server.User, HostPublicKey: server.HostPublicKey, ClientPublicKeyHash: fingerprint}
}
func validateOffer(value HostOffer) error {
	if value.SchemaVersion != 1 || !idPattern.MatchString(value.BootstrapID) || !idPattern.MatchString(value.InstallationID) || value.RootIdentity == "" || value.AccountIdentity == "" || value.Expires.IsZero() || value.Platform != value.Installed.Platform() {
		return fmt.Errorf("invalid host offer identity")
	}
	if _, paired := value.Installed.Connection().Direct(); paired {
		return fmt.Errorf("host offer must contain an installed unpaired target")
	}
	if err := value.Installed.Validate(); err != nil {
		return err
	}
	_, err := target.NewPaired(value.Installed, direct(value.Connection, fmt.Sprintf("%064d", 0)))
	return err
}
func TrustOffer(data []byte, expectedDigest string, now time.Time) (TrustedOffer, error) {
	var value HostOffer
	if len(data) > MaxDocumentSize {
		return TrustedOffer{}, fmt.Errorf("offer exceeds size limit")
	}
	if err := strictjson.Decode(data, &value); err != nil {
		return TrustedOffer{}, err
	}
	if err := validateOffer(value); err != nil {
		return TrustedOffer{}, err
	}
	if !hashPattern.MatchString(expectedDigest) || OfferDigest(value) != expectedDigest {
		return TrustedOffer{}, fmt.Errorf("host offer requires its exact digest verified through an independent trusted channel")
	}
	if !now.Before(value.Expires) {
		return TrustedOffer{}, fmt.Errorf("host offer expired")
	}
	return TrustedOffer{value}, nil
}
func TrustReceipt(data []byte, expectedDigest string) (TrustedReceipt, error) {
	var value EnrollmentReceipt
	if len(data) > MaxDocumentSize {
		return TrustedReceipt{}, fmt.Errorf("receipt exceeds size limit")
	}
	if err := strictjson.Decode(data, &value); err != nil {
		return TrustedReceipt{}, err
	}
	if value.SchemaVersion != 1 || !idPattern.MatchString(value.PairID) || !idPattern.MatchString(value.OperationID) || !hashPattern.MatchString(value.IntentSHA) || !hashPattern.MatchString(value.ScopeSHA) || value.Platform != value.Target.Platform() {
		return TrustedReceipt{}, fmt.Errorf("invalid enrollment receipt")
	}
	if _, paired := value.Target.Connection().Direct(); !paired {
		return TrustedReceipt{}, fmt.Errorf("enrollment receipt requires paired target")
	}
	if _, err := sshkey.CanonicalPublicKey(value.PublicKey); err != nil {
		return TrustedReceipt{}, err
	}
	if !hashPattern.MatchString(expectedDigest) || ReceiptDigest(value) != expectedDigest {
		return TrustedReceipt{}, fmt.Errorf("enrollment receipt requires its exact digest verified through an independent trusted channel")
	}
	return TrustedReceipt{value}, nil
}
func (client Client) now() time.Time {
	if client.Now != nil {
		return client.Now()
	}
	return time.Now()
}
func recordPath(name, file string) string { return filepath.Join("pairings", name, file+".json") }
func (client Client) read(name string) (pending, error) {
	if err := target.ValidateName(name); err != nil {
		return pending{}, err
	}
	data, err := privatefile.ReadDurable(client.Root, recordPath(name, "intent"), MaxDocumentSize)
	if err != nil {
		return pending{}, err
	}
	var value pending
	if err := strictjson.Decode(data, &value); err != nil {
		return pending{}, err
	}
	if value.SchemaVersion != 1 || value.Name != name || value.Intent.SchemaVersion != 1 || !idPattern.MatchString(value.Intent.PairID) || !idPattern.MatchString(value.Intent.OperationID) || value.Intent.OfferHash != OfferDigest(value.Offer) || !value.Intent.Expires.Equal(value.Offer.Expires) {
		return pending{}, fmt.Errorf("conflicting pairing intent")
	}
	if err := validateOffer(value.Offer); err != nil {
		return pending{}, err
	}
	if _, err := sshkey.CanonicalPublicKey(value.Intent.PublicKey); err != nil {
		return pending{}, err
	}
	return value, nil
}
func (client Client) Prepare(ctx context.Context, name string, offer TrustedOffer) (EnrollmentIntent, error) {
	if runtime.GOOS == "windows" {
		return EnrollmentIntent{}, fmt.Errorf("SSH credential preparation is unsupported on Windows until private ACL ownership is enforced")
	}
	if err := target.ValidateName(name); err != nil {
		return EnrollmentIntent{}, err
	}
	if err := validateOffer(offer.value); err != nil {
		return EnrollmentIntent{}, err
	}
	if !client.now().Before(offer.value.Expires) {
		return EnrollmentIntent{}, fmt.Errorf("host offer expired")
	}
	if err := ctx.Err(); err != nil {
		return EnrollmentIntent{}, err
	}
	existing, err := client.read(name)
	if err == nil {
		if existing.Intent.OfferHash != OfferDigest(offer.value) {
			return EnrollmentIntent{}, fmt.Errorf("name already has a different pairing intent")
		}
		reservation, reserveErr := client.readPreparation(name)
		if errors.Is(reserveErr, os.ErrNotExist) {
			fingerprint, _ := sshkey.Fingerprint(existing.Intent.PublicKey)
			if _, err := sshkey.Read(ctx, client.Root, fingerprint); err != nil {
				return EnrollmentIntent{}, err
			}
			return existing.Intent, nil
		}
		if reserveErr != nil {
			return EnrollmentIntent{}, reserveErr
		}
		return client.prepareReserved(ctx, reservation)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return EnrollmentIntent{}, err
	}
	if _, err := (target.Store{Root: client.Root}).Show(name); err == nil {
		return EnrollmentIntent{}, fmt.Errorf("target name already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return EnrollmentIntent{}, err
	}
	reservation, err := client.reserve(name, offer.value)
	if err != nil {
		return EnrollmentIntent{}, err
	}
	return client.prepareReserved(ctx, reservation)
}
func (client Client) Complete(ctx context.Context, name string, trusted TrustedReceipt) (target.Target, error) {
	value, err := client.read(name)
	if err != nil {
		return target.Target{}, err
	}
	receipt := trusted.value
	expected, err := matchReceipt(value, receipt)
	if err != nil {
		return target.Target{}, err
	}
	if err := client.verifyCredential(ctx, value); err != nil {
		return target.Target{}, err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return target.Target{}, err
	}
	path := recordPath(name, "receipt")
	if err := privatefile.Publish(client.Root, path, encoded, false); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return target.Target{}, err
		}
		existing, readErr := privatefile.ReadDurable(client.Root, path, MaxDocumentSize)
		if readErr != nil {
			return target.Target{}, readErr
		}
		if string(existing) != string(encoded) {
			return target.Target{}, fmt.Errorf("pairing already has a different receipt")
		}
	}
	store := target.Store{Root: client.Root}
	selected, err := store.Save(name, expected, false)
	if err == nil {
		return selected, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return target.Target{}, fmt.Errorf("receipt retained; target publication unresolved: %w", err)
	}
	existing, readErr := store.ShowDurable(name)
	if readErr != nil {
		return target.Target{}, fmt.Errorf("receipt retained; target publication unresolved: %w", readErr)
	}
	if existing.Fingerprint() == expected.Fingerprint() {
		return existing, nil
	}
	return target.Target{}, fmt.Errorf("receipt retained; target publication conflicts with existing target")
}
func (client Client) Inspect(ctx context.Context, name string) (PairView, error) {
	value, err := client.read(name)
	if errors.Is(err, os.ErrNotExist) {
		reservation, reserveErr := client.readPreparation(name)
		if reserveErr != nil {
			return PairView{}, reserveErr
		}
		return preparationView(reservation.Intent.PairID), nil
	}
	if err != nil {
		return PairView{}, err
	}
	view := PairView{1, value.Intent.PairID, "prepared-unconfirmed", "unchecked", "retain request and key; import the trusted host enrollment receipt"}
	if err := client.verifyCredential(ctx, value); err != nil {
		view.Access = "conflict"
		view.Next = "restore the original client credential from an authorized source"
		if errors.Is(err, os.ErrNotExist) {
			if _, reserveErr := client.readPreparation(name); reserveErr == nil {
				key, seedErr := sshkey.Reserved(ctx, client.Root, seedPath(name), false)
				if seedErr == nil && key.PublicKey() == value.Intent.PublicKey {
					return preparationView(value.Intent.PairID), nil
				}
			}
		}
		return view, nil
	}
	data, err := privatefile.ReadDurable(client.Root, recordPath(name, "receipt"), MaxDocumentSize)
	if errors.Is(err, os.ErrNotExist) {
		return view, nil
	}
	if err != nil {
		return PairView{}, err
	}
	var receipt EnrollmentReceipt
	if err := strictjson.Decode(data, &receipt); err != nil {
		return PairView{}, err
	}
	if _, err := matchReceipt(value, receipt); err != nil {
		return PairView{}, err
	}
	view.Access = "enrolled-publication-pending"
	view.Next = "repeat completion with the original trusted receipt"
	selected, err := (target.Store{Root: client.Root}).ShowDurable(name)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return PairView{}, err
	}
	if err == nil && selected.Fingerprint() == receipt.Target.Fingerprint() {
		view.Access = "enrolled"
		view.Next = "run doctor with this target and the intended Scenario payload"
	} else if err == nil {
		view.Access = "conflict"
		view.Next = "named target differs; preserve retained pairing state"
	}
	return view, nil
}

func matchReceipt(value pending, receipt EnrollmentReceipt) (target.Target, error) {
	fingerprint, err := sshkey.Fingerprint(value.Intent.PublicKey)
	if err != nil {
		return target.Target{}, err
	}
	expected, err := target.NewPaired(value.Offer.Installed, direct(value.Offer.Connection, fingerprint))
	if err != nil {
		return target.Target{}, err
	}
	if receipt.SchemaVersion != 1 || receipt.PairID != value.Intent.PairID || receipt.OperationID != value.Intent.OperationID || receipt.IntentSHA != IntentDigest(value.Intent) || receipt.PublicKey != value.Intent.PublicKey || receipt.Platform != value.Offer.Platform || receipt.Target.Fingerprint() != expected.Fingerprint() || !hashPattern.MatchString(receipt.ScopeSHA) {
		return target.Target{}, fmt.Errorf("receipt does not match the retained pairing intent and offered authority")
	}
	return expected, nil
}
