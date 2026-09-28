package pairing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/target"
)

const ScopeDigestDomain = "blender-box-pairing-scope-v1\x00"
const MaxKeysFile = 1 << 20
const defaultOfferTTL = 30 * time.Minute
const maxOfferTTL = 24 * time.Hour

// ErrKeysChanged means the keys file no longer matched the bytes and security read before the
// edit. Nothing was written; the caller re-reads and retries.
var ErrKeysChanged = errors.New("authorized keys file changed during update; retry")

// Platform supplies the OS facts and the ACL-correct atomic keys-file edit. Records, derived
// state, digests and line arithmetic stay in Host so no platform can get them wrong on its own.
type Platform interface {
	// Authority proves elevation and the installed runtime and resolves the account's effective
	// authorized keys file. It refuses when sshd is stopped or public-key auth is off.
	Authority(ctx context.Context, root, installationID string) (Authority, error)
	// ReadKeys returns bounded bytes after verifying the file's type and security are ones sshd accepts.
	ReadKeys(ctx context.Context, path string) (KeysFile, error)
	// ReplaceKeys writes contents only if the file still matches file.SHA and file.Security,
	// atomically and with the same security, then re-reads and verifies both.
	ReplaceKeys(ctx context.Context, file KeysFile, contents []byte) error
}
type Authority struct {
	Installed       target.Target
	InstallationID  string
	RootIdentity    string
	AccountIdentity string
	Login           string
	Port            uint16
	HostPublicKey   string
	KeysFile        string
	SharedKeysFile  bool
}

// KeysFile is one observation of an authorized keys file. SHA is the hex SHA-256 of Bytes; an
// absent file reads as empty. Security is the platform's opaque descriptor carried to ReplaceKeys.
type KeysFile struct {
	Path     string
	Exists   bool
	Bytes    []byte
	SHA      string
	Security string
}

type Host struct {
	Root       string
	Platform   Platform
	Now        func() time.Time
	checkpoint func(string) error
}
type TrustedIntent struct{ value EnrollmentIntent }

// grantRecord authorizes the marked line to be present. It is published before the line is
// appended, so a grant without its line is an enrollment to finish, never a stray record.
type grantRecord struct {
	SchemaVersion   int               `json:"schema_version"`
	PairID          string            `json:"pair_id"`
	OfferSHA        string            `json:"offer_sha"`
	IntentSHA       string            `json:"intent_sha"`
	InstallationID  string            `json:"installation_id"`
	AccountIdentity string            `json:"account_identity"`
	Login           string            `json:"login"`
	KeysFile        string            `json:"keys_file"`
	SharedKeysFile  bool              `json:"shared_keys_file"`
	Line            string            `json:"line"`
	Receipt         EnrollmentReceipt `json:"receipt"`
	ReceiptSHA      string            `json:"receipt_sha"`
	Granted         time.Time         `json:"granted"`
}

// tombstone authorizes removal of the grant's line and forbids re-adding it.
type tombstone struct {
	SchemaVersion int       `json:"schema_version"`
	PairID        string    `json:"pair_id"`
	GrantSHA      string    `json:"grant_sha"`
	Source        string    `json:"source"`
	Requested     time.Time `json:"requested"`
}
type scope struct {
	Platform        string `json:"platform"`
	InstallationID  string `json:"installation_id"`
	AccountIdentity string `json:"account_identity"`
	KeysFile        string `json:"keys_file"`
	Options         string `json:"options"`
}
type Enrollment struct {
	SchemaVersion    int             `json:"schema_version"`
	PairID           string          `json:"pair_id"`
	State            string          `json:"state"`
	InstallationID   string          `json:"installation_id"`
	Login            string          `json:"login"`
	KeysFile         string          `json:"keys_file"`
	SharedKeysFile   bool            `json:"shared_keys_file"`
	Line             string          `json:"line"`
	Fingerprint      string          `json:"fingerprint"`
	KeysSHA256Before string          `json:"keys_sha256_before"`
	KeysSHA256After  string          `json:"keys_sha256_after,omitempty"`
	Receipt          json.RawMessage `json:"receipt,omitempty"`
	ReceiptSHA       string          `json:"receipt_sha,omitempty"`
}
type GrantView struct {
	SchemaVersion  int        `json:"schema_version"`
	PairID         string     `json:"pair_id"`
	State          string     `json:"state"`
	InstallationID string     `json:"installation_id"`
	Login          string     `json:"login"`
	KeysFile       string     `json:"keys_file"`
	Fingerprint    string     `json:"fingerprint"`
	Granted        time.Time  `json:"granted"`
	Revoked        *time.Time `json:"revoked,omitempty"`
}

func offerPath(sha string) string    { return filepath.Join("pairings", "offers", sha+".json") }
func grantPath(pairID string) string { return filepath.Join("pairings", "grants", pairID+".json") }
func tombPath(pairID string) string  { return filepath.Join("pairings", "tombstones", pairID+".json") }
func hexSHA(data []byte) string      { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// displayFingerprint is OpenSSH's "SHA256:" form for humans; records keep sshkey.Fingerprint.
func displayFingerprint(publicKey string) string {
	wire, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(publicKey, "ssh-ed25519 "))
	sum := sha256.Sum256(wire)
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])
}

// accessState derives the pairing's state from the two create-only records and the observed line.
func accessState(tombstoned bool, exact int) string {
	switch {
	case exact > 1:
		return "conflict"
	case !tombstoned && exact == 0:
		return "granting"
	case !tombstoned:
		return "granted"
	case exact == 1:
		return "revoking"
	}
	return "revoked"
}

func TrustIntent(data []byte, expectedDigest string) (TrustedIntent, error) {
	var value EnrollmentIntent
	if len(data) > MaxDocumentSize {
		return TrustedIntent{}, fmt.Errorf("enrollment request exceeds size limit")
	}
	if err := strictjson.Decode(data, &value); err != nil {
		return TrustedIntent{}, err
	}
	if value.SchemaVersion != 1 || !idPattern.MatchString(value.PairID) || !idPattern.MatchString(value.OperationID) || !hashPattern.MatchString(value.OfferHash) || value.Expires.IsZero() {
		return TrustedIntent{}, fmt.Errorf("invalid enrollment request")
	}
	if _, err := sshkey.CanonicalPublicKey(value.PublicKey); err != nil {
		return TrustedIntent{}, err
	}
	if !hashPattern.MatchString(expectedDigest) || IntentDigest(value) != expectedDigest {
		return TrustedIntent{}, fmt.Errorf("enrollment request requires its exact digest verified through an independent trusted channel")
	}
	return TrustedIntent{value}, nil
}

func (h Host) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}
func (h Host) at(stage string) error {
	if h.checkpoint != nil {
		return h.checkpoint(stage)
	}
	return nil
}
func (h Host) readJSON(relative string, value any) ([]byte, error) {
	data, err := privatefile.ReadDurable(h.Root, relative, MaxDocumentSize)
	if err != nil {
		return nil, err
	}
	return data, strictjson.Decode(data, value)
}
func (h Host) readOffer(sha string) (HostOffer, error) {
	var value HostOffer
	if !hashPattern.MatchString(sha) {
		return HostOffer{}, fmt.Errorf("invalid offer hash")
	}
	if _, err := h.readJSON(offerPath(sha), &value); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return HostOffer{}, fmt.Errorf("request names an offer this host did not issue")
		}
		return HostOffer{}, err
	}
	if err := validateOffer(value); err != nil {
		return HostOffer{}, err
	}
	if OfferDigest(value) != sha {
		return HostOffer{}, fmt.Errorf("retained offer does not match its digest")
	}
	return value, nil
}
func (h Host) readGrant(pairID string) (grantRecord, []byte, error) {
	var value grantRecord
	if !idPattern.MatchString(pairID) {
		return grantRecord{}, nil, fmt.Errorf("invalid pair id")
	}
	data, err := h.readJSON(grantPath(pairID), &value)
	if err != nil {
		return grantRecord{}, nil, err
	}
	line, lineErr := grantLine(value.Receipt.PublicKey, pairID)
	if lineErr != nil || value.SchemaVersion != 1 || value.PairID != pairID || value.Receipt.PairID != pairID || value.ReceiptSHA != ReceiptDigest(value.Receipt) || value.Line != line || value.KeysFile == "" {
		return grantRecord{}, nil, fmt.Errorf("retained grant %s is corrupt", pairID)
	}
	return value, data, nil
}
func (h Host) readTombstone(pairID string) (tombstone, []byte, bool, error) {
	var value tombstone
	data, err := h.readJSON(tombPath(pairID), &value)
	if errors.Is(err, os.ErrNotExist) {
		return tombstone{}, nil, false, nil
	}
	if err != nil {
		return tombstone{}, nil, false, err
	}
	if value.SchemaVersion != 1 || value.PairID != pairID {
		return tombstone{}, nil, false, fmt.Errorf("retained tombstone %s is corrupt", pairID)
	}
	return value, data, true, nil
}

// Offer binds the host's current identity and expiry into a record the client must trust through
// an independent channel. It changes no access, so it takes no maintenance lock.
func (h Host) Offer(ctx context.Context, installationID, address string, ttl time.Duration) ([]byte, string, error) {
	if ttl == 0 {
		ttl = defaultOfferTTL
	}
	if ttl < 0 || ttl > maxOfferTTL {
		return nil, "", fmt.Errorf("offer expiry must be within 24h")
	}
	if !idPattern.MatchString(installationID) {
		return nil, "", fmt.Errorf("invalid installation id")
	}
	auth, err := h.Platform.Authority(ctx, h.Root, installationID)
	if err != nil {
		return nil, "", err
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, "", err
	}
	offer := HostOffer{1, "bbxb_" + hex.EncodeToString(random[:]), h.now().Add(ttl), auth.Installed.Platform(), ServerSSH{address, auth.Port, auth.Login, auth.HostPublicKey}, auth.Installed, auth.InstallationID, auth.RootIdentity, auth.AccountIdentity}
	if err := validateOffer(offer); err != nil {
		return nil, "", err
	}
	encoded, err := json.Marshal(offer)
	if err != nil {
		return nil, "", err
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	sha := OfferDigest(offer)
	if err := privatefile.Publish(h.Root, offerPath(sha), encoded, false); err != nil {
		return nil, "", err
	}
	return encoded, sha, nil
}

// Enroll admits exactly one marked line for the trusted request. Without apply it reports what
// would change. Repeating a completed enrollment returns byte-identical receipt bytes.
func (h Host) Enroll(ctx context.Context, trusted TrustedIntent, apply bool) (Enrollment, error) {
	intent := trusted.value
	if intent.SchemaVersion != 1 {
		return Enrollment{}, fmt.Errorf("zero trust wrapper")
	}
	intentSHA := IntentDigest(intent)
	grant, _, err := h.readGrant(intent.PairID)
	exists := err == nil
	switch {
	case exists && grant.IntentSHA != intentSHA:
		return Enrollment{}, fmt.Errorf("pair id %s is already bound to a different request", intent.PairID)
	case exists:
		if _, _, tombstoned, err := h.readTombstone(intent.PairID); err != nil {
			return Enrollment{}, err
		} else if tombstoned {
			return Enrollment{}, fmt.Errorf("pairing %s was revoked; prepare a new pairing", intent.PairID)
		}
	case errors.Is(err, os.ErrNotExist):
		grant, err = h.newGrant(ctx, intent)
		if err != nil {
			return Enrollment{}, err
		}
	default:
		return Enrollment{}, err
	}
	result := Enrollment{SchemaVersion: 1, PairID: grant.PairID, State: "preview", InstallationID: grant.InstallationID, Login: grant.Login, KeysFile: grant.KeysFile, SharedKeysFile: grant.SharedKeysFile, Line: grant.Line, Fingerprint: displayFingerprint(grant.Receipt.PublicKey)}
	if !apply {
		keys, err := h.Platform.ReadKeys(ctx, grant.KeysFile)
		if err != nil {
			return Enrollment{}, err
		}
		result.KeysSHA256Before = keys.SHA
		_, err = h.scanGrant(keys, grant)
		return result, err
	}
	if err := ctx.Err(); err != nil {
		return Enrollment{}, err
	}
	err = host.WithMaintenance(ctx, h.Root, func() error {
		if !exists {
			encoded, err := json.Marshal(grant)
			if err != nil {
				return err
			}
			if err := privatefile.Publish(h.Root, grantPath(grant.PairID), encoded, false); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			durable, _, err := h.readGrant(grant.PairID)
			if err != nil {
				return err
			}
			if durable.IntentSHA != intentSHA {
				return fmt.Errorf("pair id %s is already bound to a different request", intent.PairID)
			}
			grant = durable
		}
		if err := h.at("grant"); err != nil {
			return err
		}
		keys, err := h.Platform.ReadKeys(ctx, grant.KeysFile)
		if err != nil {
			return err
		}
		result.KeysSHA256Before = keys.SHA
		exact, err := h.scanGrant(keys, grant)
		if err != nil {
			return err
		}
		if exact == 0 {
			if err := h.Platform.ReplaceKeys(ctx, keys, appendLine(keys.Bytes, grant.Line)); err != nil {
				return err
			}
		}
		if err := h.at("keys"); err != nil {
			return err
		}
		after, err := h.Platform.ReadKeys(ctx, grant.KeysFile)
		if err != nil {
			return err
		}
		if exact, _, _ := scanKeys(after.Bytes, grant.Line, grant.Receipt.PublicKey, grant.PairID); exact != 1 {
			return fmt.Errorf("pairing line not verified after write: %s", accessState(false, exact))
		}
		result.KeysSHA256After = after.SHA
		return nil
	})
	if err != nil {
		return Enrollment{}, err
	}
	result.State = "granted"
	result.Receipt, err = json.Marshal(grant.Receipt)
	if err != nil {
		return Enrollment{}, err
	}
	result.ReceiptSHA = grant.ReceiptSHA
	return result, nil
}

// newGrant checks the request against the retained offer and the host's present identity.
// Any drift refuses before a record exists.
func (h Host) newGrant(ctx context.Context, intent EnrollmentIntent) (grantRecord, error) {
	offer, err := h.readOffer(intent.OfferHash)
	if err != nil {
		return grantRecord{}, err
	}
	if !intent.Expires.Equal(offer.Expires) {
		return grantRecord{}, fmt.Errorf("request expiry does not match the offer")
	}
	if !h.now().Before(offer.Expires) {
		return grantRecord{}, fmt.Errorf("offer expired; issue a new offer")
	}
	auth, err := h.Platform.Authority(ctx, h.Root, offer.InstallationID)
	if err != nil {
		return grantRecord{}, err
	}
	if auth.InstallationID != offer.InstallationID || auth.RootIdentity != offer.RootIdentity || auth.AccountIdentity != offer.AccountIdentity || auth.Installed.Fingerprint() != offer.Installed.Fingerprint() || auth.HostPublicKey != offer.Connection.HostPublicKey || auth.Port != offer.Connection.Port || auth.Login != offer.Connection.User {
		return grantRecord{}, fmt.Errorf("host identity changed since the offer; issue a new offer")
	}
	fingerprint, err := sshkey.Fingerprint(intent.PublicKey)
	if err != nil {
		return grantRecord{}, err
	}
	paired, err := target.NewPaired(offer.Installed, direct(offer.Connection, fingerprint))
	if err != nil {
		return grantRecord{}, err
	}
	line, err := grantLine(intent.PublicKey, intent.PairID)
	if err != nil {
		return grantRecord{}, err
	}
	receipt := EnrollmentReceipt{1, intent.PairID, intent.OperationID, IntentDigest(intent), offer.Platform, digest(ScopeDigestDomain, scope{offer.Platform, offer.InstallationID, offer.AccountIdentity, auth.KeysFile, "restrict"}), paired, intent.PublicKey}
	return grantRecord{1, intent.PairID, intent.OfferHash, receipt.IntentSHA, offer.InstallationID, offer.AccountIdentity, offer.Connection.User, auth.KeysFile, auth.SharedKeysFile, line, receipt, ReceiptDigest(receipt), h.now()}, nil
}

// scanGrant refuses states no write can resolve: the same key under another line, this pair's
// marker with another key, or the exact line more than once.
func (h Host) scanGrant(keys KeysFile, grant grantRecord) (int, error) {
	exact, foreignKey, foreignMarker := scanKeys(keys.Bytes, grant.Line, grant.Receipt.PublicKey, grant.PairID)
	switch {
	case foreignKey:
		return exact, fmt.Errorf("%s already contains this key outside the pairing line; remove it manually before enrolling", keys.Path)
	case foreignMarker:
		return exact, fmt.Errorf("%s contains pair %s with a different key; resolve it manually", keys.Path, grant.PairID)
	case exact > 1:
		return exact, fmt.Errorf("%s contains pair %s %d times; resolve it manually", keys.Path, grant.PairID, exact)
	}
	return exact, nil
}

// Revoke removes exactly the grant's line. It records the tombstone first, so an interrupted
// removal is finished on retry and a later enroll can never re-add the key. Under maintenance it
// refuses while any Run is active or unresolved.
func (h Host) Revoke(ctx context.Context, pairID, clientKeyHash, source string, apply bool) (RevokeResult, error) {
	if source != "host-local" && source != "paired-ssh" {
		return RevokeResult{}, fmt.Errorf("invalid revoke source")
	}
	grant, grantBytes, err := h.readGrant(pairID)
	if errors.Is(err, os.ErrNotExist) {
		return RevokeResult{}, fmt.Errorf("unknown pair id %s", pairID)
	}
	if err != nil {
		return RevokeResult{}, err
	}
	if clientKeyHash != "" {
		fingerprint, err := sshkey.Fingerprint(grant.Receipt.PublicKey)
		if err != nil {
			return RevokeResult{}, err
		}
		if fingerprint != clientKeyHash {
			return RevokeResult{}, fmt.Errorf("client key does not own pair %s", pairID)
		}
	}
	result := RevokeResult{SchemaVersion: 1, PairID: pairID}
	if !apply {
		_, _, tombstoned, err := h.readTombstone(pairID)
		if err != nil {
			return RevokeResult{}, err
		}
		keys, err := h.Platform.ReadKeys(ctx, grant.KeysFile)
		if err != nil {
			return RevokeResult{}, err
		}
		exact, _, _ := scanKeys(keys.Bytes, grant.Line, grant.Receipt.PublicKey, grant.PairID)
		result.State = accessState(tombstoned, exact)
		result.KeysSHA256Before = keys.SHA
		return result, nil
	}
	if err := ctx.Err(); err != nil {
		return RevokeResult{}, err
	}
	err = host.WithMaintenance(ctx, h.Root, func() error {
		_, tombBytes, tombstoned, err := h.readTombstone(pairID)
		if err != nil {
			return err
		}
		if !tombstoned {
			tombBytes, err = json.Marshal(tombstone{1, pairID, hexSHA(grantBytes), source, h.now()})
			if err != nil {
				return err
			}
			if err := privatefile.Publish(h.Root, tombPath(pairID), tombBytes, false); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			if _, tombBytes, _, err = h.readTombstone(pairID); err != nil {
				return err
			}
		}
		result.TombstoneSHA256 = hexSHA(tombBytes)
		if err := h.at("tombstone"); err != nil {
			return err
		}
		keys, err := h.Platform.ReadKeys(ctx, grant.KeysFile)
		if err != nil {
			return err
		}
		result.KeysSHA256Before = keys.SHA
		exact, _, _ := scanKeys(keys.Bytes, grant.Line, grant.Receipt.PublicKey, grant.PairID)
		if exact > 1 {
			return fmt.Errorf("%s contains pair %s %d times; resolve it manually", keys.Path, pairID, exact)
		}
		if exact == 1 {
			contents, err := removeLine(keys.Bytes, grant.Line)
			if err != nil {
				return err
			}
			if err := h.Platform.ReplaceKeys(ctx, keys, contents); err != nil {
				return err
			}
		}
		if err := h.at("keys"); err != nil {
			return err
		}
		after, err := h.Platform.ReadKeys(ctx, grant.KeysFile)
		if err != nil {
			return err
		}
		if exact, _, _ := scanKeys(after.Bytes, grant.Line, grant.Receipt.PublicKey, grant.PairID); exact != 0 {
			return fmt.Errorf("pairing line still present after removal")
		}
		result.KeysSHA256After = after.SHA
		return nil
	})
	if err != nil {
		return RevokeResult{}, err
	}
	result.State = "revoked"
	return result, nil
}

// Status derives each grant's state from its records and the keys file sshd reads.
func (h Host) Status(ctx context.Context, pairID string) ([]GrantView, error) {
	var ids []string
	if pairID != "" {
		ids = []string{pairID}
	} else {
		directory, err := privatefile.Directory(h.Root, filepath.Dir(grantPath("x")), false)
		if errors.Is(err, os.ErrNotExist) {
			return []GrantView{}, nil
		}
		if err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, err
		}
		if len(entries) > 4096 {
			return nil, fmt.Errorf("excessive retained grants")
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".json") {
				ids = append(ids, strings.TrimSuffix(entry.Name(), ".json"))
			}
		}
		sort.Strings(ids)
	}
	views := []GrantView{}
	for _, id := range ids {
		grant, _, err := h.readGrant(id)
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("unknown pair id %s", id)
		}
		if err != nil {
			return nil, err
		}
		tomb, _, tombstoned, err := h.readTombstone(id)
		if err != nil {
			return nil, err
		}
		keys, err := h.Platform.ReadKeys(ctx, grant.KeysFile)
		if err != nil {
			return nil, err
		}
		exact, _, _ := scanKeys(keys.Bytes, grant.Line, grant.Receipt.PublicKey, grant.PairID)
		view := GrantView{1, id, accessState(tombstoned, exact), grant.InstallationID, grant.Login, grant.KeysFile, displayFingerprint(grant.Receipt.PublicKey), grant.Granted, nil}
		if tombstoned {
			requested := tomb.Requested
			view.Revoked = &requested
		}
		views = append(views, view)
	}
	return views, nil
}
