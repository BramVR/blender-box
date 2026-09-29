package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/pairing"
	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/target"
)

const fakeKeysPath = `C:\ProgramData\ssh\administrators_authorized_keys`

type fakePairingPlatform struct {
	authority pairing.Authority
	files     map[string][]byte
}

func (p *fakePairingPlatform) Authority(context.Context, string, string) (pairing.Authority, error) {
	return p.authority, nil
}
func (p *fakePairingPlatform) ReadKeys(_ context.Context, path string) (pairing.KeysFile, error) {
	contents, exists := p.files[path]
	sum := sha256.Sum256(contents)
	return pairing.KeysFile{Path: path, Exists: exists, Bytes: append([]byte{}, contents...), SHA: hex.EncodeToString(sum[:]), Security: "protected"}, nil
}
func (p *fakePairingPlatform) ReplaceKeys(_ context.Context, file pairing.KeysFile, contents []byte) error {
	if current, _ := p.ReadKeys(context.Background(), file.Path); current.SHA != file.SHA {
		return pairing.ErrKeysChanged
	}
	p.files[file.Path] = append([]byte{}, contents...)
	return nil
}

// canonicalTestKey builds a canonical ssh-ed25519 public key without ssh-keygen.
func canonicalTestKey(fill byte) string {
	wire := binary.BigEndian.AppendUint32(nil, 11)
	wire = append(wire, "ssh-ed25519"...)
	wire = binary.BigEndian.AppendUint32(wire, 32)
	wire = append(wire, bytes.Repeat([]byte{fill}, 32)...)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(wire)
}

func privateRoot(t *testing.T) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(parent, "state")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestPairHostVerbsAndMachineRevokeUseTheSameRecords(t *testing.T) {
	installed, err := target.Load(writeTarget(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	platform := &fakePairingPlatform{authority: pairing.Authority{Installed: installed, InstallationID: "installation-test", RootIdentity: "root-test", AccountIdentity: "S-1-5-21-test", Login: "test-user", Port: 22, HostPublicKey: canonicalTestKey(9), KeysFile: fakeKeysPath, SharedKeysFile: true}, files: map[string][]byte{fakeKeysPath: []byte("ssh-rsa AAAAB3NzaC1yc2E ops\r\n")}}
	deps := Dependencies{Now: func() time.Time { return now }, Pairing: func(string) (pairing.Platform, error) { return platform, nil }}
	root := privateRoot(t)
	work := t.TempDir()
	call := func(stdin string, args ...string) (int, []byte, string) {
		t.Helper()
		var out, stderr bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(stdin), &out, &stderr, deps)
		return code, out.Bytes(), stderr.String()
	}

	offerPath := filepath.Join(work, "offer.json")
	code, out, stderr := call("", "pair", "offer", "--state-root", root, "--installation", "installation-test", "--address", "host.invalid", "--out", offerPath, "--json")
	var offered struct {
		OfferSHA256 string `json:"offer_sha256"`
		Path        string `json:"path"`
	}
	if err := json.Unmarshal(out, &offered); code != 0 || err != nil || offered.Path != offerPath {
		t.Fatalf("offer: %d %s %s", code, out, stderr)
	}
	offerBytes, err := os.ReadFile(offerPath)
	if err != nil {
		t.Fatal(err)
	}
	trustedOffer, err := pairing.TrustOffer(offerBytes, offered.OfferSHA256, now)
	if err != nil {
		t.Fatal(err)
	}
	var offer pairing.HostOffer
	if err := json.Unmarshal(offerBytes, &offer); err != nil || offer.Connection.User != "test-user" || offer.Connection.Host != "host.invalid" {
		t.Fatalf("offer contents %+v %v %v", offer, trustedOffer, err)
	}

	intent := pairing.EnrollmentIntent{SchemaVersion: 1, PairID: "pair-1", OperationID: "op-1", OfferHash: offered.OfferSHA256, PublicKey: canonicalTestKey(7), Expires: offer.Expires}
	intentBytes, _ := json.Marshal(intent)
	intentPath := filepath.Join(work, "intent.json")
	if err := os.WriteFile(intentPath, intentBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := call("", "pair", "enroll", "--state-root", root, "--intent", intentPath, "--trust-intent", strings.Repeat("0", 64)); code != 1 {
		t.Fatalf("wrong trust exit %d", code)
	}
	code, out, stderr = call("", "pair", "enroll", "--state-root", root, "--intent", intentPath, "--trust-intent", pairing.IntentDigest(intent), "--json")
	var preview pairing.Enrollment
	if err := json.Unmarshal(out, &preview); code != 0 || err != nil || preview.State != "preview" || preview.Receipt != nil || !preview.SharedKeysFile {
		t.Fatalf("preview: %d %+v %s", code, preview, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, "pairings", "grants")); !os.IsNotExist(err) {
		t.Fatal("preview wrote a grant")
	}
	if code, _, _ := call("", "pair", "enroll", "--state-root", root, "--intent", intentPath, "--trust-intent", pairing.IntentDigest(intent), "--apply"); code != 2 {
		t.Fatalf("apply without --out exit %d", code)
	}
	receiptPath := filepath.Join(work, "receipt.json")
	code, out, stderr = call("", "pair", "enroll", "--state-root", root, "--intent", intentPath, "--trust-intent", pairing.IntentDigest(intent), "--apply", "--out", receiptPath, "--json")
	var enrolled pairing.Enrollment
	if err := json.Unmarshal(out, &enrolled); code != 0 || err != nil || enrolled.State != "granted" {
		t.Fatalf("enroll: %d %s %s", code, out, stderr)
	}
	receiptBytes, err := os.ReadFile(receiptPath)
	var compact bytes.Buffer
	if compactErr := json.Compact(&compact, enrolled.Receipt); err != nil || compactErr != nil || compact.String() != string(receiptBytes) {
		t.Fatalf("receipt file %v %v %s", err, compactErr, receiptBytes)
	}
	if _, err := pairing.TrustReceipt(receiptBytes, enrolled.ReceiptSHA); err != nil {
		t.Fatal(err)
	}
	line := "restrict " + intent.PublicKey + " blender-box-pair:pair-1"
	if got := string(platform.files[fakeKeysPath]); got != "ssh-rsa AAAAB3NzaC1yc2E ops\r\n"+line+"\r\n" {
		t.Fatalf("keys %q", got)
	}
	code, out, stderr = call("", "pair", "enroll", "--state-root", root, "--intent", intentPath, "--trust-intent", pairing.IntentDigest(intent), "--apply", "--out", receiptPath)
	if code != 0 || !strings.Contains(string(out), "Receipt SHA-256 "+enrolled.ReceiptSHA) {
		t.Fatalf("repeat enroll: %d %s %s", code, out, stderr)
	}
	code, out, stderr = call("", "pair", "status", "--state-root", root, "--json")
	var views []pairing.GrantView
	if err := json.Unmarshal(out, &views); code != 0 || err != nil || len(views) != 1 || views[0].State != "granted" || views[0].PairID != "pair-1" {
		t.Fatalf("status: %d %s %s", code, out, stderr)
	}

	fingerprint, _ := sshkey.Fingerprint(intent.PublicKey)
	request := func(hash string) string {
		data, _ := json.Marshal(pairing.RevokeRequest{SchemaVersion: 1, PairID: "pair-1", ClientPublicKeyHash: hash})
		return string(data)
	}
	code, out, stderr = call(request(strings.Repeat("a", 64)), "host", "pair-revoke", "--state-root", root)
	if code != 1 || len(out) != 0 || !strings.Contains(stderr, "does not own") {
		t.Fatalf("foreign key revoke: %d %s %s", code, out, stderr)
	}
	if _, err := os.Stat(filepath.Join(root, "pairings", "tombstones")); !os.IsNotExist(err) {
		t.Fatal("refused revoke wrote a tombstone")
	}
	code, out, stderr = call(request(fingerprint), "host", "pair-revoke", "--state-root", root)
	if code != 0 || bytes.Count(out, []byte("\n")) != 1 {
		t.Fatalf("machine revoke: %d %s %s", code, out, stderr)
	}
	result, err := pairing.ParseRevokeResult(bytes.TrimSpace(out), "pair-1")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(platform.files[fakeKeysPath]); got != "ssh-rsa AAAAB3NzaC1yc2E ops\r\n" {
		t.Fatalf("keys after revoke %q", got)
	}
	code, out, stderr = call("", "pair", "revoke", "--state-root", root, "--pair", "pair-1", "--apply", "--json")
	var again pairing.RevokeResult
	if err := json.Unmarshal(out, &again); code != 0 || err != nil || again.State != "revoked" || again.TombstoneSHA256 != result.TombstoneSHA256 {
		t.Fatalf("operator revoke: %d %s %s", code, out, stderr)
	}
	if code, out, _ := call("", "pair", "status", "--state-root", root, "--pair", "pair-1"); code != 0 || !strings.Contains(string(out), "Pair pair-1: revoked") {
		t.Fatalf("status after revoke: %d %s", code, out)
	}
	if code, _, stderr := call("", "pair", "enroll", "--state-root", root, "--intent", intentPath, "--trust-intent", pairing.IntentDigest(intent), "--apply", "--out", receiptPath); code != 1 || !strings.Contains(stderr, "revoked") {
		t.Fatalf("enroll after revoke: %d %s", code, stderr)
	}
}

func TestPairHostVerbsRefuseWithoutAPlatform(t *testing.T) {
	root := privateRoot(t)
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"pair", "offer", "--state-root", root, "--installation", "installation-test", "--address", "host.invalid", "--out", filepath.Join(t.TempDir(), "offer.json")}, strings.NewReader(""), &out, &stderr, Dependencies{})
	if code != 1 || !strings.Contains(stderr.String(), "unsupported") {
		t.Fatalf("%d %s", code, stderr.String())
	}
	code = Run(context.Background(), []string{"host", "pair-revoke", "--state-root", root}, strings.NewReader(`{"schema_version":1,"pair_id":"pair-1","client_public_key_hash":"`+strings.Repeat("a", 64)+`"}`), &out, &stderr, Dependencies{})
	if code != 1 || !strings.Contains(stderr.String(), "unsupported") || out.Len() != 0 {
		t.Fatalf("%d %s %s", code, out.String(), stderr.String())
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatalf("refused commands wrote %v", entries)
	}
}
