package pairing

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/linuxtarget"
	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windowstarget"
)

const adminKeysPath = `C:\ProgramData\ssh\administrators_authorized_keys`

type fakePlatform struct {
	authority     Authority
	authorityErr  error
	files         map[string][]byte
	beforeReplace func()
	replaceErr    error
	replaces      int
}

func (p *fakePlatform) Authority(context.Context, string, string) (Authority, error) {
	return p.authority, p.authorityErr
}
func (p *fakePlatform) ReadKeys(_ context.Context, path string) (KeysFile, error) {
	contents, exists := p.files[path]
	return KeysFile{Path: path, Exists: exists, Bytes: append([]byte{}, contents...), SHA: hexSHA(contents), Security: "protected"}, nil
}
func (p *fakePlatform) ReplaceKeys(_ context.Context, file KeysFile, contents []byte) error {
	if p.replaceErr != nil {
		err := p.replaceErr
		p.replaceErr = nil
		return err
	}
	if p.beforeReplace != nil {
		p.beforeReplace()
	}
	if current, _ := p.ReadKeys(context.Background(), file.Path); current.SHA != file.SHA || current.Exists != file.Exists {
		return ErrKeysChanged
	}
	p.replaces++
	p.files[file.Path] = append([]byte{}, contents...)
	return nil
}

func hostRoot(t *testing.T) string {
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

func windowsAuthority(t *testing.T) Authority {
	t.Helper()
	installed, err := target.NewWindows("installed", windowstarget.Config{SSHUser: "operator", InteractiveUser: "operator", WorkRoot: `C:\Box`, TaskName: "box", BlenderExecutable: `C:\Blender\blender.exe`, HostExecutable: `C:\Box\bin\host.exe`, SessionBrokerExecutable: `C:\Box\bin\daemon.exe`})
	if err != nil {
		t.Fatal(err)
	}
	return Authority{Installed: installed, InstallationID: "installation-test", RootIdentity: "root-test", AccountIdentity: "S-1-5-21-test", Login: "operator", Port: 22, HostPublicKey: testPublicKey(9), KeysFile: adminKeysPath, SharedKeysFile: true}
}

// hostFixture issues one offer and builds a trusted request for it against a keys file that
// already holds two unrelated lines.
func hostFixture(t *testing.T) (Host, *fakePlatform, HostOffer, TrustedIntent) {
	t.Helper()
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	platform := &fakePlatform{authority: windowsAuthority(t), files: map[string][]byte{adminKeysPath: []byte(otherKey + "\r\n" + rsaKey + "\r\n")}}
	h := Host{Root: hostRoot(t), Platform: platform, Now: func() time.Time { return now }}
	data, sha, err := h.Offer(context.Background(), "installation-test", "host.invalid", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var offer HostOffer
	if err := json.Unmarshal(data, &offer); err != nil || OfferDigest(offer) != sha {
		t.Fatalf("offer %v %s", err, data)
	}
	return h, platform, offer, intentFor(t, offer, "pair-1", testPublicKey(7))
}
func intentFor(t *testing.T, offer HostOffer, pairID, publicKey string) TrustedIntent {
	t.Helper()
	intent := EnrollmentIntent{1, pairID, "op-1", OfferDigest(offer), publicKey, offer.Expires}
	data, _ := json.Marshal(intent)
	trusted, err := TrustIntent(data, IntentDigest(intent))
	if err != nil {
		t.Fatal(err)
	}
	return trusted
}
func records(t *testing.T, root, kind string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(root, "pairings", kind))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
func lineFor(t *testing.T, intent TrustedIntent) string {
	t.Helper()
	line, err := grantLine(intent.value.PublicKey, intent.value.PairID)
	if err != nil {
		t.Fatal(err)
	}
	return line
}

func TestTrustIntentRejectsWrongDigestAndMalformedRequests(t *testing.T) {
	_, _, offer, trusted := hostFixture(t)
	data, _ := json.Marshal(trusted.value)
	for _, digest := range []string{"", strings.Repeat("0", 64), OfferDigest(offer)} {
		if _, err := TrustIntent(data, digest); err == nil {
			t.Fatalf("accepted digest %q", digest)
		}
	}
	bad := strings.Replace(string(data), `"pair_id":"pair-1"`, `"pair_id":"-pair"`, 1)
	if _, err := TrustIntent([]byte(bad), IntentDigest(trusted.value)); err == nil {
		t.Fatal("accepted malformed pair id")
	}
}

func TestEnrollRefusesUnknownOfferAndChangedHostIdentity(t *testing.T) {
	h, platform, offer, _ := hostFixture(t)
	before := string(platform.files[adminKeysPath])
	unknown := offer
	unknown.BootstrapID = "bbxb_other"
	if _, err := h.Enroll(context.Background(), intentFor(t, unknown, "pair-1", testPublicKey(7)), true); err == nil || !strings.Contains(err.Error(), "did not issue") {
		t.Fatalf("unknown offer: %v", err)
	}
	changes := map[string]func(*Authority){
		"root identity":    func(a *Authority) { a.RootIdentity = "root-other" },
		"account identity": func(a *Authority) { a.AccountIdentity = "S-1-5-21-other" },
		"host key":         func(a *Authority) { a.HostPublicKey = testPublicKey(10) },
		"port":             func(a *Authority) { a.Port = 2222 },
		"login":            func(a *Authority) { a.Login = "other" },
	}
	for name, change := range changes {
		platform.authority = windowsAuthority(t)
		change(&platform.authority)
		_, err := h.Enroll(context.Background(), intentFor(t, offer, "pair-1", testPublicKey(7)), true)
		if err == nil || !strings.Contains(err.Error(), "host identity changed since the offer") {
			t.Fatalf("%s: %v", name, err)
		}
	}
	platform.authority = windowsAuthority(t)
	platform.authorityErr = errors.New("sshd is not running; run setup ssh")
	if _, err := h.Enroll(context.Background(), intentFor(t, offer, "pair-1", testPublicKey(7)), true); err == nil || !strings.Contains(err.Error(), "setup ssh") {
		t.Fatalf("authority error: %v", err)
	}
	if got := records(t, h.Root, "grants"); got != nil {
		t.Fatalf("grants written: %v", got)
	}
	if string(platform.files[adminKeysPath]) != before {
		t.Fatal("keys file changed")
	}
}

func TestEnrollPreviewAndCanceledContextWriteNothing(t *testing.T) {
	h, platform, _, trusted := hostFixture(t)
	before := string(platform.files[adminKeysPath])
	preview, err := h.Enroll(context.Background(), trusted, false)
	if err != nil || preview.State != "preview" || preview.Line != lineFor(t, trusted) || !preview.SharedKeysFile || preview.KeysFile != adminKeysPath || preview.KeysSHA256Before != hexSHA([]byte(before)) || preview.Receipt != nil || !strings.HasPrefix(preview.Fingerprint, "SHA256:") {
		t.Fatalf("preview %+v %v", preview, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := h.Enroll(ctx, trusted, true); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled: %v", err)
	}
	if got := records(t, h.Root, "grants"); got != nil || string(platform.files[adminKeysPath]) != before {
		t.Fatalf("preview or canceled apply wrote: %v %q", got, platform.files[adminKeysPath])
	}
}

func TestEnrollConvergesAfterCrashAtEachCheckpoint(t *testing.T) {
	for _, stage := range []string{"grant", "keys"} {
		t.Run(stage, func(t *testing.T) {
			h, platform, _, trusted := hostFixture(t)
			crash := errors.New("crash at " + stage)
			h.checkpoint = func(name string) error {
				if name == stage {
					return crash
				}
				return nil
			}
			if _, err := h.Enroll(context.Background(), trusted, true); !errors.Is(err, crash) {
				t.Fatalf("expected crash, got %v", err)
			}
			views, err := h.Status(context.Background(), "pair-1")
			if err != nil || len(views) != 1 || views[0].State != map[string]string{"grant": "granting", "keys": "granted"}[stage] {
				t.Fatalf("interrupted state %+v %v", views, err)
			}
			h.checkpoint = nil
			first, err := h.Enroll(context.Background(), trusted, true)
			if err != nil || first.State != "granted" {
				t.Fatalf("retry %+v %v", first, err)
			}
			second, err := h.Enroll(context.Background(), trusted, true)
			if err != nil || string(first.Receipt) != string(second.Receipt) || first.ReceiptSHA != second.ReceiptSHA {
				t.Fatalf("receipts differ: %s %s %v", first.Receipt, second.Receipt, err)
			}
			want := otherKey + "\r\n" + rsaKey + "\r\n" + lineFor(t, trusted) + "\r\n"
			if got := string(platform.files[adminKeysPath]); got != want || platform.replaces != 1 {
				t.Fatalf("keys %q replaces %d", got, platform.replaces)
			}
			if second.KeysSHA256Before != hexSHA([]byte(want)) || second.KeysSHA256After != hexSHA([]byte(want)) {
				t.Fatalf("repeat hashes %+v", second)
			}
			if stage == "grant" && (first.KeysSHA256Before != hexSHA([]byte(otherKey+"\r\n"+rsaKey+"\r\n")) || first.KeysSHA256After != hexSHA([]byte(want))) {
				t.Fatalf("retry hashes %+v", first)
			}
		})
	}
}

func TestEnrollRefusesDifferentRequestForSamePairAndAfterRevocation(t *testing.T) {
	h, platform, offer, trusted := hostFixture(t)
	if _, err := h.Enroll(context.Background(), trusted, true); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Enroll(context.Background(), intentFor(t, offer, "pair-1", testPublicKey(8)), true); err == nil || !strings.Contains(err.Error(), "different request") {
		t.Fatalf("different intent: %v", err)
	}
	result, err := h.Revoke(context.Background(), "pair-1", "", "host-local", true)
	if err != nil || result.State != "revoked" || result.KeysSHA256After != hexSHA([]byte(otherKey+"\r\n"+rsaKey+"\r\n")) {
		t.Fatalf("revoke %+v %v", result, err)
	}
	if _, err := h.Enroll(context.Background(), trusted, true); err == nil || !strings.Contains(err.Error(), "was revoked") {
		t.Fatalf("enroll after tombstone: %v", err)
	}
	if got := string(platform.files[adminKeysPath]); got != otherKey+"\r\n"+rsaKey+"\r\n" {
		t.Fatalf("keys %q", got)
	}
}

func TestEnrollRefusesForeignKeyOrMarkerWithoutWriting(t *testing.T) {
	cases := map[string]string{
		"unmarked copy of the key": otherKey + "\n" + testPublicKey(7) + " laptop\n",
		"marker with another key":  otherKey + "\n" + "restrict " + testPublicKey(8) + " blender-box-pair:pair-1\n",
	}
	for name, contents := range cases {
		t.Run(name, func(t *testing.T) {
			h, platform, _, trusted := hostFixture(t)
			platform.files[adminKeysPath] = []byte(contents)
			if _, err := h.Enroll(context.Background(), trusted, false); err == nil || !strings.Contains(err.Error(), "manually") {
				t.Fatalf("preview: %v", err)
			}
			if _, err := h.Enroll(context.Background(), trusted, true); err == nil || !strings.Contains(err.Error(), "manually") {
				t.Fatalf("apply: %v", err)
			}
			if string(platform.files[adminKeysPath]) != contents || platform.replaces != 0 {
				t.Fatal("keys file changed")
			}
		})
	}
}

func TestEnrollPreservesConcurrentUnrelatedEdit(t *testing.T) {
	h, platform, _, trusted := hostFixture(t)
	platform.beforeReplace = func() {
		platform.files[adminKeysPath] = append(platform.files[adminKeysPath], "ssh-rsa AAAAB3NzaC1yc2E late@edit\r\n"...)
		platform.beforeReplace = nil
	}
	if _, err := h.Enroll(context.Background(), trusted, true); !errors.Is(err, ErrKeysChanged) {
		t.Fatalf("expected ErrKeysChanged, got %v", err)
	}
	if _, err := h.Enroll(context.Background(), trusted, true); err != nil {
		t.Fatal(err)
	}
	want := otherKey + "\r\n" + rsaKey + "\r\n" + "ssh-rsa AAAAB3NzaC1yc2E late@edit\r\n" + lineFor(t, trusted) + "\r\n"
	if got := string(platform.files[adminKeysPath]); got != want {
		t.Fatalf("keys %q", got)
	}
}

func TestRevokeRefusesActiveHostAuthorityWithoutTombstone(t *testing.T) {
	h, platform, _, trusted := hostFixture(t)
	if _, err := h.Enroll(context.Background(), trusted, true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(h.Root, "host-lock.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	before := string(platform.files[adminKeysPath])
	if _, err := h.Revoke(context.Background(), "pair-1", "", "host-local", true); err == nil || !strings.Contains(err.Error(), "host-lock.json") {
		t.Fatalf("revoke under Run authority: %v", err)
	}
	if got := records(t, h.Root, "tombstones"); got != nil || string(platform.files[adminKeysPath]) != before {
		t.Fatalf("tombstones %v keys %q", got, platform.files[adminKeysPath])
	}
	fingerprint := trusted.value.PublicKey
	if _, err := h.Revoke(context.Background(), "pair-1", strings.Repeat("a", 64), "paired-ssh", true); err == nil || !strings.Contains(err.Error(), "does not own") {
		t.Fatalf("wrong client key %s: %v", fingerprint, err)
	}
	if _, err := h.Revoke(context.Background(), "pair-9", "", "host-local", true); err == nil || !strings.Contains(err.Error(), "unknown pair id") {
		t.Fatalf("unknown pair: %v", err)
	}
}

func TestRevokeConvergesAfterCrashBetweenTombstoneAndRemoval(t *testing.T) {
	h, platform, _, trusted := hostFixture(t)
	if _, err := h.Enroll(context.Background(), trusted, true); err != nil {
		t.Fatal(err)
	}
	preview, err := h.Revoke(context.Background(), "pair-1", "", "host-local", false)
	if err != nil || preview.State != "granted" || preview.KeysSHA256After != "" {
		t.Fatalf("preview %+v %v", preview, err)
	}
	crash := errors.New("crash")
	h.checkpoint = func(name string) error {
		if name == "tombstone" {
			return crash
		}
		return nil
	}
	if _, err := h.Revoke(context.Background(), "pair-1", "", "host-local", true); !errors.Is(err, crash) {
		t.Fatalf("expected crash, got %v", err)
	}
	views, err := h.Status(context.Background(), "")
	if err != nil || len(views) != 1 || views[0].State != "revoking" || views[0].Revoked == nil {
		t.Fatalf("interrupted state %+v %v", views, err)
	}
	h.checkpoint = nil
	result, err := h.Revoke(context.Background(), "pair-1", "", "host-local", true)
	if err != nil || result.State != "revoked" || result.KeysSHA256After != hexSHA([]byte(otherKey+"\r\n"+rsaKey+"\r\n")) || !hashPattern.MatchString(result.TombstoneSHA256) {
		t.Fatalf("retry %+v %v", result, err)
	}
	again, err := h.Revoke(context.Background(), "pair-1", "", "host-local", true)
	if err != nil || again.State != "revoked" || again.TombstoneSHA256 != result.TombstoneSHA256 || again.KeysSHA256Before != result.KeysSHA256After || again.KeysSHA256After != result.KeysSHA256After {
		t.Fatalf("repeat %+v %v", again, err)
	}
	if got := string(platform.files[adminKeysPath]); got != otherKey+"\r\n"+rsaKey+"\r\n" {
		t.Fatalf("keys %q", got)
	}
	if views, err := h.Status(context.Background(), "pair-1"); err != nil || views[0].State != "revoked" {
		t.Fatalf("final state %+v %v", views, err)
	}
}

// The fake Linux platform proves the seam: a platform supplies identity facts and the keys-file
// edit, and the common flow yields a paired target the existing client accepts.
func TestFakeLinuxPlatformCompletesTheWholeLifecycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("paired credentials require POSIX client")
	}
	installed, err := target.NewLinux("studio-alias", linuxtarget.Config{Distribution: linuxtarget.Distribution, UID: 1000, Home: "/home/operator", WorkRoot: "/home/operator/box", HostExecutable: "/home/operator/box/bin/blender-box", BlenderExecutable: "/opt/blender/blender", UnitName: "blender-box.service", Desktop: linuxtarget.Desktop{Display: ":0", XAuthority: "/run/user/1000/gdm/Xauthority"}, Daemon: linuxtarget.DaemonRuntime{VenvRoot: "/home/operator/daemon", PythonExecutable: "/home/operator/daemon/bin/python3", ProvenanceID: linuxtarget.ProvenanceID}})
	if err != nil {
		t.Fatal(err)
	}
	const keysPath = "/home/operator/.ssh/authorized_keys"
	platform := &fakePlatform{authority: Authority{Installed: installed, InstallationID: "installation-linux", RootIdentity: "inode-1", AccountIdentity: "1000", Login: "operator", Port: 22, HostPublicKey: testPublicKey(11), KeysFile: keysPath}, files: map[string][]byte{keysPath: []byte(otherKey + "\n")}}
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	h := Host{Root: hostRoot(t), Platform: platform, Now: func() time.Time { return now }}
	client := Client{Root: filepath.Join(t.TempDir(), "config"), Now: func() time.Time { return now }}

	offerBytes, offerSHA, err := h.Offer(context.Background(), "installation-linux", "studio.example", 0)
	if err != nil {
		t.Fatal(err)
	}
	offer, err := TrustOffer(offerBytes, offerSHA, now)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := client.Prepare(context.Background(), "studio", offer)
	if err != nil {
		t.Fatal(err)
	}
	intentBytes, _ := json.Marshal(intent)
	trusted, err := TrustIntent(intentBytes, IntentDigest(intent))
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := h.Enroll(context.Background(), trusted, true)
	if err != nil || enrollment.State != "granted" {
		t.Fatalf("enroll %+v %v", enrollment, err)
	}
	receipt, err := TrustReceipt(enrollment.Receipt, enrollment.ReceiptSHA)
	if err != nil {
		t.Fatal(err)
	}
	paired, err := client.Complete(context.Background(), "studio", receipt)
	if err != nil {
		t.Fatal(err)
	}
	direct, isPaired := paired.Connection().Direct()
	if paired.Platform() != "linux" || !isPaired || direct.Host != "studio.example" || direct.User != "operator" || direct.HostPublicKey != testPublicKey(11) || paired.Linux() != installed.Linux() {
		t.Fatalf("paired target %+v", direct)
	}
	fingerprint, _ := sshkey.Fingerprint(intent.PublicKey)
	if direct.ClientPublicKeyHash != fingerprint {
		t.Fatal("paired target pins a different client key")
	}
	if got := string(platform.files[keysPath]); got != otherKey+"\n"+"restrict "+intent.PublicKey+" blender-box-pair:"+intent.PairID+"\n" {
		t.Fatalf("keys %q", got)
	}
	result, err := h.Revoke(context.Background(), intent.PairID, fingerprint, "paired-ssh", true)
	if err != nil || result.State != "revoked" || string(platform.files[keysPath]) != otherKey+"\n" {
		t.Fatalf("revoke %+v %v %q", result, err, platform.files[keysPath])
	}
	if _, err := ParseRevokeResult(mustJSON(t, result), intent.PairID); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestEnrollRechecksRevocationUnderTheLock(t *testing.T) {
	h, platform, _, trusted := hostFixture(t)
	before := string(platform.files[adminKeysPath])
	crash := errors.New("crash")
	h.checkpoint = func(name string) error {
		if name == "grant" {
			return crash
		}
		return nil
	}
	if _, err := h.Enroll(context.Background(), trusted, true); !errors.Is(err, crash) {
		t.Fatalf("expected crash, got %v", err)
	}
	concurrent := Host{Root: hostRoot(t), Platform: platform, Now: h.Now}
	grant, err := os.ReadFile(filepath.Join(h.Root, grantPath("pair-1")))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(concurrent.Root, grantPath("pair-1"))), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(concurrent.Root, grantPath("pair-1")), grant, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := concurrent.Revoke(context.Background(), "pair-1", "", "host-local", true); err != nil {
		t.Fatal(err)
	}
	tombstone, err := os.ReadFile(filepath.Join(concurrent.Root, tombPath("pair-1")))
	if err != nil {
		t.Fatal(err)
	}
	h.checkpoint = func(name string) error {
		if name == "grant" {
			if err := os.MkdirAll(filepath.Dir(filepath.Join(h.Root, tombPath("pair-1"))), 0o700); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(h.Root, tombPath("pair-1")), tombstone, 0o600)
		}
		return nil
	}
	if _, err := h.Enroll(context.Background(), trusted, true); err == nil || !strings.Contains(err.Error(), "was revoked") {
		t.Fatalf("enroll racing a revoke = %v", err)
	}
	if got := string(platform.files[adminKeysPath]); got != before {
		t.Fatalf("revoked key re-added: %q", got)
	}
}

func TestRevokeRefusesWhileTheKeyRemainsOnAnotherLine(t *testing.T) {
	h, platform, _, trusted := hostFixture(t)
	if _, err := h.Enroll(context.Background(), trusted, true); err != nil {
		t.Fatal(err)
	}
	line := lineFor(t, trusted)
	platform.files[adminKeysPath] = []byte(strings.Replace(string(platform.files[adminKeysPath]), line+"\r\n", line+" \r\n", 1))
	result, err := h.Revoke(context.Background(), "pair-1", "", "host-local", true)
	if err == nil || result.State == "revoked" || !strings.Contains(err.Error(), "different line") {
		t.Fatalf("revoke with an edited copy = %+v, %v", result, err)
	}
}
