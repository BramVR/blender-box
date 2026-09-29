package windowsinstall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/pairing"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windowstarget"
)

const testUserSID = "S-1-5-21-1-2-3-1001"

// realAdminKeysSDDL is the descriptor an in-use administrators_authorized_keys carried on a real
// host: owner Administrators, group the account's own SID, protected auto-inherited DACL.
const realAdminKeysSDDL = `O:BAG:S-1-5-21-1111111111-2222222-333333333-1001D:PAI(A;;FA;;;SY)(A;;FA;;;BA)`

func TestVerifyDescriptorAcceptsOnlyWhatSSHDAccepts(t *testing.T) {
	cases := []struct {
		name, sddl, kind string
		refused          string
	}{
		{"admin default", adminKeysSDDL, "admin", ""},
		{"admin with users entry", `O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;BU)`, "admin", "S-1-5-32-545"},
		{"admin unprotected", `O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)`, "admin", "protected"},
		{"admin inherited protected", `O:SYG:SYD:PAI(A;ID;FA;;;SY)(A;ID;FA;;;BA)`, "admin", ""},
		{"admin real host with account group", realAdminKeysSDDL, "admin", ""},
		{"admin owner users", `O:BUG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`, "admin", "owner S-1-5-32-545"},
		{"admin deny entry", `O:BAG:SYD:P(D;;FA;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)`, "admin", "S-1-5-32-545"},
		{"admin null dacl", `O:BAG:SYD:NO_ACCESS_CONTROL`, "admin", "unsupported DACL flags"},
		{"admin no dacl", `O:BAG:SY`, "admin", "no DACL"},
		{"user default", `O:` + testUserSID + `G:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;` + testUserSID + `)`, "user", ""},
		{"user inherited from profile", `O:` + testUserSID + `G:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;FA;;;` + testUserSID + `)`, "user", ""},
		{"user with users full", `O:` + testUserSID + `G:SYD:P(A;;FA;;;SY)(A;;FA;;;` + testUserSID + `)(A;;FA;;;BU)`, "user", "S-1-5-32-545 can write"},
		{"user with everyone generic write", `O:` + testUserSID + `G:SYD:P(A;;FA;;;SY)(A;;GW;;;S-1-1-0)`, "user", "S-1-1-0 can write"},
		{"user with users modify mask", `O:` + testUserSID + `G:SYD:P(A;;FA;;;SY)(A;;0x1301bf;;;BU)`, "user", "S-1-5-32-545 can write"},
		{"user with users read", `O:` + testUserSID + `G:SYD:P(A;;FA;;;SY)(A;;FR;;;BU)`, "user", ""},
		{"user with users deny", `O:` + testUserSID + `G:SYD:P(D;;FA;;;BU)(A;;FA;;;SY)`, "user", ""},
		{"user owner other account", `O:S-1-5-21-1-2-3-1002G:SYD:P(A;;FA;;;SY)`, "user", "owner S-1-5-21-1-2-3-1002"},
		{"user unknown alias", `O:DAG:SYD:P(A;;FA;;;SY)`, "user", `unsupported SID "DA"`},
		{"user unknown right", `O:SYG:SYD:P(A;;KA;;;BU)`, "user", `unsupported access right "KA"`},
		{"user conditional entry", `O:SYG:SYD:P(XA;;FA;;;BU;(Member_of {SID(BA)}))`, "user", "malformed access entry"},
	}
	for _, tc := range cases {
		err := verifyDescriptor(tc.sddl, tc.kind, testUserSID)
		switch {
		case tc.refused == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.name, err)
		case tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)):
			t.Errorf("%s: want refusal containing %q, got %v", tc.name, tc.refused, err)
		}
	}
	if err := verifyDescriptor(adminKeysSDDL, "user", ""); err == nil || !strings.Contains(err.Error(), "account SID required") {
		t.Fatalf("user kind without a SID: %v", err)
	}
	if err := verifyDescriptor(adminKeysSDDL, "group", testUserSID); err == nil {
		t.Fatal("unknown kind accepted")
	}
}

type fakeSSHD struct {
	result sshdFacts
	err    error
	spec   string
}

func (f *fakeSSHD) facts(_ context.Context, account, host, addr string) (sshdFacts, error) {
	f.spec = account + "," + host + "," + addr
	return f.result, f.err
}

type fakeKeysFile struct {
	bytes     []byte
	sddl      string
	reparse   bool
	directory bool
}
type fakeKeys struct {
	files    map[string]*fakeKeysFile
	readBack func(*keysObservation)
	replaced []keysReplacement
}

func (f *fakeKeys) observe(path string) keysObservation {
	file := f.files[path]
	if file == nil {
		return keysObservation{}
	}
	owner := ""
	if descriptor, err := parseSDDL(file.sddl); err == nil {
		owner = descriptor.Owner
	}
	return keysObservation{Exists: true, Reparse: file.reparse, Regular: !file.directory, Size: int64(len(file.bytes)), SHA: string(digest(file.bytes)), SDDL: file.sddl, Security: "canonical:" + file.sddl, Owner: owner, Bytes: file.bytes}
}
func (f *fakeKeys) read(_ context.Context, path string) (keysObservation, error) {
	return f.observe(path), nil
}
func (f *fakeKeys) replace(_ context.Context, r keysReplacement) (keysObservation, error) {
	f.replaced = append(f.replaced, r)
	file := f.files[r.Path]
	if (file != nil) != r.Exists || file != nil && (string(digest(file.bytes)) != r.ExpectedSHA || "canonical:"+file.sddl != r.ExpectedSecurity) {
		return keysObservation{}, fmt.Errorf("%w: fake store compare", pairing.ErrKeysChanged)
	}
	if file == nil {
		file = &fakeKeysFile{sddl: r.NewSecurity}
		f.files[r.Path] = file
	}
	file.bytes = r.Contents
	observed := f.observe(r.Path)
	if f.readBack != nil {
		f.readBack(&observed)
	}
	return observed, nil
}

func runningSSHD() sshdFacts {
	return sshdFacts{ServiceStatus: "Running", StartType: "Automatic", Port: 22, PubkeyAuthentication: true, AuthorizedKeysFile: defaultAdminKeysFile, HostKeyEd25519: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb0dz5pD1+7w1M0LqQxK8xW9bVj7QYpYQ8yG8zzB8Xg", Elevated: true}
}

// installedReceipt publishes an installed receipt the way the installer leaves one, with the
// root identity the fake machine will observe for root.
func installedReceipt(t *testing.T, root, id, rootIdentity string) installationReceipt {
	t.Helper()
	intent := installIntent{Root: root, OwnerSID: "S-1-5-21-test", SSHAlias: "test-host", WindowsUser: "test-user", Task: TaskPlan{Name: "test-task", OwnerSID: "S-1-5-21-test", InstallationID: InstallationID(id), Executable: `C:\Box\runtime\blender-box.exe`}, Files: []File{{Path: "runtime", Kind: "directory"}}}
	receipt := installationReceipt{SchemaVersion: 1, InstallationID: InstallationID(id), OperationID: OperationID("bbxo_" + strings.Repeat("1", 32)), RootIdentity: rootIdentity, Intent: intent, IntentSHA256: objectDigest(intent), State: "installed", Files: []File{{Path: "runtime", Kind: "directory", Identity: "runtime-id"}}, TaskFingerprint: SHA256(strings.Repeat("c", 64)), Deleted: []string{}}
	directory := filepath.Join(root, "installations", id)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveReceipt(filepath.Join(directory, "receipt.json"), &receipt, false); err != nil {
		t.Fatal(err)
	}
	return receipt
}

func authorityFixture(t *testing.T) (pairingPlatform, *fakeMachine, *fakeSSHD, string, string) {
	t.Helper()
	root := tempRoot(t)
	id := "bbxi_" + strings.Repeat("a", 32)
	rootIdentity, err := fileIdentity(root)
	if err != nil {
		t.Fatal(err)
	}
	installedReceipt(t, root, id, rootIdentity)
	machine := &fakeMachine{inspection: Inspection{OwnerSID: "S-1-5-21-test"}}
	sshd := &fakeSSHD{result: runningSSHD()}
	return pairingPlatform{machine: machine, sshd: sshd, keys: &fakeKeys{files: map[string]*fakeKeysFile{}}, adminKeysFile: defaultAdminKeysFile}, machine, sshd, root, id
}

func TestAuthorityRefusesWithoutElevationBeforeTouchingTheHost(t *testing.T) {
	platform, machine, sshd, root, id := authorityFixture(t)
	sshd.result = sshdFacts{}
	machine.inspectionErr = errors.New("installation inspected before the elevation gate")
	_, err := platform.Authority(context.Background(), root, id)
	if err == nil || !strings.Contains(err.Error(), "run from an elevated PowerShell on the host, or over your admin SSH channel") {
		t.Fatalf("err=%v", err)
	}
	if _, err := platform.Authority(context.Background(), root, "bbxi_nope"); err == nil || !strings.Contains(err.Error(), "invalid installation id") {
		t.Fatalf("err=%v", err)
	}
}

func TestAuthorityNamesSetupSSHWhenSSHDIsNotReady(t *testing.T) {
	platform, _, sshd, root, id := authorityFixture(t)
	sshd.result.ServiceStatus = "Stopped"
	if _, err := platform.Authority(context.Background(), root, id); err == nil || !strings.Contains(err.Error(), "sshd is Stopped") || !strings.Contains(err.Error(), "setup ssh") {
		t.Fatalf("stopped: %v", err)
	}
	sshd.result = runningSSHD()
	sshd.result.PubkeyAuthentication = false
	if _, err := platform.Authority(context.Background(), root, id); err == nil || !strings.Contains(err.Error(), "PubkeyAuthentication") || !strings.Contains(err.Error(), "setup ssh") {
		t.Fatalf("pubkey off: %v", err)
	}
}

func TestAuthorityRefusesIdentityDrift(t *testing.T) {
	platform, machine, _, root, id := authorityFixture(t)
	machine.inspection.OwnerSID = "S-1-5-21-other"
	if _, err := platform.Authority(context.Background(), root, id); err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("owner drift: %v", err)
	}
	machine.inspection.OwnerSID = "S-1-5-21-test"
	receiptPath := filepath.Join(root, "installations", id, "receipt.json")
	receipt, err := readReceipt(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	receipt.RootIdentity = "other-volume"
	if err := saveReceipt(receiptPath, &receipt, true); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.Authority(context.Background(), root, id); err == nil || !strings.Contains(err.Error(), "no longer matches") {
		t.Fatalf("root drift: %v", err)
	}
	receipt.State = "partial"
	receipt.RootIdentity, _ = fileIdentity(root)
	receipt.TaskFingerprint = ""
	receipt.Files = []File{}
	if err := saveReceipt(receiptPath, &receipt, true); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.Authority(context.Background(), root, id); err == nil || !strings.Contains(err.Error(), "is partial, not installed") {
		t.Fatalf("partial: %v", err)
	}
}

func TestAuthorityReturnsTheAccountAndKeysFileSSHDResolves(t *testing.T) {
	platform, _, sshd, root, id := authorityFixture(t)
	got, err := platform.Authority(context.Background(), root, id)
	if err != nil {
		t.Fatal(err)
	}
	if sshd.spec != "test-user,localhost,127.0.0.1" {
		t.Fatalf("sshd -T connection spec %q", sshd.spec)
	}
	installed, err := target.NewWindows("test-host", windowstarget.Config{SSHUser: "test-user", InteractiveUser: "test-user", WorkRoot: `C:\Box`, TaskName: "test-task", BlenderExecutable: `C:\Blender\blender.exe`, SessionBrokerExecutable: `C:\Box\runtime\blendersessiond.exe`, HostExecutable: `C:\Box\runtime\blender-box.exe`})
	if err != nil {
		t.Fatal(err)
	}
	rootIdentity, _ := fileIdentity(root)
	want := pairing.Authority{Installed: installed, InstallationID: id, RootIdentity: rootIdentity, AccountIdentity: "S-1-5-21-test", Login: "test-user", Port: 22, HostPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb0dz5pD1+7w1M0LqQxK8xW9bVj7QYpYQ8yG8zzB8Xg", KeysFile: defaultAdminKeysFile, SharedKeysFile: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	sshd.result.AuthorizedKeysFile = strings.ToLower(defaultAdminKeysFile)
	if got, err = platform.Authority(context.Background(), root, id); err != nil || !got.SharedKeysFile {
		t.Fatalf("differently cased admin file: %+v err=%v", got, err)
	}
	sshd.result.AuthorizedKeysFile = `C:\Users\test-user\.ssh\authorized_keys`
	got, err = platform.Authority(context.Background(), root, id)
	if err != nil || got.SharedKeysFile || got.KeysFile != `C:\Users\test-user\.ssh\authorized_keys` {
		t.Fatalf("per-user file: %+v err=%v", got, err)
	}
}

func keysFixture() (pairingPlatform, *fakeKeys) {
	store := &fakeKeys{files: map[string]*fakeKeysFile{}}
	return pairingPlatform{keys: store, adminKeysFile: defaultAdminKeysFile}, store
}

func TestReadKeysReturnsBytesOnlyForFilesSSHDWouldTrust(t *testing.T) {
	platform, store := keysFixture()
	userFile := `C:\Users\test-user\.ssh\authorized_keys`
	ctx := context.Background()
	missing, err := platform.ReadKeys(ctx, defaultAdminKeysFile)
	if err != nil || !reflect.DeepEqual(missing, pairing.KeysFile{Path: defaultAdminKeysFile, Bytes: []byte{}, SHA: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}) {
		t.Fatalf("missing: %+v err=%v", missing, err)
	}
	store.files[defaultAdminKeysFile] = &fakeKeysFile{bytes: []byte("ssh-ed25519 AAAA one\n"), sddl: adminKeysSDDL}
	admin, err := platform.ReadKeys(ctx, defaultAdminKeysFile)
	want := pairing.KeysFile{Path: defaultAdminKeysFile, Exists: true, Bytes: []byte("ssh-ed25519 AAAA one\n"), SHA: string(digest([]byte("ssh-ed25519 AAAA one\n"))), Security: "canonical:" + adminKeysSDDL}
	if err != nil || !reflect.DeepEqual(admin, want) {
		t.Fatalf("admin: %+v err=%v", admin, err)
	}
	store.files[defaultAdminKeysFile].sddl = `O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;BU)`
	if _, err := platform.ReadKeys(ctx, defaultAdminKeysFile); err == nil || !strings.Contains(err.Error(), "never changes it") || !strings.Contains(err.Error(), "S-1-5-32-545") {
		t.Fatalf("users modify on admin file: %v", err)
	}
	store.files[userFile] = &fakeKeysFile{bytes: []byte("k\n"), sddl: `O:` + testUserSID + `G:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;` + testUserSID + `)(A;;FR;;;BU)`}
	if user, err := platform.ReadKeys(ctx, userFile); err != nil || string(user.Bytes) != "k\n" {
		t.Fatalf("user file: %+v err=%v", user, err)
	}
	store.files[userFile].sddl = `O:` + testUserSID + `G:SYD:P(A;;FA;;;SY)(A;;GW;;;S-1-1-0)`
	if _, err := platform.ReadKeys(ctx, userFile); err == nil || !strings.Contains(err.Error(), "S-1-1-0 can write") {
		t.Fatalf("everyone write on user file: %v", err)
	}
	store.files[userFile] = &fakeKeysFile{bytes: make([]byte, pairing.MaxKeysFile+1), sddl: `O:` + testUserSID + `G:SYD:P(A;;FA;;;SY)`}
	if _, err := platform.ReadKeys(ctx, userFile); err == nil || !strings.Contains(err.Error(), "exceeds 1048576 bytes") {
		t.Fatalf("oversize: %v", err)
	}
	store.files[userFile] = &fakeKeysFile{bytes: []byte("k\n"), sddl: `O:` + testUserSID + `G:SYD:P(A;;FA;;;SY)`, reparse: true}
	if _, err := platform.ReadKeys(ctx, userFile); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("reparse: %v", err)
	}
	store.files[userFile] = &fakeKeysFile{sddl: `O:` + testUserSID + `G:SYD:P(A;;FA;;;SY)`, directory: true}
	if _, err := platform.ReadKeys(ctx, userFile); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory: %v", err)
	}
}

func TestReplaceKeysSwapsOnlyAgainstTheObservedFile(t *testing.T) {
	platform, store := keysFixture()
	ctx := context.Background()
	store.files[defaultAdminKeysFile] = &fakeKeysFile{bytes: []byte("one\n"), sddl: adminKeysSDDL}
	file, err := platform.ReadKeys(ctx, defaultAdminKeysFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.ReplaceKeys(ctx, file, []byte("one\ntwo\n")); err != nil || string(store.files[defaultAdminKeysFile].bytes) != "one\ntwo\n" {
		t.Fatalf("replace: err=%v bytes=%q", err, store.files[defaultAdminKeysFile].bytes)
	}
	err = platform.ReplaceKeys(ctx, file, []byte("one\nthree\n"))
	if !errors.Is(err, pairing.ErrKeysChanged) || string(store.files[defaultAdminKeysFile].bytes) != "one\ntwo\n" {
		t.Fatalf("stale observation: err=%v bytes=%q", err, store.files[defaultAdminKeysFile].bytes)
	}
	file, _ = platform.ReadKeys(ctx, defaultAdminKeysFile)
	store.readBack = func(observed *keysObservation) { observed.SHA = string(digest([]byte("other"))) }
	if err := platform.ReplaceKeys(ctx, file, []byte("one\n")); err == nil || !strings.Contains(err.Error(), "does not hold the written bytes") {
		t.Fatalf("read-back bytes: %v", err)
	}
	file, _ = platform.ReadKeys(ctx, defaultAdminKeysFile)
	store.readBack = func(observed *keysObservation) {
		observed.Security = "canonical:" + `O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)`
	}
	if err := platform.ReplaceKeys(ctx, file, []byte("one\n")); err == nil || !strings.Contains(err.Error(), "security changed during replace") {
		t.Fatalf("read-back security: %v", err)
	}
	store.readBack = nil
	if err := platform.ReplaceKeys(ctx, file, make([]byte, pairing.MaxKeysFile+1)); err == nil || !strings.Contains(err.Error(), "would exceed") {
		t.Fatalf("oversize: %v", err)
	}
}

func TestReplaceKeysCreatesOnlyTheAdministratorsFile(t *testing.T) {
	platform, store := keysFixture()
	ctx := context.Background()
	userFile := `C:\Users\test-user\.ssh\authorized_keys`
	missing, _ := platform.ReadKeys(ctx, userFile)
	if err := platform.ReplaceKeys(ctx, missing, []byte("k\n")); err == nil || !strings.Contains(err.Error(), "create it as the account first") || len(store.replaced) != 0 {
		t.Fatalf("missing user file: err=%v replaced=%d", err, len(store.replaced))
	}
	missing, _ = platform.ReadKeys(ctx, defaultAdminKeysFile)
	if err := platform.ReplaceKeys(ctx, missing, []byte("k\n")); err != nil {
		t.Fatal(err)
	}
	want := keysReplacement{Path: defaultAdminKeysFile, ExpectedSHA: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", NewSecurity: `O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)`, Contents: []byte("k\n")}
	if len(store.replaced) != 1 || !reflect.DeepEqual(store.replaced[0], want) {
		t.Fatalf("replacement %+v", store.replaced)
	}
	created, err := platform.ReadKeys(ctx, defaultAdminKeysFile)
	if err != nil || string(created.Bytes) != "k\n" || created.Security != "canonical:"+adminKeysSDDL {
		t.Fatalf("created: %+v err=%v", created, err)
	}
	delete(store.files, defaultAdminKeysFile)
	store.readBack = func(observed *keysObservation) { observed.SDDL = `O:BAG:SYD:(A;;FA;;;SY)(A;;FA;;;BA)` }
	if err := platform.ReplaceKeys(ctx, missing, []byte("k\n")); err == nil || !strings.Contains(err.Error(), "created with a security descriptor sshd rejects") {
		t.Fatalf("created unprotected: %v", err)
	}
}

func TestReplaceKeysKeepsAnExistingAdministratorsDescriptorAndCRLFBytes(t *testing.T) {
	platform, store := keysFixture()
	ctx := context.Background()
	initial := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb0dz5pD1+7w1M0LqQxK8xW9bVj7QYpYQ8yG8zzB8Xg operator@one\r\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN1mB4l0cR9w2yP3vA5qF6tG7hJ8kL9mN0oP1qR2sT3u operator@two\r\n"
	store.files[defaultAdminKeysFile] = &fakeKeysFile{bytes: []byte(initial), sddl: realAdminKeysSDDL}
	file, err := platform.ReadKeys(ctx, defaultAdminKeysFile)
	if err != nil || file.Security != "canonical:"+realAdminKeysSDDL {
		t.Fatalf("read: %+v err=%v", file, err)
	}
	appended := initial + "restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA blender-box-pair:pair-1\r\n"
	if err := platform.ReplaceKeys(ctx, file, []byte(appended)); err != nil {
		t.Fatal(err)
	}
	if got := store.files[defaultAdminKeysFile]; string(got.bytes) != appended || got.sddl != realAdminKeysSDDL {
		t.Fatalf("after replace bytes=%q sddl=%q", got.bytes, got.sddl)
	}
	if len(store.replaced) != 1 || store.replaced[0].NewSecurity != "" || store.replaced[0].ExpectedSecurity != "canonical:"+realAdminKeysSDDL {
		t.Fatalf("replacement %+v", store.replaced)
	}
}
