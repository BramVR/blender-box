package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/pairing"
	sshtransport "github.com/BramVR/blender-box/internal/ssh"
	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windows"
)

type pairCLI struct {
	t      *testing.T
	pairID string
	now    time.Time
	remote *fakeSSH
}

func (cli pairCLI) call(args ...string) (int, string, string) {
	cli.t.Helper()
	var out, stderr bytes.Buffer
	code := Run(context.Background(), args, strings.NewReader(""), &out, &stderr, Dependencies{Now: func() time.Time { return cli.now }, PairRemote: windows.NewAdapter(cli.remote)})
	return code, out.String(), stderr.String()
}

// hostAnswers makes the fake SSH answer `host pair-revoke` and the no-op probe in order.
func (cli pairCLI) hostAnswers(revoke error, probes ...error) {
	cli.remote.runResult = func(args []string, _ []byte) ([]byte, error) {
		if len(args) == 2 && args[0] == "exit" {
			err := probes[0]
			probes = probes[1:]
			return nil, err
		}
		if revoke != nil {
			return nil, revoke
		}
		hash := strings.Repeat("a", 64)
		return []byte(fmt.Sprintf(`{"schema_version":1,"pair_id":"%s","state":"revoked","keys_sha256_before":"%s","keys_sha256_after":"%s","tombstone_sha256":"%s"}`, cli.pairID, hash, hash, hash)), nil
	}
}

func enrolledCLI(t *testing.T) pairCLI {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("paired credentials require POSIX")
	}
	t.Setenv("BLENDER_BOX_CONFIG_DIR", filepath.Join(t.TempDir(), "private"))
	installed, err := target.Load(writeTarget(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	cli := pairCLI{t: t, now: time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC), remote: &fakeSSH{}}
	hostKey, _, err := sshkey.Generate(context.Background(), filepath.Join(t.TempDir(), "host-key"))
	if err != nil {
		t.Fatal(err)
	}
	offer := pairing.HostOffer{SchemaVersion: 1, BootstrapID: "bootstrap-test", Expires: cli.now.Add(time.Hour), Platform: "windows", Connection: pairing.ServerSSH{Host: "100.101.102.103", Port: 22, User: "test-user", HostPublicKey: hostKey}, Installed: installed, InstallationID: "installation-test", RootIdentity: "root-test", AccountIdentity: "account-test"}
	encoded, _ := json.Marshal(offer)
	offerPath := filepath.Join(t.TempDir(), "offer.json")
	if err := os.WriteFile(offerPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	code, out, stderr := cli.call("pair", "prepare", "work", "--offer", offerPath, "--trust-offer", pairing.OfferDigest(offer))
	var intent pairing.EnrollmentIntent
	if code != 0 || json.Unmarshal([]byte(out), &intent) != nil {
		t.Fatalf("prepare: %d %s", code, stderr)
	}
	if want := "Enrollment request SHA-256 " + pairing.IntentDigest(intent) + "\n"; stderr != want {
		t.Fatalf("prepare stderr = %q, want %q", stderr, want)
	}
	fingerprint, _ := sshkey.Fingerprint(intent.PublicKey)
	paired, err := target.NewPaired(installed, target.DirectSSH{Host: offer.Connection.Host, Port: offer.Connection.Port, User: offer.Connection.User, HostPublicKey: hostKey, ClientPublicKeyHash: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	receipt := pairing.EnrollmentReceipt{SchemaVersion: 1, PairID: intent.PairID, OperationID: intent.OperationID, IntentSHA: pairing.IntentDigest(intent), Platform: "windows", ScopeSHA: strings.Repeat("1", 64), Target: paired, PublicKey: intent.PublicKey}
	encoded, _ = json.Marshal(receipt)
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.WriteFile(receiptPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := cli.call("pair", "complete", "work", "--receipt", receiptPath, "--trust-receipt", pairing.ReceiptDigest(receipt)); code != 0 {
		t.Fatalf("complete: %d %s", code, stderr)
	}
	cli.pairID = intent.PairID
	return cli
}

func (cli pairCLI) access() string {
	cli.t.Helper()
	code, out, stderr := cli.call("pair", "status", "work", "--json")
	var view pairing.PairView
	if code != 0 || json.Unmarshal([]byte(out), &view) != nil {
		cli.t.Fatalf("status: %d %s", code, stderr)
	}
	return view.Access
}

func TestPairRevokeCLIKeepsStateUntilRejectionIsProven(t *testing.T) {
	cli := enrolledCLI(t)
	cli.hostAnswers(&sshtransport.Failure{Class: sshtransport.TailscaleUnreachable, Detail: "ssh: connect to host 100.101.102.103 port 22: Operation timed out"})
	code, out, stderr := cli.call("pair", "revoke", "work")
	want := "Pair " + cli.pairID + ": revocation unconfirmed. Local pairing state kept.\nNext: retry pair revoke work once the host is reachable, or remove the key on the host with `blender-box pair revoke --state-root C:\\BlenderBoxTest --pair " + cli.pairID + " --apply`\n"
	if code != 1 || out != want || !strings.Contains(stderr, "tailscale-unreachable: connect this machine to the tailnet") {
		t.Fatalf("unreachable revoke: %d\n%s\n%s", code, out, stderr)
	}
	if access := cli.access(); access != "enrolled" {
		t.Fatalf("access after unreachable revoke = %s", access)
	}

	cli.hostAnswers(nil, &sshtransport.Failure{Class: sshtransport.HostUnreachable, Detail: "ssh: connect to host 100.101.102.103 port 22: Connection refused"}, &sshtransport.Failure{Class: sshtransport.AuthRejected, Detail: "test-user@100.101.102.103: Permission denied (publickey)."})
	if code, out, _ := cli.call("pair", "revoke", "work", "--json"); code != 1 || !strings.Contains(out, `"state": "host-revoked-unconfirmed"`) || !strings.Contains(out, `"failure": "host-unreachable"`) {
		t.Fatalf("lost probe: %d %s", code, out)
	}
	if access := cli.access(); access != "revocation-pending" {
		t.Fatalf("access after lost probe = %s", access)
	}
	code, out, stderr = cli.call("pair", "revoke", "work")
	if want := "Pair " + cli.pairID + " revoked: the host removed its key and a fresh paired connection is rejected. Local pairing state removed.\n"; code != 0 || out != want {
		t.Fatalf("confirmed revoke: %d\n%s\n%s", code, out, stderr)
	}
	if access := cli.access(); access != "none" {
		t.Fatalf("access after revoke = %s", access)
	}
	if code, _, _ := cli.call("targets", "show", "work"); code != 1 {
		t.Fatal("paired target remains after revoke")
	}
}

func TestPairForgetCLIRefusesAcceptedAccessUnlessKept(t *testing.T) {
	cli := enrolledCLI(t)
	code, _, stderr := cli.call("pair", "forget", "work")
	if code != 1 || !strings.Contains(stderr, "`blender-box pair revoke --state-root C:\\BlenderBoxTest --pair "+cli.pairID+" --apply`") {
		t.Fatalf("forget refusal: %d %s", code, stderr)
	}
	if code, _, _ := cli.call("pair", "forget", "work", "--timeout", "1m"); code != 2 {
		t.Fatal("forget accepted a revoke flag")
	}
	code, out, stderr := cli.call("pair", "forget", "work", "--keep-remote-access", "--json")
	var result pairing.ForgetResult
	if code != 0 || json.Unmarshal([]byte(out), &result) != nil || result.RemoteAccess != "not-revoked" || result.PairID != cli.pairID {
		t.Fatalf("kept forget: %d %s %s", code, out, stderr)
	}
	if access := cli.access(); access != "none" {
		t.Fatalf("access after forget = %s", access)
	}
}

func TestTargetsForgetOfPairedTargetSaysRemoteAccessRemains(t *testing.T) {
	cli := enrolledCLI(t)
	code, out, stderr := cli.call("targets", "forget", "work")
	if want := "Remote access NOT revoked (pair " + cli.pairID + "). Run: blender-box pair revoke work\n"; code != 0 || out != "Target work forgotten\n" || stderr != want {
		t.Fatalf("targets forget: %d %q %q", code, out, stderr)
	}
	cli.hostAnswers(nil, &sshtransport.Failure{Class: sshtransport.AuthRejected, Detail: "test-user@100.101.102.103: Permission denied (publickey)."})
	if code, _, stderr := cli.call("pair", "revoke", "work"); code != 0 {
		t.Fatalf("revoke after targets forget: %d %s", code, stderr)
	}
}

func TestDoctorPrintsReadinessProblemClasses(t *testing.T) {
	root := t.TempDir()
	targetPath := writeTarget(t, root)
	if err := os.WriteFile(filepath.Join(root, "scenario.py"), []byte("print('ready')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(root, "payload.json")
	if err := os.WriteFile(payloadPath, []byte(`{"schema_version":1,"files":[{"source":"scenario.py","destination":"scenario.py"}],"scenario":{"script":"scenario.py"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	checks := []map[string]any{}
	for _, id := range []string{"host.windows", "host.console-user", "host.ssh-user", "host.limited-token-policy", "blender.executable", "daemon.executable", "host.executable", "work-root.access", "work-root.state-tree", "task.interactive"} {
		failed := id == "host.console-user" || id == "daemon.executable"
		checks = append(checks, map[string]any{"id": id, "passed": !failed, "required": true, "message": id + " message."})
	}
	stdout, _ := json.Marshal(map[string]any{"schema_version": 1, "status": "fail", "checks": checks})
	dependencies := Dependencies{RunnerFor: func(target.Target) RunService {
		return orchestrator.New(windows.NewAdapter(&fakeSSH{stdout: stdout}), t.TempDir())
	}}
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"doctor", "--target", targetPath, "--payload", payloadPath}, strings.NewReader(""), &out, &stderr, dependencies)
	want := "Doctor: fail\n" +
		"interactive-desktop-unavailable (host.console-user): host.console-user message. Next: sign in to the host desktop as the target's interactive user and leave that session signed in\n" +
		"runtime-incompatible (daemon.executable): daemon.executable message. Next: on the host, run `blender-box setup inspect --platform windows --state-root C:\\BlenderBoxTest` and reinstall the runtime it reports\n"
	if code != 1 || out.String() != want {
		t.Fatalf("doctor: %d\n%s\n%s", code, out.String(), stderr.String())
	}
	out.Reset()
	code = Run(context.Background(), []string{"doctor", "--target", targetPath, "--payload", payloadPath, "--json"}, strings.NewReader(""), &out, &stderr, dependencies)
	var result orchestrator.DoctorResult
	if code != 1 || json.Unmarshal(out.Bytes(), &result) != nil || len(result.Host.Problems) != 2 || result.Host.Problems[1].Class != "runtime-incompatible" {
		t.Fatalf("doctor json: %d %s", code, out.String())
	}
}
