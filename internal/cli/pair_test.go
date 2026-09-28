package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/pairing"
	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/target"
)

func TestPairCLIExplicitTrustAndDurableReconciliation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("paired credentials require POSIX")
	}
	root := filepath.Join(t.TempDir(), "private")
	t.Setenv("BLENDER_BOX_CONFIG_DIR", root)
	installed, err := target.Load(writeTarget(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	public, _, err := sshkey.Generate(context.Background(), filepath.Join(t.TempDir(), "host-key"))
	if err != nil {
		t.Fatal(err)
	}
	offer := pairing.HostOffer{SchemaVersion: 1, BootstrapID: "bootstrap-test", Expires: now.Add(time.Hour), Platform: "windows", Connection: pairing.ServerSSH{Host: "host.invalid", Port: 2222, User: "operator", HostPublicKey: public}, Installed: installed, InstallationID: "installation-test", RootIdentity: "root-test", AccountIdentity: "account-test"}
	offerPath := filepath.Join(t.TempDir(), "offer.json")
	encoded, _ := json.Marshal(offer)
	if err := os.WriteFile(offerPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	call := func(args ...string) (int, []byte, string) {
		t.Helper()
		var out, stderr bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(""), &out, &stderr, Dependencies{Now: func() time.Time { return now }})
		return code, out.Bytes(), stderr.String()
	}
	if code, _, _ := call("pair", "prepare", "work", "--offer", offerPath); code != 2 {
		t.Fatalf("missing trust exit %d", code)
	}
	if code, _, _ := call("pair", "prepare", "work", "--offer", offerPath, "--trust-offer", strings.Repeat("0", 64)); code != 1 {
		t.Fatalf("mismatched trust exit %d", code)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("untrusted input mutated root")
	}
	code, out, stderr := call("pair", "prepare", "work", "--offer", offerPath, "--trust-offer", pairing.OfferDigest(offer))
	if code != 0 {
		t.Fatalf("prepare: %d %s", code, stderr)
	}
	var intent pairing.EnrollmentIntent
	if err := json.Unmarshal(out, &intent); err != nil {
		t.Fatal(err)
	}
	code, retry, stderr := call("pair", "prepare", "work", "--offer", offerPath, "--trust-offer", pairing.OfferDigest(offer))
	if code != 0 || !bytes.Equal(out, retry) {
		t.Fatalf("retry: %d %s", code, stderr)
	}
	fingerprint, _ := sshkey.Fingerprint(intent.PublicKey)
	selected, err := target.NewPaired(installed, target.DirectSSH{Host: offer.Connection.Host, Port: offer.Connection.Port, User: offer.Connection.User, HostPublicKey: offer.Connection.HostPublicKey, ClientPublicKeyHash: fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	receipt := pairing.EnrollmentReceipt{SchemaVersion: 1, PairID: intent.PairID, OperationID: intent.OperationID, IntentSHA: pairing.IntentDigest(intent), Platform: "windows", ScopeSHA: strings.Repeat("1", 64), Target: selected, PublicKey: intent.PublicKey}
	receiptPath := filepath.Join(t.TempDir(), "receipt.json")
	encoded, _ = json.Marshal(receipt)
	if err := os.WriteFile(receiptPath, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = call("pair", "complete", "work", "--receipt", receiptPath, "--trust-receipt", pairing.ReceiptDigest(receipt))
	if code != 0 {
		t.Fatalf("complete: %d %s", code, stderr)
	}
	code, out, stderr = call("pair", "status", "work", "--json")
	var view pairing.PairView
	if err := json.Unmarshal(out, &view); err != nil {
		t.Fatal(err)
	}
	if code != 0 || view.Access != "enrolled" || view.Readiness != "unchecked" {
		t.Fatalf("status: %d %+v %s", code, view, stderr)
	}
	for _, args := range [][]string{{"pair", "offer"}, {"pair", "enroll"}, {"pair", "revoke", "work"}, {"setup", "ssh"}} {
		if code, _, stderr := call(args...); code != 1 || !strings.Contains(stderr, "unsupported") {
			t.Fatalf("unsupported command %v: %d %s", args, code, stderr)
		}
	}
}
