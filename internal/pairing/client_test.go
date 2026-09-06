package pairing

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windowstarget"
)

func fixture(t *testing.T) (Client, HostOffer) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("paired credentials require POSIX client")
	}
	installed, err := target.NewWindows("installed", windowstarget.Config{SSHUser: "operator", InteractiveUser: "operator", WorkRoot: `C:\Box`, TaskName: "box", BlenderExecutable: `C:\Blender\blender.exe`, HostExecutable: `C:\Box\bin\host.exe`, SessionBrokerExecutable: `C:\Box\bin\daemon.exe`})
	if err != nil {
		t.Fatal(err)
	}
	hostKey, _, err := sshkey.Generate(context.Background(), filepath.Join(t.TempDir(), "host-key"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	return Client{Root: filepath.Join(t.TempDir(), "config"), Now: func() time.Time { return now }}, HostOffer{1, "bootstrap-test", now.Add(time.Hour), "windows", ServerSSH{"host.invalid", 2222, "operator", hostKey}, installed, "installation-test", "root-test", "account-test"}
}
func trustedOffer(t *testing.T, client Client, offer HostOffer) TrustedOffer {
	t.Helper()
	data, _ := json.Marshal(offer)
	trusted, err := TrustOffer(data, OfferDigest(offer), client.now())
	if err != nil {
		t.Fatal(err)
	}
	return trusted
}
func receiptFor(t *testing.T, offer HostOffer, intent EnrollmentIntent) EnrollmentReceipt {
	t.Helper()
	fingerprint, _ := sshkey.Fingerprint(intent.PublicKey)
	selected, err := target.NewPaired(offer.Installed, direct(offer.Connection, fingerprint))
	if err != nil {
		t.Fatal(err)
	}
	return EnrollmentReceipt{1, intent.PairID, intent.OperationID, IntentDigest(intent), offer.Platform, strings.Repeat("1", 64), selected, intent.PublicKey}
}
func trustedReceipt(t *testing.T, receipt EnrollmentReceipt) TrustedReceipt {
	t.Helper()
	data, _ := json.Marshal(receipt)
	trusted, err := TrustReceipt(data, ReceiptDigest(receipt))
	if err != nil {
		t.Fatal(err)
	}
	return trusted
}
func TestTrustRefusesMissingSubstitutedAndExpiredOfferBeforeWrites(t *testing.T) {
	client, offer := fixture(t)
	data, _ := json.Marshal(offer)
	for _, hash := range []string{"", strings.Repeat("0", 64)} {
		if _, err := TrustOffer(data, hash, client.now()); err == nil {
			t.Fatal("untrusted offer accepted")
		}
	}
	if _, err := TrustOffer(data, OfferDigest(offer), offer.Expires); err == nil {
		t.Fatal("expired offer accepted")
	}
	if _, err := os.Stat(client.Root); !os.IsNotExist(err) {
		t.Fatal("untrusted offer mutated storage")
	}
	if _, err := client.Prepare(context.Background(), "work", TrustedOffer{}); err == nil {
		t.Fatal("zero trust wrapper accepted")
	}
}
func TestPrepareRetryCompleteLostReplyAndReadiness(t *testing.T) {
	client, offer := fixture(t)
	ctx := context.Background()
	trusted := trustedOffer(t, client, offer)
	intent, err := client.Prepare(ctx, "work", trusted)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := client.Prepare(ctx, "work", trusted)
	if err != nil || retry != intent {
		t.Fatalf("retry changed request: %v", err)
	}
	view, err := client.Inspect(ctx, "work")
	if err != nil || view.Access != "prepared-unconfirmed" || view.Readiness != "unchecked" {
		t.Fatalf("view=%+v err=%v", view, err)
	}
	changed := offer
	changed.Connection.Port++
	if _, err := client.Prepare(ctx, "work", trustedOffer(t, client, changed)); err == nil {
		t.Fatal("changed intent accepted")
	}
	receipt := receiptFor(t, offer, intent)
	bad := receipt
	bad.OperationID = "replacement"
	if _, err := client.Complete(ctx, "work", trustedReceipt(t, bad)); err == nil {
		t.Fatal("substituted receipt accepted")
	}
	data, _ := json.Marshal(receipt)
	if err := privatefile.Publish(client.Root, recordPath("work", "receipt"), data, false); err != nil {
		t.Fatal(err)
	}
	client.Now = func() time.Time { return offer.Expires.Add(time.Hour) }
	selected, err := client.Complete(ctx, "work", trustedReceipt(t, receipt))
	if err != nil {
		t.Fatal(err)
	}
	again, err := client.Complete(ctx, "work", trustedReceipt(t, receipt))
	if err != nil || again.Fingerprint() != selected.Fingerprint() {
		t.Fatalf("lost reply retry: %v", err)
	}
	view, err = client.Inspect(ctx, "work")
	if err != nil || view.Access != "enrolled" || view.Readiness != "unchecked" {
		t.Fatalf("view=%+v err=%v", view, err)
	}
	if _, err := privatefile.Read(client.Root, recordPath("work", "intent"), MaxDocumentSize); err != nil {
		t.Fatal("recovery intent removed")
	}
}
func TestReceiptConflictAndMissingKeyPreserveRecovery(t *testing.T) {
	client, offer := fixture(t)
	ctx := context.Background()
	intent, err := client.Prepare(ctx, "work", trustedOffer(t, client, offer))
	if err != nil {
		t.Fatal(err)
	}
	receipt := receiptFor(t, offer, intent)
	if _, err := (target.Store{Root: client.Root}).Save("work", offer.Installed, false); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Complete(ctx, "work", trustedReceipt(t, receipt)); err == nil {
		t.Fatal("replacement target overwritten")
	}
	saved, err := (target.Store{Root: client.Root}).Show("work")
	if err != nil || saved.Fingerprint() != offer.Installed.Fingerprint() {
		t.Fatal("replacement target changed")
	}
	if _, err := privatefile.Read(client.Root, recordPath("work", "receipt"), MaxDocumentSize); err != nil {
		t.Fatal("trusted receipt lost")
	}
	receipt.PairID = "different"
	data, _ := json.Marshal(receipt)
	if err := privatefile.Publish(client.Root, recordPath("work", "receipt"), data, true); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Inspect(ctx, "work"); err == nil {
		t.Fatal("inspect accepted unrelated receipt")
	}
	fingerprint, _ := sshkey.Fingerprint(intent.PublicKey)
	if err := os.Remove(filepath.Join(client.Root, "credentials", fingerprint, "id_ed25519")); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Complete(ctx, "work", trustedReceipt(t, receiptFor(t, offer, intent))); err == nil {
		t.Fatal("missing credential accepted")
	}
}
