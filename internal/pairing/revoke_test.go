package pairing

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sshtransport "github.com/BramVR/blender-box/internal/ssh"
	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/target"
)

type fakeRemote struct {
	revokeErr error
	probeErrs []error
	revokes   []RevokeRequest
	probes    int
	contacted []string
}

func (remote *fakeRemote) RevokePairing(_ context.Context, paired target.Target, request RevokeRequest) (RevokeResult, error) {
	remote.revokes = append(remote.revokes, request)
	remote.contacted = append(remote.contacted, paired.Fingerprint())
	if remote.revokeErr != nil {
		return RevokeResult{}, remote.revokeErr
	}
	return RevokeResult{1, request.PairID, "revoked", strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)}, nil
}

func (remote *fakeRemote) Probe(_ context.Context, paired target.Target) error {
	remote.contacted = append(remote.contacted, paired.Fingerprint())
	err := remote.probeErrs[remote.probes]
	remote.probes++
	return err
}

func sshFailure(class sshtransport.FailureClass) error {
	return errors.Join(errors.New("host pair-revoke"), &sshtransport.Failure{Class: class, Detail: "fake OpenSSH stderr"})
}

func enrolled(t *testing.T) (Client, EnrollmentReceipt) {
	t.Helper()
	client, offer := fixture(t)
	ctx := context.Background()
	intent, err := client.Prepare(ctx, "work", trustedOffer(t, client, offer))
	if err != nil {
		t.Fatal(err)
	}
	receipt := receiptFor(t, offer, intent)
	if _, err := client.Complete(ctx, "work", trustedReceipt(t, receipt)); err != nil {
		t.Fatal(err)
	}
	return client, receipt
}

func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		if entry.IsDir() {
			files[relative+"/"] = ""
			return nil
		}
		data, err := os.ReadFile(path)
		files[relative] = string(data)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func assertForgotten(t *testing.T, client Client, receipt EnrollmentReceipt) {
	t.Helper()
	fingerprint, _ := sshkey.Fingerprint(receipt.PublicKey)
	for _, path := range []string{filepath.Join("pairings", "work"), filepath.Join("credentials", fingerprint), filepath.Join("targets", "work.json")} {
		if _, err := os.Lstat(filepath.Join(client.Root, path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s remains after forget: %v", path, err)
		}
	}
	view, err := client.Inspect(context.Background(), "work")
	if err != nil || view.Access != "none" {
		t.Fatalf("status after forget = %+v, %v", view, err)
	}
}

func TestRevokeWithUnavailableHostKeepsEveryLocalFile(t *testing.T) {
	for _, class := range []sshtransport.FailureClass{sshtransport.HostUnreachable, sshtransport.TailscaleUnreachable, sshtransport.HostKeyMismatch} {
		t.Run(string(class), func(t *testing.T) {
			client, receipt := enrolled(t)
			before := snapshot(t, client.Root)
			remote := &fakeRemote{revokeErr: sshFailure(class)}
			outcome, err := client.Revoke(context.Background(), "work", remote)
			if err == nil || outcome.State != "unconfirmed" || outcome.Failure != string(class) || outcome.PairID != receipt.PairID {
				t.Fatalf("outcome = %+v, %v", outcome, err)
			}
			if !strings.Contains(outcome.Next, `blender-box pair revoke --state-root C:\Box --pair `+receipt.PairID+" --apply") {
				t.Fatalf("next step omits the host command: %q", outcome.Next)
			}
			if remote.probes != 0 {
				t.Fatal("probe ran without a host result")
			}
			if after := snapshot(t, client.Root); !reflect.DeepEqual(before, after) {
				t.Fatalf("local state changed:\nbefore %v\nafter  %v", before, after)
			}
		})
	}
}

func TestRevokeRetryAfterLostProbeRepeatsOnlyTheProbe(t *testing.T) {
	client, receipt := enrolled(t)
	ctx := context.Background()
	remote := &fakeRemote{probeErrs: []error{sshFailure(sshtransport.HostUnreachable), sshFailure(sshtransport.AuthRejected)}}
	outcome, err := client.Revoke(ctx, "work", remote)
	if err == nil || outcome.State != "host-revoked-unconfirmed" || outcome.Host != "revoked" || outcome.Failure != "host-unreachable" {
		t.Fatalf("first outcome = %+v, %v", outcome, err)
	}
	fingerprint, _ := sshkey.Fingerprint(receipt.PublicKey)
	if want := []RevokeRequest{{1, receipt.PairID, fingerprint}}; !reflect.DeepEqual(remote.revokes, want) {
		t.Fatalf("revoke requests = %+v, want %+v", remote.revokes, want)
	}
	if _, err := sshkey.Reserved(ctx, client.Root, seedPath("work"), false); err != nil {
		t.Fatalf("seed removed before rejection proof: %v", err)
	}
	view, err := client.Inspect(ctx, "work")
	if err != nil || view.Access != "revocation-pending" || view.PairID != receipt.PairID {
		t.Fatalf("status = %+v, %v", view, err)
	}
	outcome, err = client.Revoke(ctx, "work", remote)
	if err != nil || outcome.State != "revoked" || outcome.Host != "revoked" || outcome.Next != "" {
		t.Fatalf("retry outcome = %+v, %v", outcome, err)
	}
	if len(remote.revokes) != 1 || remote.probes != 2 {
		t.Fatalf("retry revokes=%d probes=%d, want 1 and 2", len(remote.revokes), remote.probes)
	}
	for _, contacted := range remote.contacted {
		if contacted != receipt.Target.Fingerprint() {
			t.Fatal("remote contacted a target other than the receipt's paired target")
		}
	}
	assertForgotten(t, client, receipt)
}

func TestRevokeKeepsStateWhenFreshConnectionStillAuthenticates(t *testing.T) {
	client, receipt := enrolled(t)
	remote := &fakeRemote{probeErrs: []error{nil}}
	outcome, err := client.Revoke(context.Background(), "work", remote)
	if err == nil || !strings.Contains(err.Error(), "still authenticates") || outcome.State != "host-revoked-unconfirmed" {
		t.Fatalf("outcome = %+v, %v", outcome, err)
	}
	if _, err := (target.Store{Root: client.Root}).Show("work"); err != nil {
		t.Fatalf("target removed: %v", err)
	}
	if _, err := client.readReceipt(mustRead(t, client)); err != nil {
		t.Fatalf("receipt removed: %v", err)
	}
	if view, _ := client.Inspect(context.Background(), "work"); view.Access != "revocation-pending" || view.PairID != receipt.PairID {
		t.Fatalf("status = %+v", view)
	}
}

func TestRevokeProbeHostKeyMismatchIsNotRejection(t *testing.T) {
	client, _ := enrolled(t)
	remote := &fakeRemote{probeErrs: []error{sshFailure(sshtransport.HostKeyMismatch)}}
	outcome, err := client.Revoke(context.Background(), "work", remote)
	if err == nil || outcome.State != "host-revoked-unconfirmed" || outcome.Failure != "host-key-mismatch" {
		t.Fatalf("outcome = %+v, %v", outcome, err)
	}
	if _, err := client.readReceipt(mustRead(t, client)); err != nil {
		t.Fatalf("receipt removed: %v", err)
	}
}

func TestRevokeAlreadyRejectedKeyConvergesWithoutHostResult(t *testing.T) {
	client, receipt := enrolled(t)
	remote := &fakeRemote{revokeErr: sshFailure(sshtransport.AuthRejected), probeErrs: []error{sshFailure(sshtransport.AuthRejected)}}
	outcome, err := client.Revoke(context.Background(), "work", remote)
	if err != nil || outcome.State != "key-rejected" || outcome.Host != "already-rejected" {
		t.Fatalf("outcome = %+v, %v", outcome, err)
	}
	if want := `blender-box pair status --state-root C:\Box --pair ` + receipt.PairID; !strings.Contains(outcome.Next, want) {
		t.Fatalf("next = %q, want host status command %q", outcome.Next, want)
	}
	assertForgotten(t, client, receipt)
}

func TestForgetRefusesAcceptedAccessUnlessKeptExplicitly(t *testing.T) {
	client, receipt := enrolled(t)
	ctx := context.Background()
	before := snapshot(t, client.Root)
	_, err := client.Forget(ctx, "work", false)
	if err == nil || !strings.Contains(err.Error(), `blender-box pair revoke --state-root C:\Box --pair `+receipt.PairID+" --apply") {
		t.Fatalf("forget refusal = %v", err)
	}
	if after := snapshot(t, client.Root); !reflect.DeepEqual(before, after) {
		t.Fatal("refused forget changed local state")
	}
	result, err := client.Forget(ctx, "work", true)
	if err != nil || result.RemoteAccess != "not-revoked" || result.PairID != receipt.PairID {
		t.Fatalf("forget = %+v, %v", result, err)
	}
	assertForgotten(t, client, receipt)
	if _, err := client.Forget(ctx, "work", true); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("second forget = %v", err)
	}
}

func TestForgetAfterHostConfirmedRevocationNeedsNoOverride(t *testing.T) {
	client, receipt := enrolled(t)
	ctx := context.Background()
	if _, err := client.Revoke(ctx, "work", &fakeRemote{probeErrs: []error{sshFailure(sshtransport.HostUnreachable)}}); err == nil {
		t.Fatal("unproven rejection reported success")
	}
	result, err := client.Forget(ctx, "work", false)
	if err != nil || result.RemoteAccess != "revoked" {
		t.Fatalf("forget = %+v, %v", result, err)
	}
	assertForgotten(t, client, receipt)
}

func TestForgetNeverDeletesAReplacementTarget(t *testing.T) {
	client, offer := fixture(t)
	ctx := context.Background()
	intent, err := client.Prepare(ctx, "work", trustedOffer(t, client, offer))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Complete(ctx, "work", trustedReceipt(t, receiptFor(t, offer, intent))); err != nil {
		t.Fatal(err)
	}
	store := target.Store{Root: client.Root}
	if _, err := store.Save("work", offer.Installed, true); err != nil {
		t.Fatal(err)
	}
	remote := &fakeRemote{probeErrs: []error{sshFailure(sshtransport.AuthRejected)}}
	if outcome, err := client.Revoke(ctx, "work", remote); err != nil || outcome.State != "revoked" {
		t.Fatalf("revoke = %+v, %v", outcome, err)
	}
	saved, err := store.Show("work")
	if err != nil || saved.Fingerprint() != offer.Installed.Fingerprint() {
		t.Fatalf("replacement target changed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(client.Root, "pairings", "work")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pairing state remains: %v", err)
	}
}

func TestForgetUnacceptedPairingReportsUnconfirmedHostState(t *testing.T) {
	client, offer := fixture(t)
	intent, err := client.Prepare(context.Background(), "work", trustedOffer(t, client, offer))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.Forget(context.Background(), "work", false)
	if err != nil || result.RemoteAccess != "unconfirmed" || !strings.Contains(result.Next, `blender-box pair status --state-root C:\Box --pair `+intent.PairID) {
		t.Fatalf("forget = %+v, %v", result, err)
	}
	fingerprint, _ := sshkey.Fingerprint(intent.PublicKey)
	if _, err := os.Lstat(filepath.Join(client.Root, "credentials", fingerprint)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("credential remains: %v", err)
	}
}

func mustRead(t *testing.T, client Client) pending {
	t.Helper()
	value, err := client.read("work")
	if err != nil {
		t.Fatal(err)
	}
	return value
}
