package orchestrator

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/target"
)

func TestRecoveryRejectsEveryPairedConnectionChangeBeforeContact(t *testing.T) {
	const public = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
	base := target.DirectSSH{Host: "host.invalid", Port: 2222, User: "operator", HostPublicKey: public, ClientPublicKeyHash: strings.Repeat("1", 64)}
	original, err := target.NewPaired(testTarget(t), base)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*target.DirectSSH){
		"host":       func(d *target.DirectSSH) { d.Host = "replacement.invalid" },
		"port":       func(d *target.DirectSSH) { d.Port++ },
		"user":       func(d *target.DirectSSH) { d.User = "replacement" },
		"host-key":   func(d *target.DirectSSH) { d.HostPublicKey = strings.TrimSuffix(public, "Ea") + "Eb" },
		"client-key": func(d *target.DirectSSH) { d.ClientPublicKeyHash = strings.Repeat("2", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			changed := base
			mutate(&changed)
			replacement, err := target.NewPaired(testTarget(t), changed)
			if err != nil {
				t.Fatal(err)
			}
			claim := originalClaim(t)
			host := &recoveryHost{}
			runner := New(host, filepath.Join(t.TempDir(), "private"))
			if err := runner.journal.record(original, claim); err != nil {
				t.Fatal(err)
			}
			restarted := New(host, runner.journal.root)
			for _, call := range []func() error{func() error { _, err := restarted.Status(context.Background(), replacement, claim.RunID); return err }, func() error { _, err := restarted.Stop(context.Background(), replacement, claim.RunID); return err }} {
				err := call()
				if err == nil || !IsAuthorityError(err) || !strings.Contains(err.Error(), "target does not match original Run") {
					t.Fatalf("changed authority result: %v", err)
				}
			}
			if len(host.operations) != 0 {
				t.Fatalf("changed connection contacted host: %v", host.operations)
			}
		})
	}
}
