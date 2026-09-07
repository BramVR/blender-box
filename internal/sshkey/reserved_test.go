package sshkey

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/BramVR/blender-box/internal/privatefile"
)

func TestReservedOpenSSHInteropAndDurableRetry(t *testing.T) {
	requireKeygen(t)
	root := filepath.Join(t.TempDir(), "private")
	seed := filepath.Join("preparation", "seed")
	linkedError := func(root, path string, data []byte, replace bool) error {
		if err := privatefile.Publish(root, path, data, replace); err != nil {
			return err
		}
		return errors.New("injected directory sync failure after publication")
	}
	key, err := reserved(context.Background(), root, seed, true, linkedError)
	if err != nil {
		t.Fatal(err)
	}
	if err := key.publish(root, linkedError); err != nil {
		t.Fatal(err)
	}
	fingerprint, _ := Fingerprint(key.PublicKey())
	path, _ := credentialPath(fingerprint)
	actual, err := derivePublic(context.Background(), filepath.Join(root, path))
	if err != nil || actual != key.PublicKey() {
		t.Fatalf("OpenSSH interoperability failed: %v", err)
	}
	if _, err := Read(context.Background(), root, fingerprint); err != nil {
		t.Fatal(err)
	}
	again, err := Reserved(context.Background(), root, seed, true)
	if err != nil || again.PublicKey() != key.PublicKey() {
		t.Fatalf("seed winner changed: %v", err)
	}
	if err := again.Publish(root); err != nil {
		t.Fatal(err)
	}
	if err := again.Verify(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, path), []byte("private-test-invalid"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := again.Verify(root); err == nil {
		t.Fatal("conflicting credential accepted")
	}
}

func TestReservedRejectsInvalidSeedWithoutReplacement(t *testing.T) {
	requireKeygen(t)
	for _, seed := range [][]byte{nil, make([]byte, 31), make([]byte, 33)} {
		root := filepath.Join(t.TempDir(), "private")
		if err := privatefile.Publish(root, "preparation/seed", seed, false); err != nil {
			t.Fatal(err)
		}
		if _, err := Reserved(context.Background(), root, "preparation/seed", true); err == nil {
			t.Fatal("invalid seed accepted")
		}
		if _, err := os.Stat(filepath.Join(root, "credentials")); !os.IsNotExist(err) {
			t.Fatal("invalid seed published credentials")
		}
	}
}
