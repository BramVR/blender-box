package sshkey

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/privatefile"
)

// Public-only RFC 8032 test vector; never an operator credential.
const testPublic = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea"
const testFingerprint = "6db5e9b8a1bace1cdd9a7c6adb9e9396acc5073465d9fe8e3a0ef6d9c60d6d4f"

func TestCanonicalPublicKeyAndFrozenFingerprint(t *testing.T) {
	if actual, err := CanonicalPublicKey(testPublic); err != nil || actual != testPublic {
		t.Fatalf("canonical public key: %q, %v", actual, err)
	}
	if actual, err := Fingerprint(testPublic); err != nil || actual != testFingerprint {
		t.Fatalf("persisted fingerprint changed: %q, %v", actual, err)
	}
	wire, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(testPublic, keyType+" "))
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(offset int, value byte) string {
		copyWire := bytes.Clone(wire)
		copyWire[offset] = value
		return keyType + " " + base64.StdEncoding.EncodeToString(copyWire)
	}
	for _, invalid := range []string{
		"", testPublic + "\n", testPublic + " comment", " " + testPublic,
		strings.Replace(testPublic, " ", "\t", 1), strings.Replace(testPublic, " ", "  ", 1),
		"restrict " + testPublic, testPublic + "\n" + testPublic,
		strings.Replace(testPublic, keyType, "ssh-rsa", 1),
		mutate(3, 10), mutate(4, 'x'), mutate(18, 31),
		keyType + " " + base64.StdEncoding.EncodeToString(append(bytes.Clone(wire), 0)),
		keyType + " " + base64.StdEncoding.EncodeToString(wire[:len(wire)-1]),
		testPublic[:len(testPublic)-1] + "!",
	} {
		if _, err := CanonicalPublicKey(invalid); err == nil {
			t.Errorf("accepted invalid public key %q", invalid)
		}
		if _, err := Fingerprint(invalid); err == nil {
			t.Errorf("fingerprinted invalid public key %q", invalid)
		}
	}
}

func requireKeygen(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("credential storage requires POSIX ownership checks")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen unavailable")
	}
}

func TestGenerateReadAndFingerprintMismatch(t *testing.T) {
	requireKeygen(t)
	temporary := t.TempDir()
	t.Setenv("TMPDIR", temporary)
	root := filepath.Join(t.TempDir(), "private")
	publicKey, fingerprint, err := Generate(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	if actual, err := Fingerprint(publicKey); err != nil || actual != fingerprint {
		t.Fatal("generated public key fingerprint mismatch")
	}
	key, err := Read(context.Background(), root, fingerprint)
	if err != nil || !bytes.HasPrefix(key, []byte("-----BEGIN OPENSSH PRIVATE KEY-----")) {
		t.Fatalf("generated credential unreadable: %v", err)
	}
	relative, err := credentialPath(fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, filepath.Join(root, "credentials"), filepath.Dir(filepath.Join(root, relative)), filepath.Join(root, relative)} {
		info, err := os.Lstat(path)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("credential path lacks private permissions: %v", err)
		}
	}
	other, err := credentialPath(testFingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if err := privatefile.Publish(root, other, key, false); err != nil {
		t.Fatal(err)
	}
	if secret, err := Read(context.Background(), root, testFingerprint); err == nil || secret != nil {
		t.Fatal("mismatched credential returned")
	}
	entries, err := os.ReadDir(temporary)
	if err != nil || len(entries) != 0 {
		t.Fatal("disposable key files survived operation")
	}
}

func TestReadRejectsUnsafeStorage(t *testing.T) {
	requireKeygen(t)
	root := filepath.Join(t.TempDir(), "private")
	_, fingerprint, err := Generate(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	relative, _ := credentialPath(fingerprint)
	path := filepath.Join(root, relative)
	for _, unsafePath := range []string{root, filepath.Join(root, "credentials"), filepath.Dir(path), path} {
		t.Run(filepath.Base(unsafePath), func(t *testing.T) {
			info, err := os.Stat(unsafePath)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(unsafePath, info.Mode().Perm()|0o044); err != nil {
				t.Fatal(err)
			}
			defer os.Chmod(unsafePath, info.Mode().Perm())
			if secret, err := Read(context.Background(), root, fingerprint); err == nil || secret != nil {
				t.Fatal("publicly readable storage accepted")
			}
		})
	}
	for _, invalid := range []string{"", "../key", strings.ToUpper(fingerprint), fingerprint + "00", strings.Repeat("z", 64)} {
		if secret, err := Read(context.Background(), root, invalid); err == nil || secret != nil {
			t.Fatal("invalid credential path accepted")
		}
	}
	if err := os.Rename(path, path+".original"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".original", path); err != nil {
		t.Fatal(err)
	}
	if secret, err := Read(context.Background(), root, fingerprint); err == nil || secret != nil {
		t.Fatal("symlink credential accepted")
	}
	linkRoot := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, linkRoot); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Generate(context.Background(), linkRoot); err == nil {
		t.Fatal("symlink root accepted")
	}
}

func TestReadRejectsOversizedOrMalformedCredentials(t *testing.T) {
	requireKeygen(t)
	for _, contents := range [][]byte{bytes.Repeat([]byte("x"), maxKeyBytes+1), []byte("secret-malformed-material")} {
		root := filepath.Join(t.TempDir(), "private")
		relative, _ := credentialPath(testFingerprint)
		if err := privatefile.Publish(root, relative, contents, false); err != nil {
			t.Fatal(err)
		}
		key, err := Read(context.Background(), root, testFingerprint)
		if err == nil || key != nil {
			t.Fatal("invalid stored credential returned")
		}
		if strings.Contains(err.Error(), "secret-malformed-material") {
			t.Fatal("error leaked private material")
		}
	}
}

func TestCanceledOperationsDoNotCreateStorage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unsupported platform")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	root := filepath.Join(t.TempDir(), "missing")
	if _, _, err := Generate(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatalf("generation cancellation lost: %v", err)
	}
	if _, err := Read(ctx, root, testFingerprint); !errors.Is(err, context.Canceled) {
		t.Fatalf("read cancellation lost: %v", err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("canceled operation created storage")
	}
	if _, err := runKeygen(ctx, "-h"); !errors.Is(err, context.Canceled) {
		t.Fatalf("subprocess cancellation lost: %v", err)
	}
}

func TestWindowsCredentialsFailBeforeIO(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows-specific refusal")
	}
	root := filepath.Join(t.TempDir(), "missing")
	if _, _, err := Generate(context.Background(), root); err == nil || !strings.Contains(err.Error(), "unsupported on Windows") {
		t.Fatalf("generation unsupported error: %v", err)
	}
	if _, err := Read(context.Background(), root, testFingerprint); err == nil || !strings.Contains(err.Error(), "unsupported on Windows") {
		t.Fatalf("read unsupported error: %v", err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatal("unsupported operation created storage")
	}
}

func TestKeygenOutputBoundAndRedaction(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX test executable")
	}
	directory := t.TempDir()
	t.Setenv("PATH", directory)
	path := filepath.Join(directory, "ssh-keygen")
	for _, fixture := range []struct{ script, want string }{
		{"printf 'private-test-secret' >&2; exit 1", "ssh-keygen failed"},
		{"i=0; while [ $i -lt 4096 ]; do printf 'abcdefgh'; i=$((i+1)); done", "output exceeded"},
		{"i=0; while [ $i -lt 4096 ]; do printf 'abcdefgh' >&2; i=$((i+1)); done", "output exceeded"},
	} {
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"+fixture.script+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		output, err := runKeygen(context.Background())
		if err == nil || output != nil || !strings.Contains(err.Error(), fixture.want) || strings.Contains(err.Error(), "private-test-secret") {
			t.Fatalf("unbounded or unredacted subprocess result: %v", err)
		}
	}
}
