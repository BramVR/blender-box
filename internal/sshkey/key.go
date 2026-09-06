// Package sshkey stores paired Ed25519 credentials without exposing private keys in errors.
package sshkey

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/privatefile"
)

const (
	keyType       = "ssh-ed25519"
	maxKeyBytes   = 16 << 10
	keygenTimeout = 15 * time.Second
)

// CanonicalPublicKey accepts exactly an Ed25519 type and canonical SSH wire encoding.
// Comments, authorized_keys options, whitespace variants, and additional keys are rejected.
func CanonicalPublicKey(value string) (string, error) {
	if _, err := publicWire(value); err != nil {
		return "", err
	}
	return value, nil
}

func publicWire(value string) ([]byte, error) {
	const wireLength = 4 + len(keyType) + 4 + ed25519.PublicKeySize
	if len(value) != len(keyType)+1+base64.StdEncoding.EncodedLen(wireLength) || !strings.HasPrefix(value, keyType+" ") {
		return nil, errors.New("expected canonical ssh-ed25519 public key")
	}
	encoded := value[len(keyType)+1:]
	wire, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(wire) != wireLength || base64.StdEncoding.EncodeToString(wire) != encoded {
		return nil, errors.New("invalid Ed25519 SSH encoding")
	}
	if binary.BigEndian.Uint32(wire[:4]) != uint32(len(keyType)) || string(wire[4:4+len(keyType)]) != keyType || binary.BigEndian.Uint32(wire[4+len(keyType):8+len(keyType)]) != ed25519.PublicKeySize {
		return nil, errors.New("invalid Ed25519 SSH wire fields")
	}
	return wire, nil
}

// Fingerprint is the lowercase hexadecimal SHA-256 digest of the SSH wire bytes.
// This persisted identity intentionally differs from OpenSSH's display fingerprint.
func Fingerprint(publicKey string) (string, error) {
	wire, err := publicWire(publicKey)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

func credentialPath(fingerprint string) (string, error) {
	decoded, err := hex.DecodeString(fingerprint)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != fingerprint {
		return "", errors.New("invalid SSH credential fingerprint")
	}
	return filepath.Join("credentials", fingerprint, "id_ed25519"), nil
}

func supported() error {
	if runtime.GOOS == "windows" {
		return errors.New("SSH credential generation and reading are unsupported on Windows until private ACL ownership is enforced")
	}
	return nil
}

// Generate publishes a fresh key at credentials/<fingerprint>/id_ed25519 below root.
// Only its public key and fingerprint leave this function.
func Generate(ctx context.Context, root string) (publicKey string, fingerprint string, err error) {
	if err := supported(); err != nil {
		return "", "", err
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if _, err := privatefile.Directory(root, "", true); err != nil {
		return "", "", err
	}
	temporary, err := os.MkdirTemp("", "blender-box-sshkey-")
	if err != nil {
		return "", "", err
	}
	defer os.RemoveAll(temporary)
	keyPath := filepath.Join(temporary, "id_ed25519")
	if _, err := runKeygen(ctx, "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", keyPath); err != nil {
		return "", "", err
	}
	privateKey, err := privatefile.Read(temporary, "id_ed25519", maxKeyBytes)
	if err != nil {
		return "", "", err
	}
	publicKey, err = derivePublic(ctx, keyPath)
	if err != nil {
		return "", "", err
	}
	fingerprint, err = Fingerprint(publicKey)
	if err != nil {
		return "", "", err
	}
	relative, err := credentialPath(fingerprint)
	if err != nil {
		return "", "", err
	}
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if err := privatefile.Publish(root, relative, privateKey, false); err != nil {
		return "", "", err
	}
	return publicKey, fingerprint, nil
}

// Read checks private ownership and derives the public key before returning a credential.
func Read(ctx context.Context, root, fingerprint string) ([]byte, error) {
	if err := supported(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	relative, err := credentialPath(fingerprint)
	if err != nil {
		return nil, err
	}
	privateKey, err := privatefile.Read(root, relative, maxKeyBytes)
	if err != nil {
		return nil, err
	}
	temporary, err := os.MkdirTemp("", "blender-box-sshkey-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(temporary)
	if err := privatefile.Publish(temporary, "id_ed25519", privateKey, false); err != nil {
		return nil, err
	}
	publicKey, err := derivePublic(ctx, filepath.Join(temporary, "id_ed25519"))
	if err != nil {
		return nil, err
	}
	actual, err := Fingerprint(publicKey)
	if err != nil {
		return nil, err
	}
	if actual != fingerprint {
		return nil, errors.New("stored SSH credential does not match its fingerprint")
	}
	return privateKey, nil
}

func derivePublic(ctx context.Context, path string) (string, error) {
	output, err := runKeygen(ctx, "-y", "-P", "", "-f", path)
	if err != nil {
		return "", err
	}
	return CanonicalPublicKey(strings.TrimSuffix(string(output), "\n"))
}

func runKeygen(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, keygenTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, "ssh-keygen", args...)
	command.WaitDelay = time.Second
	stdout := &boundedOutput{}
	stderr := &boundedOutput{}
	command.Stdout = stdout
	command.Stderr = stderr
	err := command.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if stdout.exceeded || stderr.exceeded {
		return nil, errors.New("ssh-keygen output exceeded its limit")
	}
	if err != nil {
		// Subprocess diagnostics can contain key material. Never include captured output.
		return nil, fmt.Errorf("ssh-keygen failed: %w", err)
	}
	return stdout.buffer.Bytes(), nil
}

type boundedOutput struct {
	buffer   bytes.Buffer
	exceeded bool
}

func (output *boundedOutput) Write(data []byte) (int, error) {
	if len(data) > maxKeyBytes-output.buffer.Len() {
		output.exceeded = true
		return 0, errors.New("ssh-keygen output limit")
	}
	return output.buffer.Write(data)
}
