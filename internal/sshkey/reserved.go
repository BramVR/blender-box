package sshkey

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"os"

	"github.com/BramVR/blender-box/internal/privatefile"
)

// ReservedKey derives the same credential from a retained preparation seed.
// Private material stays inside this package.
type ReservedKey struct {
	publicKey string
	private   []byte
}

func (key ReservedKey) PublicKey() string { return key.publicKey }

// Reserved reads the winning seed durably before deriving any global credential.
// The caller must durably reserve ownership of seedPath before allowing creation.
func Reserved(ctx context.Context, root, seedPath string, create bool) (ReservedKey, error) {
	return reserved(ctx, root, seedPath, create, privatefile.Publish)
}

func reserved(ctx context.Context, root, seedPath string, create bool, publish func(string, string, []byte, bool) error) (ReservedKey, error) {
	if err := supported(); err != nil {
		return ReservedKey{}, err
	}
	if err := ctx.Err(); err != nil {
		return ReservedKey{}, err
	}
	seed, err := privatefile.ReadDurable(root, seedPath, ed25519.SeedSize)
	if errors.Is(err, os.ErrNotExist) && create {
		candidate := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(candidate); err != nil {
			return ReservedKey{}, err
		}
		publishErr := publish(root, seedPath, candidate, false)
		seed, err = privatefile.ReadDurable(root, seedPath, ed25519.SeedSize)
		if err != nil && publishErr != nil {
			return ReservedKey{}, publishErr
		}
	}
	if err != nil {
		return ReservedKey{}, err
	}
	if len(seed) != ed25519.SeedSize {
		return ReservedKey{}, errors.New("invalid retained SSH preparation seed")
	}
	return keyFromSeed(seed), nil
}

func sshString(value []byte) []byte {
	result := make([]byte, 4, 4+len(value))
	binary.BigEndian.PutUint32(result, uint32(len(value)))
	return append(result, value...)
}

func keyFromSeed(seed []byte) ReservedKey {
	private := ed25519.NewKeyFromSeed(seed)
	public := private[ed25519.SeedSize:]
	wire := append(sshString([]byte(keyType)), sshString(public)...)
	// Unencrypted openssh-key-v1 uses duplicate checkints and 8-byte padding.
	// Deriving the checkint from the random seed keeps retry bytes identical.
	block := append([]byte{}, seed[:4]...)
	block = append(block, seed[:4]...)
	block = append(block, sshString([]byte(keyType))...)
	block = append(block, sshString(public)...)
	block = append(block, sshString(private)...)
	block = append(block, sshString(nil)...)
	for padding := byte(1); len(block)%8 != 0; padding++ {
		block = append(block, padding)
	}
	encoded := []byte("openssh-key-v1\x00")
	encoded = append(encoded, sshString([]byte("none"))...)
	encoded = append(encoded, sshString([]byte("none"))...)
	encoded = append(encoded, sshString(nil)...)
	encoded = append(encoded, 0, 0, 0, 1)
	encoded = append(encoded, sshString(wire)...)
	encoded = append(encoded, sshString(block)...)
	return ReservedKey{publicKey: keyType + " " + base64.StdEncoding.EncodeToString(wire), private: pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: encoded})}
}

// Verify checks durable credential bytes without creating a temporary private copy.
func (key ReservedKey) Verify(root string) error {
	if len(key.private) == 0 {
		return errors.New("missing reserved SSH key")
	}
	fingerprint, err := Fingerprint(key.PublicKey())
	if err != nil {
		return err
	}
	relative, _ := credentialPath(fingerprint)
	actual, err := privatefile.ReadDurable(root, relative, maxKeyBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(actual, key.private) {
		return errors.New("stored SSH credential conflicts with retained preparation")
	}
	return nil
}

// Publish reconciles the immutable global credential with the retained seed.
// The caller must first retain a durable intent naming this public key.
func (key ReservedKey) Publish(root string) error {
	return key.publish(root, privatefile.Publish)
}

func (key ReservedKey) publish(root string, publish func(string, string, []byte, bool) error) error {
	if len(key.private) == 0 {
		return errors.New("missing reserved SSH key")
	}
	fingerprint, err := Fingerprint(key.PublicKey())
	if err != nil {
		return err
	}
	relative, _ := credentialPath(fingerprint)
	publishErr := publish(root, relative, key.private, false)
	if err := key.Verify(root); err != nil {
		if publishErr != nil {
			return publishErr
		}
		return err
	}
	return nil
}
