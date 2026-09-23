package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"github.com/BramVR/blender-box/internal/target"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacySetupPreviewAndUnownedApplyRefusal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "host.exe")
	data := []byte("host")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	fake := &scriptedSSH{}
	result, err := Setup(context.Background(), fake, adapterTarget(), path, false)
	hash := sha256.Sum256(data)
	if err != nil || result.Status != "plan" || result.Applied || result.HostSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	_, err = Setup(context.Background(), fake, adapterTarget(), path, true)
	if err == nil || !strings.Contains(err.Error(), "legacy-setup-unowned") || len(fake.arguments) != 0 || len(fake.uploads) != 0 {
		t.Fatalf("legacy apply reached transport: %v", err)
	}
}
func TestSetupRejectsEmptyHostBinaryBeforeSSH(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &scriptedSSH{}
	if _, err := Setup(context.Background(), fake, adapterTarget(), path, true); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("Setup() error = %v", err)
	}
	if len(fake.arguments) != 0 || len(fake.uploads) != 0 {
		t.Fatal("empty host binary reached SSH")
	}
}

func TestSetupValidatesTargetBeforeAnySSHCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}
	selected := target.Target{}
	fake := &scriptedSSH{}
	_, err := Setup(context.Background(), fake, selected, path, true)
	if err == nil || !strings.Contains(err.Error(), "platform") {
		t.Fatalf("Setup() error = %v", err)
	}
	if len(fake.arguments) != 0 || len(fake.uploads) != 0 {
		t.Fatal("invalid target reached SSH")
	}
}
