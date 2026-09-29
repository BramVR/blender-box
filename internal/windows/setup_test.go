package windows

import (
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
	result, err := Setup(adapterTarget(), path, false)
	hash := sha256.Sum256(data)
	if err != nil || result.Status != "plan" || result.Applied || result.HostSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	_, err = Setup(adapterTarget(), path, true)
	if err == nil || !strings.Contains(err.Error(), "legacy-setup-unowned") {
		t.Fatalf("legacy apply error = %v", err)
	}
}
func TestSetupRejectsEmptyHostBinary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Setup(adapterTarget(), path, true); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("Setup() error = %v", err)
	}
}

func TestSetupRequiresWindowsTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Setup(target.Target{}, path, true); err == nil || !strings.Contains(err.Error(), "platform") {
		t.Fatalf("Setup() error = %v", err)
	}
}
