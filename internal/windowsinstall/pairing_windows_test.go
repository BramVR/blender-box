//go:build windows

package windowsinstall

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/pairing"
	"github.com/BramVR/blender-box/internal/strictjson"
)

func setFileSDDL(t *testing.T, path, sddl string) {
	t.Helper()
	_, err := powerShell(context.Background(), `$acl=[Security.AccessControl.FileSecurity]::new();$acl.SetSecurityDescriptorSddlForm($r.sddl);[IO.File]::SetAccessControl($r.path,$acl)`, map[string]string{"path": path, "sddl": sddl})
	if err != nil {
		t.Fatal(err)
	}
}

// liveSecurity returns the file's raw SDDL, its canonical form, and the canonical form of want.
func liveSecurity(t *testing.T, path, want string) (raw, live, wanted string) {
	t.Helper()
	output, err := powerShell(context.Background(), `$acl=Get-Acl -LiteralPath $r.path
[ordered]@{raw=$acl.Sddl;live=(Canonical-Security $acl.Sddl);want=(Canonical-Security $r.sddl)}|ConvertTo-Json -Compress`, map[string]string{"path": path, "sddl": want})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Raw  string `json:"raw"`
		Live string `json:"live"`
		Want string `json:"want"`
	}
	if err := strictjson.Decode(output, &result); err != nil {
		t.Fatal(err)
	}
	return result.Raw, result.Live, result.Want
}

func TestNativeKeysReplaceKeepsTheProtectedAdministratorsDACL(t *testing.T) {
	ctx := context.Background()
	output, err := powerShell(ctx, `[ordered]@{elevated=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)}|ConvertTo-Json -Compress`, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	var token struct {
		Elevated bool `json:"elevated"`
	}
	if err := strictjson.Decode(output, &token); err != nil {
		t.Fatal(err)
	}
	if !token.Elevated {
		t.Skip("setting the protected administrators SDDL needs an elevated test process")
	}
	directory := tempRoot(t)
	path := filepath.Join(directory, "administrators_authorized_keys")
	initial := "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb0dz5pD1+7w1M0LqQxK8xW9bVj7QYpYQ8yG8zzB8Xg operator@one\r\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIN1mB4l0cR9w2yP3vA5qF6tG7hJ8kL9mN0oP1qR2sT3u operator@two\r\n"
	if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	setFileSDDL(t, path, adminKeysSDDL)
	platform := pairingPlatform{keys: nativeKeys{}, adminKeysFile: path}
	file, err := platform.ReadKeys(ctx, path)
	if err != nil || !file.Exists || string(file.Bytes) != initial || file.SHA != string(digest([]byte(initial))) || file.Security == "" {
		t.Fatalf("read: %+v err=%v", file, err)
	}
	appended := initial + "restrict ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPairedKeyBytesPairedKeyBytesPairedKeyBytesPai blender-box-pair:test\r\n"
	if err := platform.ReplaceKeys(ctx, file, []byte(appended)); err != nil {
		t.Fatal(err)
	}
	live, err := os.ReadFile(path)
	if err != nil || string(live) != appended {
		t.Fatalf("live bytes %q err=%v", live, err)
	}
	raw, canonical, want := liveSecurity(t, path, adminKeysSDDL)
	if canonical != want || canonical == "" {
		t.Fatalf("security after replace %q want %q (raw %q)", canonical, want, raw)
	}
	if err := verifyDescriptor(raw, "admin", ""); err != nil {
		t.Fatalf("live descriptor %q: %v", raw, err)
	}
	err = platform.ReplaceKeys(ctx, file, []byte(initial+"stale\r\n"))
	if !errors.Is(err, pairing.ErrKeysChanged) {
		t.Fatalf("stale observation: %v", err)
	}
	if live, _ := os.ReadFile(path); string(live) != appended {
		t.Fatalf("stale replace changed bytes to %q", live)
	}
	setFileSDDL(t, path, `O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;BU)`)
	if _, err := platform.ReadKeys(ctx, path); err == nil || !strings.Contains(err.Error(), "S-1-5-32-545") {
		t.Fatalf("users modify accepted: %v", err)
	}

	inUse := filepath.Join(directory, "in_use_administrators_authorized_keys")
	if err := os.WriteFile(inUse, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	setFileSDDL(t, inUse, realAdminKeysSDDL)
	platform = pairingPlatform{keys: nativeKeys{}, adminKeysFile: inUse}
	file, err = platform.ReadKeys(ctx, inUse)
	if err != nil {
		t.Fatalf("read in-use descriptor: %v", err)
	}
	if err := platform.ReplaceKeys(ctx, file, []byte(appended)); err != nil {
		t.Fatal(err)
	}
	if live, err := os.ReadFile(inUse); err != nil || string(live) != appended {
		t.Fatalf("in-use bytes %q err=%v", live, err)
	}
	raw, canonical, want = liveSecurity(t, inUse, realAdminKeysSDDL)
	if canonical != want || !strings.Contains(raw, "S-1-5-21-1111111111-2222222-333333333-1001") {
		t.Fatalf("in-use security %q want %q (raw %q)", canonical, want, raw)
	}

	created := filepath.Join(directory, "created_authorized_keys")
	platform = pairingPlatform{keys: nativeKeys{}, adminKeysFile: created}
	missing, err := platform.ReadKeys(ctx, created)
	if err != nil || missing.Exists {
		t.Fatalf("missing: %+v err=%v", missing, err)
	}
	if err := platform.ReplaceKeys(ctx, missing, []byte("k\n")); err != nil {
		t.Fatal(err)
	}
	if live, err := os.ReadFile(created); err != nil || string(live) != "k\n" {
		t.Fatalf("created bytes %q err=%v", live, err)
	}
	raw, canonical, want = liveSecurity(t, created, adminKeysSDDL)
	if canonical != want {
		t.Fatalf("created security %q want %q (raw %q)", canonical, want, raw)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".blender-box-") {
			t.Fatalf("temp file left behind: %s", entry.Name())
		}
	}
}
