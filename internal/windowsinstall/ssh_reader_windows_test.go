//go:build windows

package windowsinstall

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"unsafe"
)

func TestSSHWindowsRetainedReadRejectsWritersAndReenumerates(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "fixture.txt")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	scope := newSSHReadScope(sshWindowsBackend{})
	defer scope.Close()
	image, err := scope.image(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(image.Bytes) != "fixture" {
		t.Fatal("wrong held bytes")
	}
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, access := range []uint32{syscall.GENERIC_WRITE, 0x00010000} {
		handle, err := syscall.CreateFile(pointer, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, 0, 0)
		if err == nil {
			syscall.CloseHandle(handle)
			t.Fatal("retained read permitted writer or deleter")
		}
	}
	first, err := scope.ReadDir(root, 16)
	if err != nil || len(first) != 1 {
		t.Fatalf("first list: %v %v", first, err)
	}
	if err := os.WriteFile(filepath.Join(root, "appeared.txt"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := scope.ReadDir(root, 16)
	if err != nil || len(second) != 2 {
		t.Fatalf("directory membership frozen: %v %v", second, err)
	}
	scope.Close()
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal("scope leaked handle", err)
	}
	writer.Close()
}
func TestSSHWindowsSymlinkAncestorRefusesMissingLeaf(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("local symlink privilege unavailable: %v", err)
	}
	scope := newSSHReadScope(sshWindowsBackend{})
	defer scope.Close()
	if _, err := scope.Stat(filepath.Join(link, "absent")); err == nil || os.IsNotExist(err) {
		t.Fatalf("descendant touched before reparse refusal: %v", err)
	}
}

func TestSSHReaderPowerShellUTF8RoundTrip(t *testing.T) {
	reader := &sshNativeReader{newSSHReadScope(sshWindowsBackend{})}
	defer reader.Close()
	cache := filepath.Join(t.TempDir(), "unused-module-cache")
	t.Setenv("PSModuleAnalysisCachePath", cache)
	want := "Données 日本語 🎨"
	data, err := reader.powerShell(context.Background(), `[ordered]@{value=$r.value;cache=$env:PSModuleAnalysisCachePath} | ConvertTo-Json -Compress`, map[string]string{"value": want})
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Value string `json:"value"`
		Cache string `json:"cache"`
	}
	if err := json.Unmarshal(data, &result); err != nil || result.Value != want || result.Cache != "nul" {
		t.Fatalf("SSH PowerShell roundtrip=%q error=%v", data, err)
	}
	if os.Getenv("PSModuleAnalysisCachePath") != cache {
		t.Fatal("SSH reader changed parent cache environment")
	}
	if _, err := os.Lstat(cache); !os.IsNotExist(err) {
		t.Fatalf("SSH reader wrote inherited module cache: %v", err)
	}
}

func TestSSHExecutablePathRefusesUntrustedApplicationDirectory(t *testing.T) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		t.Fatal(err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := user.User.Sid.String()
	if err != nil {
		t.Fatal(err)
	}
	for _, rights := range []uint32{0x2, 0x4, 0x40000000} {
		t.Run(fmt.Sprintf("directory-rights-%x", rights), func(t *testing.T) {
			application := filepath.Join(t.TempDir(), "application")
			if err := os.Mkdir(application, 0700); err != nil {
				t.Fatal(err)
			}
			executable := filepath.Join(application, "fixture.exe")
			if err := os.WriteFile(executable, []byte("task-owned non-executable fixture"), 0600); err != nil {
				t.Fatal(err)
			}
			descriptorText := fmt.Sprintf("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%s)(A;;0x%08x;;;WD)", sid, rights)
			text, err := syscall.UTF16PtrFromString(descriptorText)
			if err != nil {
				t.Fatal(err)
			}
			var descriptor unsafe.Pointer
			convert := syscall.NewLazyDLL("advapi32.dll").NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
			ok, _, callErr := convert.Call(uintptr(unsafe.Pointer(text)), 1, uintptr(unsafe.Pointer(&descriptor)), 0)
			if ok == 0 {
				t.Fatal(callErr)
			}
			defer sshLocalFree.Call(uintptr(descriptor))
			directory, err := syscall.UTF16PtrFromString(application)
			if err != nil {
				t.Fatal(err)
			}
			set := syscall.NewLazyDLL("advapi32.dll").NewProc("SetFileSecurityW")
			ok, _, callErr = set.Call(uintptr(unsafe.Pointer(directory)), 0x80000004, uintptr(descriptor))
			if ok == 0 {
				t.Fatal(callErr)
			}
			reader := &sshNativeReader{newSSHReadScope(sshWindowsBackend{})}
			defer reader.Close()
			if err := reader.trusted(executable, sid); err != nil {
				t.Fatalf("trusted executable with weaker ancestor check refused: %v", err)
			}
			path, err := reader.executablePath(executable, sid)
			if err == nil || path != "" {
				t.Fatalf("untrusted application directory produced launch path %q: %v", path, err)
			}
		})
	}
}

func TestSSHPreviewWindowsDACLBinding(t *testing.T) {
	owner, reader, request := sshPreviewFixture(t)
	reader.change = func(observed *sshNativeObservation) {
		scope := newSSHReadScope(sshWindowsBackend{})
		defer scope.Close()
		image, err := scope.image(reader.config, maxSSHConfig)
		if err != nil {
			t.Fatal(err)
		}
		observed.Configuration = image
	}
	before, err := owner.previewSSH(context.Background(), request)
	if err != nil || before.State != "previewed" {
		t.Fatalf("before preview: %+v %v", before, err)
	}
	command := exec.Command(filepath.Join(os.Getenv("SystemRoot"), "System32", "icacls.exe"), reader.config, "/grant", "*S-1-1-0:(R)")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("task-file DACL change: %v %s", err, output)
	}
	inventory := sshInventory(t, filepath.Dir(request.StateRoot))
	after, err := owner.previewSSH(context.Background(), request)
	if err != nil || after.State != "previewed" {
		t.Fatalf("after preview: %+v %v", after, err)
	}
	oldPin, newPin := before.Plan.Body.Configuration.Before.Pin, after.Plan.Body.Configuration.Before.Pin
	if oldPin.Path.PhysicalID != newPin.Path.PhysicalID || oldPin.BytesSHA != newPin.BytesSHA || oldPin.Path.DescriptorSHA == newPin.Path.DescriptorSHA || before.Plan.PlanSHA256 == after.Plan.PlanSHA256 {
		t.Fatal("native DACL change not bound independently of file identity and bytes")
	}
	if !reflect.DeepEqual(inventory, sshInventory(t, filepath.Dir(request.StateRoot))) {
		t.Fatal("preview changed files after DACL observation")
	}
}
