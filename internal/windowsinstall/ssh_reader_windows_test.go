//go:build windows

package windowsinstall

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
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
