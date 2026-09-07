//go:build windows

package windowsinstall

import (
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

var moveFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")
var getFileSecurity = syscall.NewLazyDLL("advapi32.dll").NewProc("GetFileSecurityW")
var setFileInformation = syscall.NewLazyDLL("kernel32.dll").NewProc("SetFileInformationByHandle")

func openIdentity(path string, access uint32) (syscall.Handle, error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	return syscall.CreateFile(pointer, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}
func handleIdentity(handle syscall.Handle) (string, error) {
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &info); err != nil {
		return "", err
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", fmt.Errorf("reparse file")
	}
	return fmt.Sprintf("%d:%d:%d", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow), nil
}
func fileIdentity(path string) (string, error) {
	handle, err := openIdentity(path, syscall.GENERIC_READ)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(handle)
	id, err := handleIdentity(handle)
	if err != nil {
		return "", err
	}
	acl, err := securityDigest(path)
	if err != nil {
		return "", err
	}
	return id + ":" + string(acl), nil
}
func securityDigest(path string) (SHA256, error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	var needed uint32
	_, _, _ = getFileSecurity.Call(uintptr(unsafe.Pointer(pointer)), 7, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 || needed > 65536 {
		return "", fmt.Errorf("invalid file security size")
	}
	data := make([]byte, needed)
	result, _, err := getFileSecurity.Call(uintptr(unsafe.Pointer(pointer)), 7, uintptr(unsafe.Pointer(&data[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)))
	if result == 0 {
		return "", err
	}
	return digest(data), nil
}
func publishFile(source, destination string, replace bool) error {
	from, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	flags := uintptr(8)
	if replace {
		flags |= 1
	}
	result, _, err := moveFileEx.Call(uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), flags)
	if result == 0 {
		return err
	}
	return nil
}
func removeOwnedFile(path string, expected File) error {
	handle, err := openIdentity(path, syscall.GENERIC_READ|0x00010000)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), path)
	defer file.Close()
	id, err := handleIdentity(handle)
	if err != nil {
		return err
	}
	parts := strings.Split(expected.Identity, ":")
	if len(parts) != 4 || id != strings.Join(parts[:3], ":") {
		return fmt.Errorf("file changed before exact-handle deletion")
	}
	acl, err := securityDigest(path)
	if err != nil || string(acl) != parts[3] {
		return fmt.Errorf("file security changed before deletion")
	}
	if expected.Kind == "file" {
		data, err := io.ReadAll(io.LimitReader(file, maxArtifact+1))
		if err != nil {
			return err
		}
		if int64(len(data)) != expected.Size || digest(data) != expected.SHA256 {
			return fmt.Errorf("file bytes changed before deletion")
		}
	}
	var disposition byte = 1
	result, _, err := setFileInformation.Call(uintptr(handle), 4, uintptr(unsafe.Pointer(&disposition)), unsafe.Sizeof(disposition))
	if result == 0 {
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return nil
}
