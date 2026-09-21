//go:build windows

package privatefile

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

var moveFileExW = syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW")
var setFileInformationByHandle = syscall.NewLazyDLL("kernel32.dll").NewProc("SetFileInformationByHandle")

func checkPrivate(os.FileInfo) error { return nil }
func unsafeType(info os.FileInfo) bool {
	if info.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return true
	}
	attributes, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return !ok || attributes.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
func publish(source, destination string, replace bool) error {
	if replace {
		return replaceFile(source, destination)
	}
	from, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	to, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return err
	}
	result, _, callErr := moveFileExW.Call(uintptr(unsafe.Pointer(from)), uintptr(unsafe.Pointer(to)), 0x8)
	if result == 0 {
		return callErr
	}
	return nil
}

func replaceFile(source, destination string) error {
	const (
		deleteAccess       = 0x00010000
		fileReadAttributes = 0x00000080
		fileRenameInfoEx   = 22
		replaceIfExists    = 0x00000001
		posixSemantics     = 0x00000002
	)
	info := struct {
		Flags          uint32
		RootDirectory  syscall.Handle
		FileNameLength uint32
		FileName       [32768]uint16
	}{Flags: replaceIfExists | posixSemantics}
	to, err := syscall.UTF16FromString(destination)
	if err != nil {
		return err
	}
	if len(to) > len(info.FileName) {
		return syscall.ENAMETOOLONG
	}
	copy(info.FileName[:], to)
	info.FileNameLength = uint32((len(to) - 1) * 2)
	from, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	handle, err := syscall.CreateFile(from, deleteAccess|fileReadAttributes, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(handle), source)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return err
	}
	if !opened.Mode().IsRegular() || unsafeType(opened) {
		return fmt.Errorf("publication source is not a regular file")
	}
	// POSIX replacement preserves old readers while new opens see the new file.
	result, _, callErr := setFileInformationByHandle.Call(uintptr(handle), fileRenameInfoEx, uintptr(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	if result == 0 {
		return callErr
	}
	return nil
}

func syncDirectory(string) error { return nil }

func openRead(path string) (*os.File, error) {
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Delete sharing lets atomic profile replacement coexist with open readers.
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(handle), path), nil
}
