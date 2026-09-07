//go:build windows

package windowsinstall

import (
	"fmt"
	"syscall"
	"unsafe"
)

var nativeGetSystemDirectory = nativeProcessKernel.NewProc("GetSystemDirectoryW")

func systemDirectory() (string, error) {
	var path [32768]uint16
	length, _, err := nativeGetSystemDirectory.Call(uintptr(unsafe.Pointer(&path[0])), uintptr(len(path)))
	if length == 0 {
		return "", fmt.Errorf("get Windows system directory: %w", err)
	}
	if length >= uintptr(len(path)) {
		return "", fmt.Errorf("Windows system directory exceeds bound")
	}
	return syscall.UTF16ToString(path[:length]), nil
}
