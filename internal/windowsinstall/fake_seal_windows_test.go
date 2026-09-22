//go:build windows

package windowsinstall

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

var convertFakeSD = syscall.NewLazyDLL("advapi32.dll").NewProc("ConvertStringSecurityDescriptorToSecurityDescriptorW")
var fakeSetSecurity = syscall.NewLazyDLL("advapi32.dll").NewProc("SetFileSecurityW")
var fakeSDString = syscall.NewLazyDLL("advapi32.dll").NewProc("ConvertSecurityDescriptorToStringSecurityDescriptorW")

func fakeCurrentSID() (string, error) {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return "", err
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil {
		return "", err
	}
	return user.User.Sid.String()
}

func fakeDACL(extra bool) (string, error) {
	sid, err := fakeCurrentSID()
	if err != nil {
		return "", err
	}
	sddl := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;" + sid + ")"
	if extra {
		sddl += "(A;;FR;;;AU)"
	}
	return sddl, nil
}

func setFakeDACL(path string, extra bool) error {
	sddl, err := fakeDACL(extra)
	if err != nil {
		return err
	}
	encoded, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return err
	}
	var descriptor uintptr
	var size uint32
	result, _, callErr := convertFakeSD.Call(uintptr(unsafe.Pointer(encoded)), 1, uintptr(unsafe.Pointer(&descriptor)), uintptr(unsafe.Pointer(&size)))
	if result == 0 {
		return callErr
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	result, _, callErr = fakeSetSecurity.Call(uintptr(unsafe.Pointer(name)), 0x80000004, descriptor)
	if result == 0 {
		return callErr
	}
	return nil
}

func fakeSeal(path string) error     { return setFakeDACL(path, false) }
func fakeThirdACL(path string) error { return setFakeDACL(path, true) }

func fakeSealed(path string) error {
	want, err := fakeDACL(false)
	if err != nil {
		return err
	}
	want, err = canonicalFakeDACL(want)
	if err != nil {
		return err
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	var needed uint32
	_, _, _ = getFileSecurity.Call(uintptr(unsafe.Pointer(name)), 4, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 || needed > 65536 {
		return fmt.Errorf("invalid fake security descriptor size")
	}
	data := make([]byte, needed)
	result, _, callErr := getFileSecurity.Call(uintptr(unsafe.Pointer(name)), 4, uintptr(unsafe.Pointer(&data[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)))
	if result == 0 {
		return callErr
	}
	actual, err := fakeDescriptorString(uintptr(unsafe.Pointer(&data[0])))
	if err != nil {
		return err
	}
	if actual != want {
		return fmt.Errorf("sealed runtime ACL changed: %s", path)
	}
	return nil
}

func canonicalFakeDACL(sddl string) (string, error) {
	value, err := syscall.UTF16PtrFromString(sddl)
	if err != nil {
		return "", err
	}
	var descriptor uintptr
	var size uint32
	result, _, callErr := convertFakeSD.Call(uintptr(unsafe.Pointer(value)), 1, uintptr(unsafe.Pointer(&descriptor)), uintptr(unsafe.Pointer(&size)))
	if result == 0 {
		return "", callErr
	}
	defer syscall.LocalFree(syscall.Handle(descriptor))
	return fakeDescriptorString(descriptor)
}

func fakeDescriptorString(descriptor uintptr) (string, error) {
	var encoded uintptr
	var count uint32
	result, _, callErr := fakeSDString.Call(descriptor, 1, 4, uintptr(unsafe.Pointer(&encoded)), uintptr(unsafe.Pointer(&count)))
	if result == 0 {
		return "", callErr
	}
	defer syscall.LocalFree(syscall.Handle(encoded))
	sddl := syscall.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(encoded)), count))
	aces := strings.IndexByte(sddl, '(')
	if aces < 0 || !strings.Contains(sddl[:aces], "P") {
		return "", fmt.Errorf("fake runtime DACL is not protected")
	}
	return "D:P" + sddl[aces:], nil
}
