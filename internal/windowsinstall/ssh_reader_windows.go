//go:build windows

package windowsinstall

import (
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

var sshKernel = syscall.NewLazyDLL("kernel32.dll")
var sshVolumeName = sshKernel.NewProc("GetVolumeNameForVolumeMountPointW")
var sshDriveType = sshKernel.NewProc("GetDriveTypeW")
var sshReopen = sshKernel.NewProc("ReOpenFile")
var sshKernelSecurity = syscall.NewLazyDLL("advapi32.dll").NewProc("GetKernelObjectSecurity")
var sshGetAce = syscall.NewLazyDLL("advapi32.dll").NewProc("GetAce")
var sshNtCreate = syscall.NewLazyDLL("ntdll.dll").NewProc("NtCreateFile")
var sshNtError = syscall.NewLazyDLL("ntdll.dll").NewProc("RtlNtStatusToDosError")

type sshWindowsBackend struct{}
type sshWindowsFile struct {
	*os.File
	physical string
}

func newSSHNativeReader() (sshReadBoundary, error) {
	return &sshNativeReader{newSSHReadScope(sshWindowsBackend{})}, nil
}

type sshNativeReader struct{ *sshReadScope }

func (s *sshNativeReader) files() sshFilesystem                     { return s.sshReadScope }
func (b sshWindowsBackend) anchor(root string) (sshHeldFile, error) { return sshCaptureAnchor(root, b) }
func (sshWindowsBackend) capture(root string) (string, error) {
	input, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return "", err
	}
	var volume [128]uint16
	ok, _, callErr := sshVolumeName.Call(uintptr(unsafe.Pointer(input)), uintptr(unsafe.Pointer(&volume[0])), uintptr(len(volume)))
	if ok == 0 {
		return "", callErr
	}
	return syscall.UTF16ToString(volume[:]), nil
}
func (sshWindowsBackend) fixed(physical string) bool {
	pointer, err := syscall.UTF16PtrFromString(physical)
	if err != nil {
		return false
	}
	kind, _, _ := sshDriveType.Call(uintptr(unsafe.Pointer(pointer)))
	return kind == 3
}
func (sshWindowsBackend) openVolume(physical string) (sshHeldFile, error) {
	pointer, err := syscall.UTF16PtrFromString(physical)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(pointer, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	return &sshWindowsFile{os.NewFile(uintptr(handle), physical), physical}, nil
}

type sshUnicodeString struct {
	length, maximum uint16
	buffer          *uint16
}
type sshObjectAttributes struct {
	length        uint32
	root          syscall.Handle
	name          *sshUnicodeString
	attributes    uint32
	security, qos uintptr
}
type sshIOStatus struct{ status, information uintptr }

func (sshWindowsBackend) child(parent sshHeldFile, name string) (sshHeldFile, error) {
	p := parent.(*sshWindowsFile)
	units, err := syscall.UTF16FromString(name)
	if err != nil {
		return nil, err
	}
	text := sshUnicodeString{uint16((len(units) - 1) * 2), uint16(len(units) * 2), &units[0]}
	attributes := sshObjectAttributes{root: syscall.Handle(p.Fd()), name: &text, attributes: 0x40}
	attributes.length = uint32(unsafe.Sizeof(attributes))
	var handle syscall.Handle
	var result sshIOStatus
	code, _, _ := sshNtCreate.Call(uintptr(unsafe.Pointer(&handle)), uintptr(syscall.GENERIC_READ|syscall.SYNCHRONIZE), uintptr(unsafe.Pointer(&attributes)), uintptr(unsafe.Pointer(&result)), 0, 0, uintptr(syscall.FILE_SHARE_READ), 1, 0x00200000|0x20|0x4000, 0, 0)
	runtime.KeepAlive(units)
	runtime.KeepAlive(p)
	if uint32(code)&0x80000000 != 0 {
		translated, _, _ := sshNtError.Call(code)
		return nil, &os.PathError{Op: "open child", Path: name, Err: syscall.Errno(translated)}
	}
	physical := p.physical
	if physical[len(physical)-1] != '\\' {
		physical += `\`
	}
	physical += name
	return &sshWindowsFile{os.NewFile(uintptr(handle), physical), physical}, nil
}
func (f *sshWindowsFile) ReadDir(maximum int) ([]fs.DirEntry, error) {
	handle, _, err := sshReopen.Call(f.Fd(), uintptr(syscall.GENERIC_READ), uintptr(syscall.FILE_SHARE_READ), uintptr(syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT))
	if handle == ^uintptr(0) {
		return nil, err
	}
	file := os.NewFile(handle, f.physical)
	defer file.Close()
	return file.ReadDir(maximum)
}
func (f *sshWindowsFile) pin(path string) (SSHPathPin, error) {
	identity, err := handleIdentity(syscall.Handle(f.Fd()))
	if err != nil {
		return SSHPathPin{}, err
	}
	var needed uint32
	sshKernelSecurity.Call(f.Fd(), 7, 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 || needed > 65536 {
		return SSHPathPin{}, fmt.Errorf("invalid handle security size")
	}
	data := make([]byte, needed)
	ok, _, callErr := sshKernelSecurity.Call(f.Fd(), 7, uintptr(unsafe.Pointer(&data[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed)))
	if ok == 0 {
		return SSHPathPin{}, callErr
	}
	return SSHPathPin{Path: path, PhysicalID: identity, DescriptorSHA: digest(data)}, nil
}
func (f *sshWindowsFile) trust(sid string, authority uint32) error {
	var owner, acl, descriptor unsafe.Pointer
	code, _, _ := sshGetSecurityInfo.Call(f.Fd(), 1, 7, uintptr(unsafe.Pointer(&owner)), 0, uintptr(unsafe.Pointer(&acl)), 0, uintptr(unsafe.Pointer(&descriptor)))
	if code != 0 {
		return syscall.Errno(code)
	}
	defer sshLocalFree.Call(uintptr(descriptor))
	trusted := func(value string) bool {
		return value == sid || value == "S-1-5-18" || value == "S-1-5-32-544" || value == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	}
	if owner == nil {
		return fmt.Errorf("missing native owner")
	}
	ownerSID, err := (*syscall.SID)(owner).String()
	if err != nil || !trusted(ownerSID) || acl == nil {
		return fmt.Errorf("untrusted native path owner or DACL")
	}
	header := (*struct {
		revision, padding     byte
		size, count, padding2 uint16
	})(acl)
	if header.size < 8 || header.count > 4096 {
		return fmt.Errorf("invalid native DACL")
	}
	for i := uint16(0); i < header.count; i++ {
		var ace unsafe.Pointer
		ok, _, _ := sshGetAce.Call(uintptr(acl), uintptr(i), uintptr(unsafe.Pointer(&ace)))
		if ok == 0 {
			return fmt.Errorf("invalid native ACE")
		}
		entry := (*struct {
			kind, flags byte
			size        uint16
			mask        uint32
		})(ace)
		if entry.flags&8 != 0 {
			continue
		}
		if entry.kind == 1 {
			continue
		}
		if entry.kind != 0 || entry.size < 16 {
			return fmt.Errorf("unsupported native ACE")
		}
		mask := entry.mask
		if mask&0x10000000 != 0 {
			mask |= 0x001f01ff
		}
		if mask&0x40000000 != 0 {
			mask |= 0x00000116
		}
		principal, err := (*syscall.SID)(unsafe.Add(ace, 8)).String()
		if err != nil || mask&authority != 0 && !trusted(principal) {
			return fmt.Errorf("untrusted native path writer")
		}
	}
	return nil
}
