//go:build !windows

package privatefile

import (
	"fmt"
	"os"
	"syscall"
)

func checkPrivate(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("private storage requires current-user ownership and private permissions")
	}
	return nil
}
func unsafeType(info os.FileInfo) bool { return info.Mode()&os.ModeSymlink != 0 }
func publish(source, destination string, replace bool) error {
	if replace {
		return os.Rename(source, destination)
	}
	return os.Link(source, destination)
}
func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func openRead(path string) (*os.File, error) {
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(descriptor), path), nil
}
