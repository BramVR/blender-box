//go:build !windows

package host

import (
	"github.com/BramVR/blender-box/internal/linuxruntime"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
)

func replaceFile(source, destination string) error {
	if err := os.Rename(source, destination); err != nil {
		return err
	}
	return syncDirectoryHierarchy(filepath.Dir(destination))
}
func syncDirectoryHierarchy(path string) error {
	for current := path; ; current = filepath.Dir(current) {
		directory, err := os.Open(current)
		if err != nil {
			return err
		}
		err = directory.Sync()
		closeErr := directory.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}
func validateNativePath(path string, private bool) error {
	if runtime.GOOS == "linux" {
		return linuxruntime.SafePath(path, uint32(os.Geteuid()), private)
	}
	return nil
}
func openRegularRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
