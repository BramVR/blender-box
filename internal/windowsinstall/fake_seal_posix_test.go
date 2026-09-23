//go:build !windows

package windowsinstall

import (
	"fmt"
	"os"
)

func fakeSeal(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	mode := os.FileMode(0640)
	if info.IsDir() {
		mode = 0701
	}
	return os.Chmod(path, mode)
}

func fakeSealed(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	mode := os.FileMode(0640)
	if info.IsDir() {
		mode = 0701
	}
	if info.Mode().Perm() != mode {
		return fmt.Errorf("sealed runtime ACL changed")
	}
	return nil
}

func fakeThirdACL(path string) error { return os.Chmod(path, 0601) }
