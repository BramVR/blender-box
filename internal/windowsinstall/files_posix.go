//go:build !windows

package windowsinstall

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func fileIdentity(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	stat := info.Sys().(*syscall.Stat_t)
	return fmt.Sprintf("%d:%d:%o", stat.Dev, stat.Ino, info.Mode()), nil
}
func publishFile(source, destination string, replace bool) error {
	if replace {
		if err := os.Rename(source, destination); err != nil {
			return err
		}
	} else {
		if err := os.Link(source, destination); err != nil {
			return err
		}
	}
	directory, err := os.Open(filepath.Dir(destination))
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func removeOwnedFile(path string, _ File) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
