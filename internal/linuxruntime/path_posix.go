//go:build !windows

package linuxruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func SafePath(name string, uid uint32, private bool) error {
	if !filepath.IsAbs(name) {
		return fmt.Errorf("Linux path must be absolute: %s", name)
	}
	if filepath.Clean(name) != name {
		return fmt.Errorf("Linux path must be canonical: %s", name)
	}
	for current := name; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) || (stat.Uid != 0 && stat.Uid != uid) || (info.Mode().Perm()&0022 != 0 && !(current != name && info.IsDir() && stat.Uid == 0 && info.Mode()&os.ModeSticky != 0)) {
			return fmt.Errorf("unsafe Linux path owner, mode or type at %s", current)
		}
		if current == name && private && (stat.Uid != uid || info.Mode().Perm()&0077 != 0) {
			return fmt.Errorf("Linux private path must be UID-owned and owner-only: %s", name)
		}
		if current == "/" {
			break
		}
	}
	return nil
}
