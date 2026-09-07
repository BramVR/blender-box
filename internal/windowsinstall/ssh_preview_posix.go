//go:build !windows

package windowsinstall

import "fmt"

func newSSHNativeReader() (sshReadBoundary, error) {
	return nil, fmt.Errorf("SSH preview requires native Windows inspection; no host state created")
}
