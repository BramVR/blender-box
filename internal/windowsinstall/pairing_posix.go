//go:build !windows

package windowsinstall

import (
	"context"
	"fmt"
)

type nativeSSHD struct{}
type nativeKeys struct{}

func adminKeysFile() string { return defaultAdminKeysFile }

func (nativeSSHD) facts(context.Context, string, string, string) (sshdFacts, error) {
	return sshdFacts{}, fmt.Errorf("host pairing requires Windows: unsupported platform; no host changes performed")
}
func (nativeKeys) read(context.Context, string) (keysObservation, error) {
	return keysObservation{}, fmt.Errorf("host pairing requires Windows: unsupported platform; no host changes performed")
}
func (nativeKeys) replace(context.Context, keysReplacement) (keysObservation, error) {
	return keysObservation{}, fmt.Errorf("host pairing requires Windows: unsupported platform; no host changes performed")
}
