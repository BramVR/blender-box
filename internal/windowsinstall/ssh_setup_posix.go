//go:build !windows

package windowsinstall

import (
	"context"
	"fmt"
)

type nativeSSHMachine struct{ nativeSSHD }

func (nativeSSHMachine) setService(context.Context, string, bool) error {
	return fmt.Errorf("unsupported platform; no host changes performed")
}
func (nativeSSHMachine) rule(context.Context, string, FirewallRule) (bool, bool, error) {
	return false, false, fmt.Errorf("unsupported platform; no host changes performed")
}
func (nativeSSHMachine) admittingRule(context.Context, uint16) (string, error) {
	return "", fmt.Errorf("unsupported platform; no host changes performed")
}
