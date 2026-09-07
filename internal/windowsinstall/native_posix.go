//go:build !windows

package windowsinstall

import (
	"context"
	"fmt"
	"github.com/BramVR/blender-box/internal/target"
)

type nativeMachine struct{}

func (nativeMachine) inspect(context.Context, Request) (Inspection, error) {
	return Inspection{BlenderCandidates: []Candidate{}}, fmt.Errorf("host-local setup requires Windows; no files were created")
}
func (nativeMachine) securePath(context.Context, string, string, bool) error {
	return fmt.Errorf("unsupported platform")
}
func (nativeMachine) createDirectory(context.Context, string, string) error {
	return fmt.Errorf("unsupported platform")
}
func (nativeMachine) task(context.Context, string, taskSpec) (taskObservation, error) {
	return taskObservation{}, fmt.Errorf("unsupported platform")
}
func (nativeMachine) probe(context.Context, string, string) error {
	return fmt.Errorf("unsupported platform")
}

func (nativeMachine) target(installIntent) (target.Target, error) {
	return target.Target{}, fmt.Errorf("unsupported platform")
}
