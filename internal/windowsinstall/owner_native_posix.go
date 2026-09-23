//go:build !windows

package windowsinstall

import (
	"context"
	"fmt"
	"io"
	"os"
)

func launchNativeKeeper(_ context.Context, request Request) (Result, error) {
	return problem(emptyResult(request), "unsupported-platform", fmt.Errorf("host-local setup requires Windows"))
}
func runNativeWorker(context.Context, executionRequest, func(executionOwnership) error) (workerOutcome, *treeExit, error) {
	return workerOutcome{}, nil, fmt.Errorf("native worker requires Windows")
}
func nativeProcessAlive(ProcessIdentity) (bool, error) {
	return false, fmt.Errorf("native process identity requires Windows")
}
func openPinnedSource(path string) (*os.File, error)    { return os.Open(path) }
func openPinnedDirectory(path string) (*os.File, error) { return os.Open(path) }
func RunInternal(args []string, _ io.Reader, _ io.Writer, stderr io.Writer) (bool, int) {
	if len(args) > 0 && (args[0] == "__setup-keeper" || args[0] == "__setup-worker") {
		fmt.Fprintln(stderr, "setup internal roles require Windows")
		return true, 1
	}
	return false, 0
}
