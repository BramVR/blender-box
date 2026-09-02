//go:build windows

package host

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"
)

const (
	lockfileExclusiveLock   = 0x00000002
	lockfileFailImmediately = 0x00000001
	errorLockViolation      = syscall.Errno(33)
)

var (
	kernel32Operation = syscall.NewLazyDLL("kernel32.dll")
	lockFileEx        = kernel32Operation.NewProc("LockFileEx")
	unlockFileEx      = kernel32Operation.NewProc("UnlockFileEx")
)

func acquireOperation(ctx context.Context, root string) (func(), error) {
	return acquireOperationFile(ctx, filepath.Join(root, ".operation.lock"))
}

func acquireLaunch(ctx context.Context, root string) (func(), error) {
	return acquireOperationFile(ctx, filepath.Join(root, ".launch.lock"))
}

func acquireOperationFile(ctx context.Context, path string) (func(), error) {
	lock, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		var overlapped syscall.Overlapped
		result, _, callErr := lockFileEx.Call(
			lock.Fd(),
			lockfileExclusiveLock|lockfileFailImmediately,
			0,
			1,
			0,
			uintptr(unsafe.Pointer(&overlapped)),
		)
		if result != 0 {
			return func() {
				var unlockOverlapped syscall.Overlapped
				_, _, _ = unlockFileEx.Call(lock.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(&unlockOverlapped)))
				_ = lock.Close()
			}, nil
		}
		if errno, ok := callErr.(syscall.Errno); !ok || errno != errorLockViolation {
			_ = lock.Close()
			return nil, callErr
		}
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			_ = lock.Close()
			return nil, fmt.Errorf("wait for host operation: %w", ctx.Err())
		case <-timer.C:
		}
	}
}
