//go:build !windows

package host

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func acquireOperation(ctx context.Context, root string) (func(), error) {
	return acquireOperationFile(ctx, filepath.Join(root, ".operation.lock"))
}

func acquireLaunch(ctx context.Context, root string) (func(), error) {
	return acquireOperationFile(ctx, filepath.Join(root, ".launch.lock"))
}

func acquireOperationFile(ctx context.Context, path string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("wait for host operation: %w", err)
	}
	lock, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			_ = lock.Close()
			return nil, fmt.Errorf("wait for host operation: %w", err)
		}
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return func() {
				_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
				_ = lock.Close()
			}, nil
		} else if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			_ = lock.Close()
			return nil, err
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

func tryAcquireLaunch(root string) (func(), bool, error) {
	lock, err := os.OpenFile(filepath.Join(root, ".launch.lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
		return func() {
			_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
			_ = lock.Close()
		}, true, nil
	} else if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
		_ = lock.Close()
		return nil, false, nil
	} else {
		_ = lock.Close()
		return nil, false, err
	}
}
