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
	lock, err := openOperationLock(path)
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
	lock, err := openOperationLock(filepath.Join(root, ".launch.lock"))
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

func openOperationLock(path string) (*os.File, error) {
	if err := validateRoot(filepath.Dir(path)); err != nil {
		return nil, err
	}
	lock, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := lock.Stat()
	if err != nil {
		lock.Close()
		return nil, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0077 != 0 {
		lock.Close()
		return nil, fmt.Errorf("host operation lock must be a private owned regular file")
	}
	return lock, nil
}
