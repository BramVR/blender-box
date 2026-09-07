//go:build windows

package windowsinstall

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var nativePostPort = nativeProcessKernel.NewProc("PostQueuedCompletionStatus")

const nativeCollectorWake = ^uint32(0)

type nativeMemberWindows struct{ job syscall.Handle }

func (api nativeMemberWindows) open(pid uint32) (nativeMember, error) {
	handle, err := syscall.OpenProcess(syscall.SYNCHRONIZE|0x1000, false, pid)
	if err != nil {
		return nativeMember{}, fmt.Errorf("open native job member %d: %w", pid, err)
	}
	var created, exited, kernel, user syscall.Filetime
	if err = syscall.GetProcessTimes(handle, &created, &exited, &kernel, &user); err == nil {
		var member uint32
		if ok, _, callErr := nativeIsProcessInJob.Call(uintptr(handle), uintptr(api.job), uintptr(unsafe.Pointer(&member))); ok == 0 {
			err = fmt.Errorf("query exact native job membership: %w", callErr)
		} else if member != 1 {
			err = fmt.Errorf("process is outside exact native job")
		}
	}
	if err != nil {
		_ = syscall.CloseHandle(handle)
		return nativeMember{}, err
	}
	return nativeMember{uintptr(handle), pid, uint64(created.HighDateTime)<<32 | uint64(created.LowDateTime)}, nil
}

func (nativeMemberWindows) close(handle uintptr) { _ = syscall.CloseHandle(syscall.Handle(handle)) }

func (api nativeMemberWindows) counts() (nativeJobCounts, error) {
	var accounting nativeAccounting
	var length uint32
	if ok, _, err := nativeQueryJob.Call(uintptr(api.job), 1, uintptr(unsafe.Pointer(&accounting)), unsafe.Sizeof(accounting), uintptr(unsafe.Pointer(&length))); ok == 0 {
		return nativeJobCounts{}, fmt.Errorf("query native job accounting: %w", err)
	}
	if length != uint32(unsafe.Sizeof(accounting)) {
		return nativeJobCounts{}, fmt.Errorf("native job accounting has invalid size")
	}
	return nativeJobCounts{accounting.TotalProcesses, accounting.ActiveProcesses}, nil
}

func (api nativeMemberWindows) list() (nativeMemberList, error) {
	var list struct {
		Assigned, Listed uint32
		PIDs             [nativeMemberLimit]uintptr
	}
	if ok, _, err := nativeQueryJob.Call(uintptr(api.job), 3, uintptr(unsafe.Pointer(&list)), unsafe.Sizeof(list), 0); ok == 0 {
		return nativeMemberList{}, fmt.Errorf("query native job members: %w", err)
	}
	if list.Listed > nativeMemberLimit || list.Assigned != list.Listed {
		return nativeMemberList{}, fmt.Errorf("native job member list is incomplete")
	}
	pids := make([]uint32, list.Listed)
	for i := range pids {
		if list.PIDs[i] == 0 || uint64(list.PIDs[i]) > uint64(^uint32(0)) {
			return nativeMemberList{}, fmt.Errorf("native job member PID is invalid")
		}
		pids[i] = uint32(list.PIDs[i])
	}
	return nativeMemberList{list.Assigned, pids}, nil
}

func (api nativeMemberWindows) terminate() error {
	if ok, _, err := nativeTerminateJob.Call(uintptr(api.job), 1); ok == 0 {
		return fmt.Errorf("terminate native job: %w", err)
	}
	return nil
}

func nativeWaitMillis(deadline time.Time) uint32 {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return 0
	}
	return uint32((remaining + time.Millisecond - 1) / time.Millisecond)
}

func (nativeMemberWindows) wait(handle uintptr, deadline time.Time) error {
	wait, err := syscall.WaitForSingleObject(syscall.Handle(handle), nativeWaitMillis(deadline))
	if err != nil || wait != syscall.WAIT_OBJECT_0 {
		return fmt.Errorf("wait native member: event=%d error=%v", wait, err)
	}
	return nil
}

type nativeCollector struct {
	members  *nativeMembers
	done     chan struct{}
	cancel   chan struct{}
	stopOnce sync.Once
	stopErr  error
}

func (job *nativeJob) collect(spawn nativeSpawn) error {
	collector := &nativeCollector{members: newNativeMembers(nativeMemberWindows{job.handle}), done: make(chan struct{}), cancel: make(chan struct{})}
	created := uint64(spawn.Created.HighDateTime)<<32 | uint64(spawn.Created.LowDateTime)
	if err := collector.members.seed(spawn.Info.ProcessId, created); err != nil {
		collector.members.close()
		return err
	}
	job.collector = collector
	port, key := job.port, uintptr(job.handle)
	started := make(chan struct{})
	go func() {
		defer close(collector.done)
		close(started)
		for collector.members.fault == nil {
			select {
			case <-collector.cancel:
				return
			default:
			}
			var message uint32
			var receivedKey, pid uintptr
			// The finite wait also releases the collector if its explicit wake fails.
			ok, _, err := nativeReadPort.Call(uintptr(port), uintptr(unsafe.Pointer(&message)), uintptr(unsafe.Pointer(&receivedKey)), uintptr(unsafe.Pointer(&pid)), uintptr(nativeCleanupTimeout/time.Millisecond))
			if ok == 0 {
				if err == syscall.Errno(syscall.WAIT_TIMEOUT) {
					continue
				}
				collector.members.fail(fmt.Errorf("read native completion: %w", err))
				return
			}
			if receivedKey != key {
				collector.members.fail(fmt.Errorf("unexpected native completion key"))
				return
			}
			if message == nativeCollectorWake && pid == 0 {
				return
			}
			if !collector.members.event(message, pid) {
				return
			}
		}
	}()
	<-started
	return nil
}

func (job *nativeJob) stopCollection(deadline time.Time) error {
	collector := job.collector
	collector.stopOnce.Do(func() {
		select {
		case <-collector.done:
			return
		default:
		}
		if ok, _, err := nativePostPort.Call(uintptr(job.port), uintptr(nativeCollectorWake), uintptr(job.handle), 0); ok == 0 {
			collector.stopErr = fmt.Errorf("wake native collector: %w", err)
			close(collector.cancel)
		}
	})
	timer := time.NewTimer(max(time.Until(deadline), 0))
	defer timer.Stop()
	select {
	case <-collector.done:
		collector.members.fail(collector.stopErr)
		return nil
	case <-timer.C:
		return errors.Join(errNativeCleanupUnknown, collector.stopErr, fmt.Errorf("native collector did not acknowledge cleanup deadline"))
	}
}

func (job *nativeJob) settle(deadline time.Time) error {
	if job.collector == nil {
		members := newNativeMembers(nativeMemberWindows{job.handle})
		defer members.close()
		return members.settle(deadline)
	}
	if err := job.stopCollection(deadline); err != nil {
		return errors.Join(err, nativeMemberWindows{job.handle}.terminate())
	}
	return job.collector.members.settle(deadline)
}
