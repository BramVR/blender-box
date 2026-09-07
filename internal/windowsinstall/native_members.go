package windowsinstall

import (
	"errors"
	"fmt"
	"time"
)

const (
	nativeMemberLimit = 256
	nativeEventLimit  = 2048
)

type nativeMember struct {
	handle  uintptr
	pid     uint32
	created uint64
}

type nativeJobCounts struct{ total, active uint32 }
type nativeMemberList struct {
	assigned uint32
	pids     []uint32
}

type nativeMemberBoundary interface {
	open(uint32) (nativeMember, error)
	close(uintptr)
	counts() (nativeJobCounts, error)
	list() (nativeMemberList, error)
	terminate() error
	wait(uintptr, time.Time) error
}

type nativeMembers struct {
	api       nativeMemberBoundary
	held      map[uint32]nativeMember
	fault     error
	lastTotal uint32
	events    int
}

func newNativeMembers(api nativeMemberBoundary) *nativeMembers {
	return &nativeMembers{api: api, held: make(map[uint32]nativeMember)}
}

func (members *nativeMembers) fail(err error) {
	if err != nil && members.fault == nil {
		members.fault = errors.Join(errNativeCleanupUnknown, err)
	}
}

func (members *nativeMembers) retain(pid uint32, expectedCreation uint64) {
	if pid == 0 {
		members.fail(fmt.Errorf("native member has invalid PID"))
		return
	}
	if prior, exists := members.held[pid]; exists {
		if expectedCreation != 0 && prior.created != expectedCreation {
			members.fail(fmt.Errorf("native member creation changed"))
		}
		return
	}
	if len(members.held) >= nativeMemberLimit {
		members.fail(fmt.Errorf("native member limit exceeded"))
		return
	}
	member, err := members.api.open(pid)
	if err != nil {
		members.fail(err)
		return
	}
	if member.handle == 0 || member.pid != pid || member.created == 0 || expectedCreation != 0 && member.created != expectedCreation {
		if member.handle != 0 {
			members.api.close(member.handle)
		}
		members.fail(fmt.Errorf("native member identity changed"))
		return
	}
	members.held[pid] = member
}

func (members *nativeMembers) seed(pid uint32, created uint64) error {
	if created == 0 {
		members.fail(fmt.Errorf("native root creation identity unavailable"))
	} else {
		members.retain(pid, created)
	}
	return members.fault
}

func (members *nativeMembers) observeCounts() nativeJobCounts {
	counts, err := members.api.counts()
	if err != nil {
		members.fail(err)
		return counts
	}
	if counts.total < members.lastTotal || counts.total > nativeMemberLimit || counts.active > counts.total {
		members.fail(fmt.Errorf("native job accounting exceeds coverage bounds"))
	}
	members.lastTotal = counts.total
	return counts
}

func (members *nativeMembers) snapshot() []uint32 {
	list, err := members.api.list()
	if err != nil {
		members.fail(err)
		return nil
	}
	if list.assigned > nativeMemberLimit || int(list.assigned) != len(list.pids) {
		members.fail(fmt.Errorf("native job member list is incomplete"))
		return nil
	}
	seen := make(map[uint32]bool, len(list.pids))
	for _, pid := range list.pids {
		if pid == 0 || seen[pid] {
			members.fail(fmt.Errorf("native job member list has invalid identities"))
			return nil
		}
		seen[pid] = true
	}
	return list.pids
}

func (members *nativeMembers) event(message uint32, pid uintptr) bool {
	members.events++
	if members.events > nativeEventLimit {
		members.fail(fmt.Errorf("native completion event limit exceeded"))
		return false
	}
	switch message {
	case 4:
		if pid != 0 {
			members.fail(fmt.Errorf("native empty-job completion has a PID"))
		}
	case 6, 7, 8:
		if pid == 0 || uint64(pid) > uint64(^uint32(0)) {
			members.fail(fmt.Errorf("native completion has invalid PID"))
			return false
		}
		if message == 6 {
			members.retain(uint32(pid), 0)
			members.observeCounts()
		}
	default:
		members.fail(fmt.Errorf("unexpected native completion message %d", message))
	}
	return members.fault == nil
}

func (members *nativeMembers) settleFailedStart(hasReturnedIdentity bool, startErr error, deadline time.Time) (bool, error) {
	failed := startErr != nil
	if !failed {
		startErr = fmt.Errorf("native start succeeded without a process")
	}
	var counts nativeJobCounts
	if time.Until(deadline) > 0 {
		counts = members.observeCounts()
	}
	if time.Until(deadline) <= 0 {
		members.fail(fmt.Errorf("native cleanup deadline exceeded"))
	}
	if failed && !hasReturnedIdentity && members.fault == nil && counts.total == 0 && counts.active == 0 {
		return true, startErr
	}
	return false, errors.Join(startErr, errNativeCleanupUnknown, members.settle(deadline))
}

func (members *nativeMembers) settle(deadline time.Time) error {
	withinDeadline := func() bool {
		if time.Until(deadline) > 0 {
			return true
		}
		members.fail(fmt.Errorf("native cleanup deadline exceeded"))
		return false
	}
	if withinDeadline() {
		members.observeCounts()
	}
	var pids []uint32
	if withinDeadline() {
		pids = members.snapshot()
	}
	for _, pid := range pids {
		if !withinDeadline() {
			break
		}
		members.retain(pid, 0)
	}
	members.fail(members.api.terminate())
	for _, member := range members.held {
		if !withinDeadline() {
			break
		}
		members.fail(members.api.wait(member.handle, deadline))
	}
	if !withinDeadline() {
		return members.fault
	}
	counts := members.observeCounts()
	if !withinDeadline() {
		return members.fault
	}
	remaining := members.snapshot()
	if counts.active != 0 || len(remaining) != 0 || counts.total != uint32(len(members.held)) {
		members.fail(fmt.Errorf("native job lifetime coverage is incomplete"))
	}
	withinDeadline()
	return members.fault
}

func (members *nativeMembers) close() {
	for _, member := range members.held {
		members.api.close(member.handle)
	}
	clear(members.held)
}
