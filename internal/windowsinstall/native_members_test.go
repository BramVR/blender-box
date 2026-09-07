package windowsinstall

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

type memberFixtureProcess struct {
	created  uint64
	visible  bool
	signaled bool
}

type memberFixture struct {
	processes       map[uint32]*memberFixtureProcess
	handles         map[uintptr]*memberFixtureProcess
	nextHandle      uintptr
	total           uint32
	openErr         error
	countErrors     []error
	countsErr       error
	listErr         error
	terminateErr    error
	waitErr         error
	countResults    []nativeJobCounts
	partial         bool
	onTerminate     func()
	terminations    int
	closed          int
	now             time.Time
	waitDuration    time.Duration
	waitedDeadlines []time.Time
}

func newMemberFixture() *memberFixture {
	return &memberFixture{processes: make(map[uint32]*memberFixtureProcess), handles: make(map[uintptr]*memberFixtureProcess), now: time.Now()}
}

func (fixture *memberFixture) add(pid uint32) {
	fixture.total++
	fixture.processes[pid] = &memberFixtureProcess{created: uint64(pid) + 1000, visible: true}
}

func (fixture *memberFixture) open(pid uint32) (nativeMember, error) {
	if fixture.openErr != nil {
		return nativeMember{}, fixture.openErr
	}
	process := fixture.processes[pid]
	if process == nil {
		return nativeMember{}, fmt.Errorf("process disappeared")
	}
	fixture.nextHandle++
	fixture.handles[fixture.nextHandle] = process
	return nativeMember{fixture.nextHandle, pid, process.created}, nil
}

func (fixture *memberFixture) close(handle uintptr) {
	delete(fixture.handles, handle)
	fixture.closed++
}

func (fixture *memberFixture) counts() (nativeJobCounts, error) {
	err := fixture.countsErr
	if len(fixture.countErrors) > 0 {
		err = fixture.countErrors[0]
		fixture.countErrors = fixture.countErrors[1:]
	}
	if len(fixture.countResults) > 0 {
		result := fixture.countResults[0]
		fixture.countResults = fixture.countResults[1:]
		return result, err
	}
	var active uint32
	for _, process := range fixture.processes {
		if process.visible {
			active++
		}
	}
	return nativeJobCounts{fixture.total, active}, err
}

func (fixture *memberFixture) list() (nativeMemberList, error) {
	var result nativeMemberList
	for pid, process := range fixture.processes {
		if process.visible {
			result.pids = append(result.pids, pid)
		}
	}
	result.assigned = uint32(len(result.pids))
	if fixture.partial {
		result.assigned++
	}
	return result, fixture.listErr
}

func (fixture *memberFixture) terminate() error {
	fixture.terminations++
	if fixture.onTerminate != nil {
		fixture.onTerminate()
	}
	for _, process := range fixture.processes {
		process.visible = false
	}
	return fixture.terminateErr
}

func (fixture *memberFixture) wait(handle uintptr, deadline time.Time) error {
	fixture.waitedDeadlines = append(fixture.waitedDeadlines, deadline)
	if fixture.waitErr != nil {
		return fixture.waitErr
	}
	remaining := deadline.Sub(fixture.now)
	if remaining < fixture.waitDuration {
		fixture.now = deadline
		return fmt.Errorf("process wait timed out")
	}
	fixture.now = fixture.now.Add(fixture.waitDuration)
	fixture.handles[handle].signaled = true
	return nil
}

func TestNativeMembersRetainExitedObjectsAndIgnoreDuplicateHints(t *testing.T) {
	fixture := newMemberFixture()
	fixture.add(1)
	fixture.add(2)
	members := newNativeMembers(fixture)
	members.retain(1, fixture.processes[1].created)
	members.event(6, 1)
	members.event(6, 2)
	fixture.openErr = errors.New("exited object cannot be reopened")
	members.event(6, 2)
	fixture.processes[2].visible = false
	fixture.processes[2].signaled = true
	members.event(7, 2)
	if err := members.settle(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(members.held) != 2 || len(fixture.handles) != 2 || fixture.terminations != 1 || !fixture.processes[1].signaled {
		t.Fatalf("incomplete retained cleanup: held=%d handles=%d termination=%d", len(members.held), len(fixture.handles), fixture.terminations)
	}
	members.close()
	if len(fixture.handles) != 0 {
		t.Fatal("retained process handles leaked")
	}
}

func TestNativeMembersMissingHintsRequireCompleteLifetimeCoverage(t *testing.T) {
	for _, mode := range []string{"still-present", "early-disappeared", "late-assignment"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newMemberFixture()
			fixture.add(1)
			members := newNativeMembers(fixture)
			defer members.close()
			members.retain(1, fixture.processes[1].created)
			if mode == "late-assignment" {
				fixture.onTerminate = func() { fixture.add(2) }
			} else {
				fixture.add(2)
				fixture.processes[2].visible = mode == "still-present"
			}
			err := members.settle(time.Now().Add(time.Second))
			if mode == "still-present" {
				if err != nil || !fixture.processes[2].signaled {
					t.Fatalf("complete cleanup capture did not settle child: %v", err)
				}
			} else if !errors.Is(err, errNativeCleanupUnknown) || fixture.processes[2].signaled {
				t.Fatalf("unobserved child was falsely settled: %v", err)
			}
		})
	}
}

func TestNativeMembersBoundaryFailuresStayUnknown(t *testing.T) {
	for _, failure := range []string{"open", "membership", "creation", "partial-list", "list-error", "counts-error", "terminate", "wait"} {
		t.Run(failure, func(t *testing.T) {
			fixture := newMemberFixture()
			fixture.add(1)
			members := newNativeMembers(fixture)
			defer members.close()
			cause := errors.New(failure)
			switch failure {
			case "open", "membership":
				fixture.openErr = cause
			case "creation":
				members.retain(1, fixture.processes[1].created+1)
			case "partial-list":
				fixture.partial = true
			case "list-error":
				fixture.listErr = cause
			case "counts-error":
				fixture.countsErr = cause
			case "terminate":
				fixture.terminateErr = cause
			case "wait":
				fixture.waitErr = cause
			}
			if err := members.settle(time.Now().Add(time.Second)); !errors.Is(err, errNativeCleanupUnknown) {
				t.Fatalf("boundary failure acknowledged cleanup: %v", err)
			}
			if fixture.terminations != 1 {
				t.Fatalf("cleanup dispatched %d terminations", fixture.terminations)
			}
		})
	}
}

func TestNativeMembersCoverageFaultCannotBeRepairedByLaterSuccess(t *testing.T) {
	fixture := newMemberFixture()
	fixture.add(1)
	members := newNativeMembers(fixture)
	defer members.close()
	fixture.openErr = errors.New("first identity unavailable")
	members.event(6, 1)
	fixture.openErr = nil
	if err := members.settle(time.Now().Add(time.Second)); !errors.Is(err, errNativeCleanupUnknown) || !fixture.processes[1].signaled {
		t.Fatalf("sticky failure lost or cleanup not attempted: %v", err)
	}
}

func TestNativeMembersRejectChangedPinnedCreation(t *testing.T) {
	fixture := newMemberFixture()
	fixture.add(1)
	members := newNativeMembers(fixture)
	defer members.close()
	members.event(6, 1)
	members.retain(1, 999)
	if !errors.Is(members.fault, errNativeCleanupUnknown) || len(members.held) != 1 || len(fixture.handles) != 1 {
		t.Fatal("conflicting PID hint replaced pinned object")
	}
}

func TestNativeMembersReusedUnpinnedPIDDoesNotFillLifetimeGap(t *testing.T) {
	fixture := newMemberFixture()
	fixture.add(1)
	fixture.add(2)
	fixture.processes[2].visible = false
	fixture.processes[2].signaled = true
	members := newNativeMembers(fixture)
	defer members.close()
	members.retain(1, fixture.processes[1].created)
	fixture.add(2)
	fixture.processes[2].created++
	members.event(6, 2)
	if err := members.settle(time.Now().Add(time.Second)); !errors.Is(err, errNativeCleanupUnknown) {
		t.Fatalf("replacement PID filled an unseen historical object: %v", err)
	}
	if len(members.held) != 2 || fixture.total != 3 || !fixture.processes[2].signaled {
		t.Fatal("replacement member was not retained and settled independently")
	}
}

func TestNativeMembersSeedRequiresExactRecordedRoot(t *testing.T) {
	for _, mode := range []string{"missing-creation", "changed-creation", "open-failure", "valid"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newMemberFixture()
			fixture.add(1)
			created := fixture.processes[1].created
			switch mode {
			case "missing-creation":
				created = 0
			case "changed-creation":
				created++
			case "open-failure":
				fixture.openErr = errors.New("root query denied")
			}
			members := newNativeMembers(fixture)
			defer members.close()
			err := members.seed(1, created)
			if mode == "valid" {
				if err != nil || len(members.held) != 1 {
					t.Fatalf("exact root was not retained: %v", err)
				}
			} else if !errors.Is(err, errNativeCleanupUnknown) || len(members.held) != 0 || len(fixture.handles) != 0 {
				t.Fatalf("unverified root admitted: error=%v members=%d handles=%d", err, len(members.held), len(fixture.handles))
			}
		})
	}
}

func TestNativeMembersRejectMalformedCompletion(t *testing.T) {
	for _, event := range []struct {
		message uint32
		pid     uintptr
	}{{6, 0}, {7, 0}, {4, 1}, {99, 1}} {
		members := newNativeMembers(newMemberFixture())
		if members.event(event.message, event.pid) || !errors.Is(members.fault, errNativeCleanupUnknown) {
			t.Fatalf("malformed completion was accepted: %+v", event)
		}
	}
}

func TestNativeMembersRejectInvalidAccounting(t *testing.T) {
	for _, counts := range [][]nativeJobCounts{
		{{2, 1}, {1, 0}},
		{{nativeMemberLimit + 1, 1}},
		{{1, 2}},
		{{1, 1}, {2, 0}},
		{{1, 1}, {1, 1}},
	} {
		fixture := newMemberFixture()
		fixture.add(1)
		fixture.countResults = counts
		members := newNativeMembers(fixture)
		if err := members.settle(time.Now().Add(time.Second)); !errors.Is(err, errNativeCleanupUnknown) {
			t.Fatalf("invalid accounting acknowledged cleanup: %+v", counts)
		}
		members.close()
	}
}

func TestNativeMembersBoundRetainedObjectsAndEvents(t *testing.T) {
	fixture := newMemberFixture()
	members := newNativeMembers(fixture)
	defer members.close()
	for pid := uint32(1); pid <= nativeMemberLimit+1; pid++ {
		fixture.add(pid)
		members.retain(pid, 0)
	}
	if len(members.held) != nativeMemberLimit || len(fixture.handles) != nativeMemberLimit || !errors.Is(members.fault, errNativeCleanupUnknown) {
		t.Fatal("retained member bound was not enforced")
	}
	events := newNativeMembers(newMemberFixture())
	for i := 0; i < nativeEventLimit; i++ {
		if !events.event(4, 0) {
			t.Fatal("event budget ended too early")
		}
	}
	if events.event(4, 0) || !errors.Is(events.fault, errNativeCleanupUnknown) {
		t.Fatal("event budget did not end collection")
	}
}

func TestNativeMembersWaitsConsumeOneDeadline(t *testing.T) {
	fixture := newMemberFixture()
	fixture.add(1)
	fixture.add(2)
	fixture.waitDuration = 4 * time.Second
	deadline := fixture.now.Add(5 * time.Second)
	members := newNativeMembers(fixture)
	defer members.close()
	if err := members.settle(deadline); !errors.Is(err, errNativeCleanupUnknown) {
		t.Fatalf("member waits reset their deadline: %v", err)
	}
	signaled := 0
	for _, process := range fixture.processes {
		if process.signaled {
			signaled++
		}
	}
	if signaled != 1 || !fixture.now.Equal(deadline) {
		t.Fatalf("wait budget was not shared: signaled=%d elapsed=%s", signaled, fixture.now.Sub(deadline.Add(-5*time.Second)))
	}
	for _, observed := range fixture.waitedDeadlines {
		if observed != deadline {
			t.Fatal("member received a replacement deadline")
		}
	}
}

func TestNativeMembersExpiredCaptureStillTerminatesWithoutAcknowledgment(t *testing.T) {
	fixture := newMemberFixture()
	fixture.add(1)
	members := newNativeMembers(fixture)
	defer members.close()
	if err := members.settle(time.Now().Add(-time.Second)); !errors.Is(err, errNativeCleanupUnknown) || fixture.terminations != 1 || len(members.held) != 0 {
		t.Fatalf("expired capture was accepted or termination skipped: %v", err)
	}
}

func TestNativeMembersFailedStartProof(t *testing.T) {
	for _, mode := range []string{"zero-history", "observed-total-one-active-zero", "partial-identity", "transient-accounting-error", "success-without-process", "retained-members", "terminate-error", "wait-error", "wait-budget-exhausted", "expired-deadline"} {
		t.Run(mode, func(t *testing.T) {
			fixture := newMemberFixture()
			startErr := errors.New("original start failure")
			cause := errors.New("boundary failure")
			hasIdentity := false
			deadline := fixture.now.Add(time.Second)
			switch mode {
			case "observed-total-one-active-zero":
				fixture.total = 1
			case "partial-identity":
				hasIdentity = true
			case "transient-accounting-error":
				fixture.countErrors = []error{cause, nil, nil}
			case "success-without-process":
				startErr = nil
			case "retained-members", "wait-error", "wait-budget-exhausted":
				fixture.add(1)
				fixture.add(2)
				if mode == "wait-error" {
					fixture.waitErr = cause
				}
				if mode == "wait-budget-exhausted" {
					fixture.waitDuration = 4 * time.Second
					deadline = fixture.now.Add(5 * time.Second)
				}
			case "terminate-error":
				hasIdentity = true
				fixture.terminateErr = cause
			case "expired-deadline":
				deadline = fixture.now.Add(-time.Second)
			}
			members := newNativeMembers(fixture)
			defer members.close()
			notStarted, err := members.settleFailedStart(hasIdentity, startErr, deadline)
			if mode == "zero-history" {
				if !notStarted || err != startErr || fixture.terminations != 0 || len(fixture.handles) != 0 {
					t.Fatalf("zero-history proof lost: notStarted=%v err=%v terminations=%d", notStarted, err, fixture.terminations)
				}
				return
			}
			if notStarted || !errors.Is(err, errNativeCleanupUnknown) || fixture.terminations != 1 {
				t.Fatalf("unproved failed start acknowledged: notStarted=%v err=%v terminations=%d", notStarted, err, fixture.terminations)
			}
			if startErr != nil && !errors.Is(err, startErr) {
				t.Fatalf("original start error lost: %v", err)
			}
			if mode == "transient-accounting-error" || mode == "terminate-error" || mode == "wait-error" {
				if !errors.Is(err, cause) {
					t.Fatalf("boundary cause lost after settlement: %v", err)
				}
			}
			if mode == "wait-budget-exhausted" {
				signaled := 0
				for _, process := range fixture.processes {
					if process.signaled {
						signaled++
					}
				}
				if signaled != 1 || !fixture.now.Equal(deadline) || len(fixture.waitedDeadlines) != 2 {
					t.Fatal("failed-start member waits did not consume one deadline")
				}
			}
			if mode == "retained-members" {
				if len(fixture.waitedDeadlines) != 2 || !fixture.processes[1].signaled || !fixture.processes[2].signaled {
					t.Fatal("retained members were not waited")
				}
				for _, observed := range fixture.waitedDeadlines {
					if observed != deadline {
						t.Fatal("retained member received a replacement deadline")
					}
				}
				members.close()
				if fixture.closed != 2 || len(fixture.handles) != 0 {
					t.Fatal("retained member handles leaked")
				}
			}
		})
	}
}
