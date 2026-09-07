//go:build windows

package windowsinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

func ownerNativeArgs(mode, directory string) []string {
	return []string{"-test.run=^TestNativeOwnerHelper$", "--", mode, directory}
}
func ownerNativeEnvironment(t *testing.T) []string {
	return append(nativeTestEnvironment(t), "BLENDER_BOX_OWNER_TEST_HELPER=1")
}

// This helper exercises only task-owned native processes and test-local files.
func TestNativeOwnerHelper(t *testing.T) {
	if os.Getenv("BLENDER_BOX_OWNER_TEST_HELPER") != "1" {
		return
	}
	args := os.Args
	separator := -1
	for i, arg := range args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 || len(args) != separator+3 {
		os.Exit(80)
	}
	mode, directory := args[separator+1], args[separator+2]
	switch mode {
	case "mutate", "large-output", "overflow":
		if err := nativeTestRecord(filepath.Join(directory, "worker.json")); err != nil {
			os.Exit(81)
		}
		if err := os.WriteFile(filepath.Join(directory, "mutated"), []byte("declared mutation"), 0600); err != nil {
			os.Exit(82)
		}
		if mode == "large-output" {
			_, _ = os.Stdout.Write([]byte(strings.Repeat("x", 300<<10)))
		}
		if mode == "overflow" {
			_, _ = os.Stdout.Write([]byte(strings.Repeat("x", maxExecutionRecord+1)))
		}
		os.Exit(0)
	case "leaf", "tree":
		if err := nativeTestRecord(filepath.Join(directory, mode+".json")); err != nil {
			os.Exit(83)
		}
		if mode == "tree" {
			child := exec.Command(os.Args[0], ownerNativeArgs("leaf", directory)...)
			child.Env = os.Environ()
			if err := child.Start(); err != nil {
				os.Exit(84)
			}
		} else {
			eventName, err := syscall.UTF16PtrFromString(os.Getenv("BLENDER_BOX_OWNER_TEST_READY"))
			if err != nil {
				os.Exit(85)
			}
			event, _, _ := testOpenEvent.Call(0x00100002, 0, uintptr(unsafe.Pointer(eventName)))
			if event == 0 {
				os.Exit(86)
			}
			testSetEvent.Call(event)
			syscall.CloseHandle(syscall.Handle(event))
		}
		event, _, _ := testCreateEvent.Call(0, 1, 0, 0)
		if event == 0 {
			os.Exit(87)
		}
		_, _ = syscall.WaitForSingleObject(syscall.Handle(event), syscall.INFINITE)
		os.Exit(88)
	case "keeper-loss":
		job, err := newNativeJob()
		if err != nil {
			os.Exit(95)
		}
		null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			os.Exit(96)
		}
		spawn, err := job.startFlags(os.Args[0], ownerNativeArgs("tree", directory), os.Environ(), [3]*os.File{null, null, null}, 0x00000004)
		if err != nil || spawn.Info.Process == 0 {
			os.Exit(97)
		}
		if err := nativeTestRecord(filepath.Join(directory, "keeper.json")); err != nil {
			os.Exit(98)
		}
		if result, _, _ := nativeResumeThread.Call(uintptr(spawn.Info.Thread)); result != 1 {
			os.Exit(99)
		}
		syscall.CloseHandle(spawn.Info.Thread)
		eventName, err := syscall.UTF16PtrFromString(os.Getenv("BLENDER_BOX_OWNER_TEST_LOSS"))
		if err != nil {
			os.Exit(100)
		}
		loss, _, _ := testOpenEvent.Call(0x00100002, 0, uintptr(unsafe.Pointer(eventName)))
		if loss == 0 {
			os.Exit(101)
		}
		if wait, err := syscall.WaitForSingleObject(syscall.Handle(loss), 20000); err != nil || wait != syscall.WAIT_OBJECT_0 {
			os.Exit(102)
		}
		// ExitProcess closes the sole Job handle without publishing terminal proof.
		os.Exit(0)
	case "breakaway", "nested-breakaway":
		null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
		if err != nil {
			os.Exit(89)
		}
		defer null.Close()
		var job *nativeJob
		childMode := "mutate"
		flags := uint32(0x01000000 | 0x00000008 | 0x00000004)
		if mode == "nested-breakaway" {
			job, err = newNativeJob()
			if err != nil {
				os.Exit(90)
			}
			defer job.close()
			limits := nativeExtendedLimits{Basic: nativeBasicLimits{Flags: 0x00002000 | 0x00000800}}
			if ok, _, _ := nativeSetJob.Call(uintptr(job.handle), 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits)); ok == 0 {
				os.Exit(91)
			}
			childMode = "breakaway"
			flags = 0x00000004
		}
		spawn, err := job.startFlags(os.Args[0], ownerNativeArgs(childMode, directory), os.Environ(), [3]*os.File{null, os.Stdout, os.Stderr}, flags)
		if spawn.Info.Process == 0 {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]bool{"detached": false})
			os.Exit(0)
		}
		defer syscall.CloseHandle(spawn.Info.Process)
		defer syscall.CloseHandle(spawn.Info.Thread)
		if err == nil && mode == "breakaway" {
			err = requireDetachedKeeper(spawn.Info.Process)
		}
		if err != nil {
			_ = syscall.TerminateProcess(spawn.Info.Process, 1)
			_, _ = syscall.WaitForSingleObject(spawn.Info.Process, 5000)
			_ = json.NewEncoder(os.Stdout).Encode(map[string]bool{"detached": false})
			os.Exit(0)
		}
		if result, _, _ := nativeResumeThread.Call(uintptr(spawn.Info.Thread)); result == 0xffffffff {
			os.Exit(92)
		}
		if wait, err := syscall.WaitForSingleObject(spawn.Info.Process, 10000); err != nil || wait != syscall.WAIT_OBJECT_0 {
			os.Exit(93)
		}
		if mode == "breakaway" {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]bool{"detached": true})
		}
		os.Exit(0)
	}
	os.Exit(94)
}

func TestNativeOwnerGatePublishesBeforeWorkerMutation(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint(reject), func(t *testing.T) {
			directory := t.TempDir()
			executable, _ := os.Executable()
			admitted, exited := false, false
			_, err := runNativeJobGated(context.Background(), executable, ownerNativeArgs("mutate", directory), nil, ownerNativeEnvironment(t), &nativeRunGate{
				Admit: func(spawn nativeSpawn) error {
					if _, err := os.Stat(filepath.Join(directory, "mutated")); !os.IsNotExist(err) {
						t.Error("worker mutated before ownership receipt")
					}
					identity := processIdentity(spawn.Info.ProcessId, spawn.Created)
					if !identity.valid() {
						return fmt.Errorf("missing exact native identity")
					}
					admitted = true
					if reject {
						return fmt.Errorf("receipt publication refused")
					}
					return publishExecutionJSON(filepath.Join(directory, "ownership.json"), directory, identity, nil)
				},
				TreeExited: func(spawn nativeSpawn) { exited = true },
			})
			if !admitted {
				t.Fatal("ownership callback absent")
			}
			_, mutationErr := os.Stat(filepath.Join(directory, "mutated"))
			if reject {
				if err == nil || errors.Is(err, errNativeCleanupUnknown) || !os.IsNotExist(mutationErr) {
					t.Fatalf("rejected gate mutated or cleanup unknown: %v", err)
				}
			} else if err != nil || !exited || mutationErr != nil {
				t.Fatalf("owned mutation=%v exit=%v", err, exited)
			}
		})
	}
}

func TestNativeOwnerOutputUsesExecutionBound(t *testing.T) {
	for _, mode := range []string{"large-output", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			executable, _ := os.Executable()
			exited := false
			output, err := runNativeJobGated(context.Background(), executable, ownerNativeArgs(mode, t.TempDir()), nil, ownerNativeEnvironment(t), &nativeRunGate{
				Admit: func(nativeSpawn) error { return nil }, TreeExited: func(nativeSpawn) { exited = true },
			})
			if !exited {
				t.Fatal("output failure lost exact tree-exit proof")
			}
			if mode == "large-output" && (err != nil || len(output) != 300<<10) {
				t.Fatalf("valid execution output rejected: len=%d err=%v", len(output), err)
			}
			if mode == "overflow" && (err == nil || errors.Is(err, errNativeCleanupUnknown)) {
				t.Fatalf("overflow cleanup=%v", err)
			}
		})
	}
}

func TestNativeOwnerSelfDeadlineSettlesNestedDescendants(t *testing.T) {
	directory := t.TempDir()
	id, _ := newID("owner-deadline-")
	eventName := `Local\BlenderBox-` + id
	pointer, _ := syscall.UTF16PtrFromString(eventName)
	event, _, err := testCreateEvent.Call(0, 1, 0, uintptr(unsafe.Pointer(pointer)))
	if event == 0 {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(syscall.Handle(event))
	executable, _ := os.Executable()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	done := make(chan error, 1)
	exited := make(chan struct{}, 1)
	go func() {
		_, err := runNativeJobGated(ctx, executable, ownerNativeArgs("tree", directory), nil, append(ownerNativeEnvironment(t), "BLENDER_BOX_OWNER_TEST_READY="+eventName), &nativeRunGate{
			Admit: func(nativeSpawn) error { return nil }, TreeExited: func(nativeSpawn) { exited <- struct{}{} },
		})
		done <- err
	}()
	if ready, err := syscall.WaitForSingleObject(syscall.Handle(event), 10000); err != nil || ready != syscall.WAIT_OBJECT_0 {
		t.Fatalf("nested child readiness=%d err=%v", ready, err)
	}
	if err := <-done; !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errNativeCleanupUnknown) {
		t.Fatalf("deadline did not settle tree: %v", err)
	}
	select {
	case <-exited:
	default:
		t.Fatal("deadline lacks retained Job tree proof")
	}
}

func TestNativeKeeperBreakawayRequiresLeavingEveryAncestorJob(t *testing.T) {
	self, _ := syscall.GetCurrentProcess()
	if err := requireDetachedKeeper(self); err != nil {
		t.Skip("native breakaway fixture requires a test runner outside ambient Jobs")
	}
	for _, mode := range []string{"allowed", "denied", "nested"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			job, err := newNativeJob()
			if err != nil {
				t.Fatal(err)
			}
			defer job.close()
			if mode == "allowed" {
				limits := nativeExtendedLimits{Basic: nativeBasicLimits{Flags: 0x00002000 | 0x00000800}}
				if ok, _, err := nativeSetJob.Call(uintptr(job.handle), 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits)); ok == 0 {
					t.Fatal(err)
				}
			}
			null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer null.Close()
			read, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer read.Close()
			defer write.Close()
			executable, _ := os.Executable()
			helperMode := "breakaway"
			if mode == "nested" {
				helperMode = "nested-breakaway"
			}
			spawn, err := job.start(executable, ownerNativeArgs(helperMode, directory), ownerNativeEnvironment(t), [3]*os.File{null, write, null})
			_ = write.Close()
			if spawn.Info.Process == 0 {
				t.Fatal(err)
			}
			defer syscall.CloseHandle(spawn.Info.Process)
			defer syscall.CloseHandle(spawn.Info.Thread)
			defer job.terminateAndWait()
			if err != nil {
				t.Fatal(err)
			}
			if wait, err := syscall.WaitForSingleObject(spawn.Info.Process, 15000); err != nil || wait != syscall.WAIT_OBJECT_0 {
				t.Fatalf("breakaway fixture wait=%d err=%v", wait, err)
			}
			var result struct {
				Detached bool `json:"detached"`
			}
			if err := json.NewDecoder(read).Decode(&result); err != nil {
				t.Fatal(err)
			}
			if result.Detached != (mode == "allowed") {
				t.Fatalf("breakaway %s detached=%v", mode, result.Detached)
			}
			_, mutationErr := os.Stat(filepath.Join(directory, "mutated"))
			if mode != "allowed" && !os.IsNotExist(mutationErr) {
				t.Fatal("blocked keeper mutated before leaving all Jobs")
			}
		})
	}
}

func TestNativeNoStartProofRequiresFailedSpawn(t *testing.T) {
	started, notStarted := false, false
	_, err := runNativeJobGated(context.Background(), filepath.Join(t.TempDir(), "missing.exe"), nil, nil, ownerNativeEnvironment(t), &nativeRunGate{
		Admit:      func(nativeSpawn) error { started = true; return nil },
		NotStarted: func() { notStarted = true },
		TreeExited: func(nativeSpawn) { t.Error("failed spawn invented process-tree proof") },
	})
	if err == nil || started || !notStarted || errors.Is(err, errNativeCleanupUnknown) {
		t.Fatalf("failed spawn proof started=%v notStarted=%v err=%v", started, notStarted, err)
	}
}

func TestNativeKeeperLossKillsOwnedTreeWithoutPublishingTerminalProof(t *testing.T) {
	directory := t.TempDir()
	event := func(prefix string) (string, syscall.Handle) {
		id, _ := newID(prefix)
		name := `Local\BlenderBox-` + id
		pointer, _ := syscall.UTF16PtrFromString(name)
		handle, _, err := testCreateEvent.Call(0, 1, 0, uintptr(unsafe.Pointer(pointer)))
		if handle == 0 {
			t.Fatal(err)
		}
		t.Cleanup(func() { syscall.CloseHandle(syscall.Handle(handle)) })
		return name, syscall.Handle(handle)
	}
	readyName, ready := event("owner-ready-")
	lossName, loss := event("owner-loss-")
	environment := append(ownerNativeEnvironment(t), "BLENDER_BOX_OWNER_TEST_READY="+readyName, "BLENDER_BOX_OWNER_TEST_LOSS="+lossName)
	outer, err := newNativeJob()
	if err != nil {
		t.Fatal(err)
	}
	defer outer.close()
	defer outer.terminateAndWait()
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	executable, _ := os.Executable()
	keeper, err := outer.start(executable, ownerNativeArgs("keeper-loss", directory), environment, [3]*os.File{null, null, null})
	if keeper.Info.Process == 0 {
		t.Fatal(err)
	}
	defer syscall.CloseHandle(keeper.Info.Process)
	defer syscall.CloseHandle(keeper.Info.Thread)
	if err != nil {
		t.Fatal(err)
	}
	if wait, err := syscall.WaitForSingleObject(ready, 15000); err != nil || wait != syscall.WAIT_OBJECT_0 {
		t.Fatalf("owned tree readiness=%d %v", wait, err)
	}
	children := []syscall.Handle{}
	for _, name := range []string{"tree.json", "leaf.json"} {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			t.Fatal(err)
		}
		var record nativeTestProcess
		if err := json.Unmarshal(data, &record); err != nil {
			t.Fatal(err)
		}
		process, err := syscall.OpenProcess(syscall.SYNCHRONIZE|0x1000, false, uint32(record.PID))
		if err != nil {
			t.Fatal(err)
		}
		defer syscall.CloseHandle(process)
		var created, exited, kernel, user syscall.Filetime
		if err := syscall.GetProcessTimes(process, &created, &exited, &kernel, &user); err != nil || created != record.Created {
			t.Fatal("fixture process identity changed", err)
		}
		children = append(children, process)
	}
	if ok, _, err := testSetEvent.Call(uintptr(loss)); ok == 0 {
		t.Fatal(err)
	}
	if wait, err := syscall.WaitForSingleObject(keeper.Info.Process, 10000); err != nil || wait != syscall.WAIT_OBJECT_0 {
		t.Fatalf("keeper exit=%d %v", wait, err)
	}
	for _, child := range children {
		if wait, err := syscall.WaitForSingleObject(child, 5000); err != nil || wait != syscall.WAIT_OBJECT_0 {
			t.Fatalf("owned child survived keeper death=%d %v", wait, err)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, "terminal.json")); !os.IsNotExist(err) {
		t.Fatal("keeper loss fabricated terminal proof")
	}
}
