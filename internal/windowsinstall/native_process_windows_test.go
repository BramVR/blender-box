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
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

var testProcessKernel = syscall.NewLazyDLL("kernel32.dll")
var testCreateEvent = testProcessKernel.NewProc("CreateEventW")
var testOpenEvent = testProcessKernel.NewProc("OpenEventW")
var testSetEvent = testProcessKernel.NewProc("SetEvent")
var testResetEvent = testProcessKernel.NewProc("ResetEvent")
var testQueryProcessImage = testProcessKernel.NewProc("QueryFullProcessImageNameW")

type nativeTestProcess struct {
	PID        int
	ParentPID  int
	Executable string
	Created    syscall.Filetime
}

func nativeTestEnvironment(t *testing.T) []string {
	t.Helper()
	environment, err := cleanEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	return environment
}

func nativeTestRecord(path string) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return err
	}
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(process, &created, &exited, &kernel, &user); err != nil {
		return err
	}
	data, err := json.Marshal(nativeTestProcess{os.Getpid(), os.Getppid(), executable, created})
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func TestNativeProcessHelper(t *testing.T) {
	if os.Getenv("BLENDER_BOX_NATIVE_TEST_HELPER") != "1" {
		return
	}
	separator := 0
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i + 1
			break
		}
	}
	if separator == 0 || len(os.Args[separator:]) != 3 {
		os.Exit(90)
	}
	mode, eventName, directory := os.Args[separator], os.Args[separator+1], os.Args[separator+2]
	if mode == "exit-7" {
		os.Exit(7)
	}
	if mode == "environment" {
		cwd, err := os.Getwd()
		if err != nil {
			os.Exit(93)
		}
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"state": os.Getenv("BLENDERSESSIOND_STATE_DIR"), "value": os.Getenv("BLENDER_BOX_NATIVE_TEST_VALUE"), "cwd": cwd, "path": os.Getenv("PATH"), "system_root": os.Getenv("SystemRoot"), "windir": os.Getenv("WINDIR")})
		os.Exit(0)
	}
	if mode == "exit-0" {
		os.Exit(0)
	}
	name, err := syscall.UTF16PtrFromString(eventName)
	if err != nil {
		os.Exit(91)
	}
	event, _, _ := testOpenEvent.Call(0x00100002, 0, uintptr(unsafe.Pointer(name)))
	if event == 0 {
		os.Exit(92)
	}
	defer syscall.CloseHandle(syscall.Handle(event))
	if mode == "probe-root" {
		if nativeTestRecord(filepath.Join(directory, "root.json")) != nil {
			os.Exit(95)
		}
		if ok, _, _ := testSetEvent.Call(event); ok == 0 {
			os.Exit(94)
		}
		var release [1]byte
		if _, err := os.Stdin.Read(release[:]); err != nil {
			os.Exit(100)
		}
		os.Exit(0)
	}
	if mode == "leaf" || mode == "early-leaf" {
		if nativeTestRecord(filepath.Join(directory, "leaf.json")) != nil {
			os.Exit(93)
		}
		if ok, _, _ := testSetEvent.Call(event); ok == 0 {
			os.Exit(94)
		}
		if mode == "early-leaf" {
			exitName, _ := syscall.UTF16PtrFromString(eventName + "-exit")
			exitEvent, _, _ := testOpenEvent.Call(syscall.SYNCHRONIZE, 0, uintptr(unsafe.Pointer(exitName)))
			if exitEvent == 0 {
				os.Exit(101)
			}
			wait, err := syscall.WaitForSingleObject(syscall.Handle(exitEvent), 10000)
			syscall.CloseHandle(syscall.Handle(exitEvent))
			if err != nil || wait != syscall.WAIT_OBJECT_0 {
				os.Exit(102)
			}
			os.Exit(0)
		}
	} else {
		if nativeTestRecord(filepath.Join(directory, "root.json")) != nil {
			os.Exit(95)
		}
		if mode == "probe-late" {
			if ok, _, _ := testSetEvent.Call(event); ok == 0 {
				os.Exit(94)
			}
			var create [1]byte
			if _, err := os.Stdin.Read(create[:]); err != nil {
				os.Exit(100)
			}
		}
		childMode := "leaf"
		if mode == "probe-early" {
			childMode = "early-leaf"
		}
		child := exec.Command(os.Args[0], "-test.run=^TestNativeProcessHelper$", "--", childMode, eventName, directory)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(96)
		}
		if got, err := syscall.WaitForSingleObject(syscall.Handle(event), 10000); err != nil || got != syscall.WAIT_OBJECT_0 {
			os.Exit(97)
		}
		if mode == "probe-parent" || mode == "probe-late" || mode == "probe-early" {
			var release [1]byte
			if _, err := os.Stdin.Read(release[:]); err != nil {
				os.Exit(100)
			}
			os.Exit(0)
		}
		if mode == "parent-exits" {
			os.Exit(0)
		}
		if mode == "overflow" {
			_, _ = os.Stdout.Write([]byte(strings.Repeat("x", 512<<10)))
		}
	}
	blocked, _, _ := testCreateEvent.Call(0, 1, 0, 0)
	if blocked == 0 {
		os.Exit(98)
	}
	_, _ = syscall.WaitForSingleObject(syscall.Handle(blocked), syscall.INFINITE)
	os.Exit(99)
}

func TestNativeOperationSettlesOwnedDescendants(t *testing.T) {
	for _, mode := range []string{"cancel", "parent-exits", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			id, err := newID("native-test-")
			if err != nil {
				t.Fatal(err)
			}
			eventName := `Local\BlenderBox-` + id
			name, _ := syscall.UTF16PtrFromString(eventName)
			event, _, callErr := testCreateEvent.Call(0, 1, 0, uintptr(unsafe.Pointer(name)))
			if event == 0 {
				t.Fatal(callErr)
			}
			defer syscall.CloseHandle(syscall.Handle(event))
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				_, err := runNative(ctx, executable, []string{"-test.run=^TestNativeProcessHelper$", "--", mode, eventName, directory}, nil, append(nativeTestEnvironment(t), "BLENDER_BOX_NATIVE_TEST_HELPER=1"))
				done <- err
			}()
			if got, err := syscall.WaitForSingleObject(syscall.Handle(event), 10000); err != nil || got != syscall.WAIT_OBJECT_0 {
				t.Fatalf("child readiness=%d error=%v", got, err)
			}
			read := func(name string) nativeTestProcess {
				data, err := os.ReadFile(filepath.Join(directory, name))
				if err != nil {
					t.Fatal(err)
				}
				var record nativeTestProcess
				if err := json.Unmarshal(data, &record); err != nil {
					t.Fatal(err)
				}
				if !strings.EqualFold(record.Executable, executable) || record.PID <= 0 {
					t.Fatal("invalid task-owned spawn receipt")
				}
				return record
			}
			root, leaf := read("root.json"), read("leaf.json")
			if leaf.ParentPID != root.PID || root.ParentPID != os.Getpid() {
				t.Fatal("helper parent identity changed")
			}
			child, err := syscall.OpenProcess(syscall.SYNCHRONIZE|0x1000|syscall.PROCESS_TERMINATE, false, uint32(leaf.PID))
			if err != nil {
				if mode != "cancel" && errors.Is(err, syscall.Errno(87)) {
					select {
					case err = <-done:
					case <-ctx.Done():
						t.Fatal("native cleanup did not finish")
					}
					if err == nil {
						t.Fatal("native operation left descendants without an error")
					}
					return
				}
				t.Fatal(err)
			}
			defer syscall.CloseHandle(child)
			var created, exited, kernel, user syscall.Filetime
			if err := syscall.GetProcessTimes(child, &created, &exited, &kernel, &user); err != nil || created != leaf.Created {
				t.Fatalf("child spawn identity mismatch: %v", err)
			}
			defer func() {
				if got, _ := syscall.WaitForSingleObject(child, 0); got == syscall.WAIT_TIMEOUT {
					_ = syscall.TerminateProcess(child, 101)
					_, _ = syscall.WaitForSingleObject(child, 5000)
				}
			}()
			if mode == "cancel" {
				cancel()
			}
			select {
			case err = <-done:
			case <-time.After(7 * time.Second):
				t.Fatal("native cleanup did not finish")
			}
			if err == nil {
				t.Fatal("native operation left descendants without an error")
			}
			operationErr := err
			if got, waitErr := syscall.WaitForSingleObject(child, 0); waitErr != nil || got != syscall.WAIT_OBJECT_0 {
				later, laterErr := syscall.WaitForSingleObject(child, uint32(nativeCleanupTimeout/time.Millisecond))
				t.Fatalf("owned descendant survives native return: wait=%d error=%v operation_error=%v cleanup_unknown=%t later_wait=%d later_error=%v", got, waitErr, operationErr, errors.Is(operationErr, errNativeCleanupUnknown), later, laterErr)
			}
		})
	}
}

func TestNativeOperationPreservesExitError(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	_, err = runNative(context.Background(), executable, []string{"-test.run=^TestNativeProcessHelper$", "--", "exit-7", "unused", t.TempDir()}, nil, append(nativeTestEnvironment(t), "BLENDER_BOX_NATIVE_TEST_HELPER=1"))
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 {
		t.Fatalf("native exit error=%v", err)
	}
}

func TestNativeOperationWithoutDescendantsSucceeds(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runNative(context.Background(), executable, []string{"-test.run=^TestNativeProcessHelper$", "--", "exit-0", "unused", t.TempDir()}, nil, append(nativeTestEnvironment(t), "BLENDER_BOX_NATIVE_TEST_HELPER=1")); err != nil {
		t.Fatal(err)
	}
}

func TestNativeOperationCanceledBeforeStartCreatesNothing(t *testing.T) {
	directory := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := runNative(ctx, executable, []string{"-test.run=^TestNativeProcessHelper$", "--", "cancel", "unused", directory}, nil, append(nativeTestEnvironment(t), "BLENDER_BOX_NATIVE_TEST_HELPER=1")); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled native operation: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("pre-canceled operation created process records: %v %v", entries, err)
	}
}

func TestNativePowerShellUTF8RoundTrip(t *testing.T) {
	want := "Données 日本語 🎨"
	data, err := powerShell(context.Background(), `$r | ConvertTo-Json -Compress`, map[string]string{"value": want})
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]string
	if err := json.Unmarshal(data, &result); err != nil || result["value"] != want {
		t.Fatal(fmt.Sprintf("UTF8 result=%q error=%v", data, err))
	}
}

func TestNativeOperationPreservesEnvironment(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	system, err := systemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	t.Setenv("SystemRoot", t.TempDir())
	t.Setenv("WINDIR", t.TempDir())
	environment := append(nativeTestEnvironment(t), "BLENDER_BOX_NATIVE_TEST_HELPER=1", "BLENDER_BOX_NATIVE_TEST_VALUE=日本語 🎨=value")
	filtered := environment[:0]
	for _, entry := range environment {
		if !strings.HasPrefix(strings.ToUpper(entry), "BLENDERSESSIOND_STATE_DIR=") {
			filtered = append(filtered, entry)
		}
	}
	environment = append(filtered, `BLENDERSESSIOND_STATE_DIR=C:\PrivateFixture`)
	data, err := runNative(context.Background(), executable, []string{"-test.run=^TestNativeProcessHelper$", "--", "environment", "unused", t.TempDir()}, nil, environment)
	if err != nil {
		t.Fatal(err)
	}
	var observed map[string]string
	if err := json.Unmarshal(data, &observed); err != nil || observed["state"] != `C:\PrivateFixture` || observed["value"] != "日本語 🎨=value" {
		t.Fatalf("native environment=%q error=%v", data, err)
	}
	if !strings.EqualFold(observed["cwd"], filepath.Dir(executable)) || observed["path"] != system || observed["system_root"] != filepath.Dir(system) || observed["windir"] != filepath.Dir(system) {
		t.Fatalf("unsafe native startup environment=%q", data)
	}
}

func TestPowerShellIgnoresInheritedSystemRoot(t *testing.T) {
	system, err := systemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", t.TempDir())
	t.Setenv("SystemRoot", t.TempDir())
	t.Setenv("WINDIR", t.TempDir())
	t.Setenv("PSModulePath", t.TempDir())
	data, err := powerShell(context.Background(), `$null=Get-Acl -LiteralPath $PSHOME
[ordered]@{path=$env:PATH;root=$env:SystemRoot;cwd=[Environment]::CurrentDirectory;modules=$env:PSModulePath}|ConvertTo-Json -Compress`, struct{}{})
	if err != nil {
		t.Fatal(err)
	}
	var observed map[string]string
	if err := json.Unmarshal(data, &observed); err != nil || observed["path"] != system || observed["root"] != filepath.Dir(system) || !strings.EqualFold(observed["cwd"], filepath.Join(system, "WindowsPowerShell", "v1.0")) {
		t.Fatalf("unsafe PowerShell startup=%q error=%v", data, err)
	}
	if !strings.EqualFold(observed["modules"], filepath.Join(system, "WindowsPowerShell", "v1.0", "Modules")) {
		t.Fatalf("unsafe PowerShell module path=%q", data)
	}
}

func TestNativeJobCompletionObservations(t *testing.T) {
	for _, flags := range []struct {
		name  string
		value uint32
	}{{"current", 0}, {"detached", 0x00000008}} {
		for _, mode := range []string{"probe-root", "probe-parent", "probe-late", "probe-early"} {
			t.Run(flags.name+"/"+mode, func(t *testing.T) {
				directory := t.TempDir()
				executable, err := os.Executable()
				if err != nil {
					t.Fatal(err)
				}
				id, err := newID("native-observation-")
				if err != nil {
					t.Fatal(err)
				}
				eventName := `Local\BlenderBox-` + id
				createEvent := func(name string) syscall.Handle {
					wide, err := syscall.UTF16PtrFromString(name)
					if err != nil {
						t.Fatal(err)
					}
					handle, _, callErr := testCreateEvent.Call(0, 1, 0, uintptr(unsafe.Pointer(wide)))
					if handle == 0 {
						t.Fatal(callErr)
					}
					t.Cleanup(func() { syscall.CloseHandle(syscall.Handle(handle)) })
					return syscall.Handle(handle)
				}
				event := createEvent(eventName)
				var exitEvent syscall.Handle
				if mode == "probe-early" {
					exitEvent = createEvent(eventName + "-exit")
				}
				input, release, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer input.Close()
				defer release.Close()
				null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
				if err != nil {
					t.Fatal(err)
				}
				defer null.Close()
				job, err := newNativeJob()
				if err != nil {
					t.Fatal(err)
				}
				type member struct {
					pid     uint32
					handle  syscall.Handle
					created syscall.Filetime
					image   string
				}
				var spawn nativeSpawn
				var captured []member
				var witness syscall.Handle
				var witnessPID uint32
				var deadline time.Time
				terminated, terminationAttempted := false, false
				var rows strings.Builder
				started := time.Now()
				row := func(format string, values ...any) {
					fmt.Fprintf(&rows, "NATIVE_OBSERVATION flags=%s mode=%s elapsed_ns=%d ", flags.name, mode, time.Since(started).Nanoseconds())
					fmt.Fprintf(&rows, format+"\n", values...)
				}
				waitUntil := func(handle syscall.Handle, until time.Time) (uint32, error) {
					return syscall.WaitForSingleObject(handle, uint32(max(time.Until(until), 0)/time.Millisecond))
				}
				defer func() {
					if deadline.IsZero() {
						deadline = time.Now().Add(nativeCleanupTimeout)
					}
					if !terminationAttempted {
						ok, _, err := nativeTerminateJob.Call(uintptr(job.handle), 101)
						terminated = ok != 0
						row("phase=cleanup terminate_ok=%d terminate_error=%v", ok, err)
					}
					if !terminated {
						t.Error("exact Job cleanup unknown; closing kill-on-close Job")
						job.close()
					}
					handles := []syscall.Handle{spawn.Info.Process, witness}
					for _, process := range captured {
						handles = append(handles, process.handle)
					}
					for _, handle := range handles {
						if handle == 0 {
							continue
						}
						wait, err := waitUntil(handle, deadline)
						if err != nil || wait != syscall.WAIT_OBJECT_0 {
							t.Errorf("native observation cleanup unknown: wait=%d error=%v", wait, err)
						}
						syscall.CloseHandle(handle)
					}
					if spawn.Info.Thread != 0 {
						syscall.CloseHandle(spawn.Info.Thread)
					}
					job.close()
					fmt.Print(rows.String())
				}()
				spawn, err = job.startFlags(executable, []string{"-test.run=^TestNativeProcessHelper$", "--", mode, eventName, directory}, append(nativeTestEnvironment(t), "BLENDER_BOX_NATIVE_TEST_HELPER=1"), [3]*os.File{input, null, null}, flags.value)
				if err != nil {
					t.Fatal(err)
				}
				row("phase=start go=%s arch=%s added_flags=%#x child_flags=default root_pid=%d root_created=%+v", runtime.Version(), runtime.GOARCH, flags.value, spawn.Info.ProcessId, spawn.Created)
				ready := func() {
					if wait, err := syscall.WaitForSingleObject(event, 10000); err != nil || wait != syscall.WAIT_OBJECT_0 {
						t.Fatalf("native observation readiness=%d error=%v", wait, err)
					}
				}
				ready()
				image := func(handle syscall.Handle) (string, error) {
					var buffer [1024]uint16
					size := uint32(len(buffer))
					ok, _, err := testQueryProcessImage.Call(uintptr(handle), 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
					if ok == 0 || size == 0 || size > uint32(len(buffer)) {
						return "", fmt.Errorf("bounded process image query failed: ok=%d size=%d error=%v", ok, size, err)
					}
					return syscall.UTF16ToString(buffer[:size]), nil
				}
				verifyMember := func(handle syscall.Handle) {
					var member uint32
					ok, _, err := nativeIsProcessInJob.Call(uintptr(handle), uintptr(job.handle), uintptr(unsafe.Pointer(&member)))
					if ok == 0 || member != 1 {
						t.Fatalf("exact Job membership failed: ok=%d member=%d error=%v", ok, member, err)
					}
				}
				pinWitness := func() {
					data, err := os.ReadFile(filepath.Join(directory, "leaf.json"))
					if err != nil {
						t.Fatal(err)
					}
					var record nativeTestProcess
					if err := json.Unmarshal(data, &record); err != nil || record.ParentPID != int(spawn.Info.ProcessId) || !strings.EqualFold(record.Executable, executable) || record.PID <= 0 {
						t.Fatal("native observation leaf receipt mismatch")
					}
					witnessPID = uint32(record.PID)
					witness, err = syscall.OpenProcess(syscall.SYNCHRONIZE|0x1000, false, witnessPID)
					if err != nil {
						t.Fatal(err)
					}
					var created, exited, kernel, user syscall.Filetime
					if err := syscall.GetProcessTimes(witness, &created, &exited, &kernel, &user); err != nil || created != record.Created {
						t.Fatalf("native observation leaf creation mismatch: %v", err)
					}
					actualImage, err := image(witness)
					if err != nil {
						t.Fatal(err)
					}
					if !strings.EqualFold(actualImage, executable) {
						t.Fatal("native observation leaf executable mismatch")
					}
					verifyMember(witness)
					wait, err := syscall.WaitForSingleObject(witness, 0)
					row("phase=witness-pinned pid=%d parent_pid=%d created=%+v image=%q wait=%d error=%v", witnessPID, record.ParentPID, created, actualImage, wait, err)
					if err != nil || wait != syscall.WAIT_TIMEOUT {
						t.Fatal("witness exited before pinning")
					}
				}
				type jobList struct {
					Assigned, Listed uint32
					PIDs             [32]uintptr
				}
				observe := func(phase string) (nativeAccounting, jobList) {
					var accounting nativeAccounting
					var length uint32
					ok, _, queryErr := nativeQueryJob.Call(uintptr(job.handle), 1, uintptr(unsafe.Pointer(&accounting)), unsafe.Sizeof(accounting), uintptr(unsafe.Pointer(&length)))
					var list jobList
					listOK, _, listErr := nativeQueryJob.Call(uintptr(job.handle), 3, uintptr(unsafe.Pointer(&list)), unsafe.Sizeof(list), 0)
					row("phase=%s sequential=true query_ok=%d query_error=%v length=%d accounting=%+v list_ok=%d list_error=%v assigned=%d listed=%d pids=%v captured_distinct=%d", phase, ok, queryErr, length, accounting, listOK, listErr, list.Assigned, list.Listed, list.PIDs, len(captured))
					if ok == 0 || length != uint32(unsafe.Sizeof(accounting)) || listOK == 0 || list.Assigned != list.Listed || list.Listed > uint32(len(list.PIDs)) {
						t.Fatal("native observation query failed or incomplete")
					}
					for _, process := range append([]member{{pid: spawn.Info.ProcessId, handle: spawn.Info.Process}, {pid: witnessPID, handle: witness}}, captured...) {
						if process.handle == 0 {
							continue
						}
						wait, err := syscall.WaitForSingleObject(process.handle, 0)
						row("phase=%s pid=%d witness=%t retained_member=%t wait=%d wait_error=%v", phase, process.pid, process.handle == witness, process.created != (syscall.Filetime{}), wait, err)
						if err != nil || (wait != syscall.WAIT_OBJECT_0 && wait != syscall.WAIT_TIMEOUT) {
							t.Fatal("native observation signal query failed")
						}
					}
					return accounting, list
				}
				if mode == "probe-parent" || mode == "probe-early" {
					pinWitness()
				}
				if mode == "probe-early" {
					if ok, _, err := testSetEvent.Call(uintptr(exitEvent)); ok == 0 {
						t.Fatal(err)
					}
					wait, err := syscall.WaitForSingleObject(witness, 10000)
					row("phase=early-witness-before-capture pid=%d wait=%d error=%v", witnessPID, wait, err)
					if err != nil || wait != syscall.WAIT_OBJECT_0 {
						t.Fatal("early witness did not exit before capture")
					}
				}
				_, list := observe("candidate-capture")
				seen := make(map[uint32]bool)
				for _, pid := range list.PIDs[:list.Listed] {
					if pid == 0 || pid > uintptr(^uint32(0)) || seen[uint32(pid)] {
						t.Fatal("invalid or duplicate Job PID")
					}
					seen[uint32(pid)] = true
					handle, err := syscall.OpenProcess(syscall.SYNCHRONIZE|0x1000, false, uint32(pid))
					if err != nil {
						t.Fatalf("open exact Job member %d: %v", pid, err)
					}
					captured = append(captured, member{pid: uint32(pid), handle: handle})
					process := &captured[len(captured)-1]
					verifyMember(handle)
					var exited, kernel, user syscall.Filetime
					if err := syscall.GetProcessTimes(handle, &process.created, &exited, &kernel, &user); err != nil {
						t.Fatal(err)
					}
					process.image, err = image(handle)
					if err != nil {
						row("phase=member-image-unavailable pid=%d error=%v", pid, err)
					}
					wait, err := syscall.WaitForSingleObject(handle, 0)
					row("phase=member-pinned pid=%d created=%+v image=%q wait=%d wait_error=%v member=1", pid, process.created, process.image, wait, err)
					if err != nil || (wait != syscall.WAIT_OBJECT_0 && wait != syscall.WAIT_TIMEOUT) {
						t.Fatal("candidate member signal query failed")
					}
					if (uint32(pid) == spawn.Info.ProcessId || (mode == "probe-parent" && uint32(pid) == witnessPID)) && wait != syscall.WAIT_TIMEOUT {
						t.Fatal("controlled process exited before release")
					}
					if uint32(pid) == spawn.Info.ProcessId && process.created != spawn.Created {
						t.Fatal("captured root creation mismatch")
					}
				}
				if !seen[spawn.Info.ProcessId] {
					t.Fatal("candidate omitted original root")
				}
				if mode == "probe-parent" && !seen[witnessPID] {
					t.Fatal("candidate omitted live parent-leaf witness")
				}
				if mode == "probe-late" {
					if ok, _, err := testResetEvent.Call(uintptr(event)); ok == 0 {
						t.Fatal(err)
					}
					if _, err := release.Write([]byte{1}); err != nil {
						t.Fatal(err)
					}
					ready()
					pinWitness()
					if seen[witnessPID] {
						t.Fatal("late witness unexpectedly present in candidate capture")
					}
				}
				if mode == "probe-early" {
					row("phase=early-witness-capture-observation pid=%d captured=%t", witnessPID, seen[witnessPID])
				}
				observe("before-root-release")
				deadline = time.Now().Add(nativeCleanupTimeout)
				if _, err := release.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
				if wait, err := waitUntil(spawn.Info.Process, deadline); err != nil || wait != syscall.WAIT_OBJECT_0 {
					t.Fatalf("native observation root wait=%d error=%v", wait, err)
				}
				observe("after-root-wait-before-terminate")
				terminationAttempted = true
				ok, _, terminateErr := nativeTerminateJob.Call(uintptr(job.handle), 1)
				terminated = ok != 0
				row("phase=terminate terminate_ok=%d terminate_error=%v", ok, terminateErr)
				observe("after-terminate")
				if !terminated {
					t.Fatal("native observation Job termination failed")
				}
				for _, process := range captured {
					wait, err := waitUntil(process.handle, deadline)
					row("phase=captured-bounded-wait pid=%d wait=%d error=%v", process.pid, wait, err)
					if err != nil || wait != syscall.WAIT_OBJECT_0 {
						t.Fatal("captured member did not terminate")
					}
				}
				accounting, finalList := observe("after-captured-waits")
				row("phase=count-certificate-observation total=%d captured_distinct=%d count_matches=%t active=%d listed=%d", accounting.TotalProcesses, len(captured), accounting.TotalProcesses == uint32(len(captured)), accounting.ActiveProcesses, finalList.Listed)
				if mode == "probe-late" && accounting.TotalProcesses <= uint32(len(captured)) {
					t.Fatal("controlled missing witness did not produce a lifetime count gap")
				}
				if witness != 0 {
					wait, err := waitUntil(witness, deadline)
					row("phase=witness-bounded-wait pid=%d wait=%d error=%v", witnessPID, wait, err)
					if err != nil || wait != syscall.WAIT_OBJECT_0 {
						t.Fatal("independent witness did not terminate")
					}
				}
				observe("after-all-pinned-waits-handles-held")
				for index := 0; index < 64; index++ {
					var message uint32
					var key, pid uintptr
					ok, _, err := nativeReadPort.Call(uintptr(job.port), uintptr(unsafe.Pointer(&message)), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&pid)), 0)
					if ok == 0 {
						row("phase=completion-observation index=%d ok=%d error=%v", index, ok, err)
						if err != syscall.Errno(syscall.WAIT_TIMEOUT) {
							t.Fatal("completion observation failed")
						}
						break
					}
					row("phase=completion-observation index=%d ok=%d message=%d key_matches=%t pid=%d", index, ok, message, key == uintptr(job.handle), pid)
					if key != uintptr(job.handle) {
						t.Fatal("completion observation has unexpected key")
					}
					if index == 63 {
						row("phase=completion-observation capped=true")
					}
				}
			})
		}
	}
}
