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

var testProcessKernel = syscall.NewLazyDLL("kernel32.dll")
var testCreateEvent = testProcessKernel.NewProc("CreateEventW")
var testOpenEvent = testProcessKernel.NewProc("OpenEventW")
var testSetEvent = testProcessKernel.NewProc("SetEvent")

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
	if mode == "leaf" {
		if nativeTestRecord(filepath.Join(directory, "leaf.json")) != nil {
			os.Exit(93)
		}
		if ok, _, _ := testSetEvent.Call(event); ok == 0 {
			os.Exit(94)
		}
	} else {
		if nativeTestRecord(filepath.Join(directory, "root.json")) != nil {
			os.Exit(95)
		}
		child := exec.Command(os.Args[0], "-test.run=^TestNativeProcessHelper$", "--", "leaf", eventName, directory)
		child.Stdout, child.Stderr = os.Stdout, os.Stderr
		if child.Start() != nil {
			os.Exit(96)
		}
		if got, err := syscall.WaitForSingleObject(syscall.Handle(event), 10000); err != nil || got != syscall.WAIT_OBJECT_0 {
			os.Exit(97)
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
			if got, err := syscall.WaitForSingleObject(child, 0); err != nil || got != syscall.WAIT_OBJECT_0 {
				t.Fatalf("owned descendant survives native return: wait=%d error=%v", got, err)
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
