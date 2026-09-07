//go:build windows

package windowsinstall

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"
)

func sshDiagnosticRecord(t *testing.T, fields map[string]any) {
	t.Helper()
	data, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("SSH_NATIVE_DIAGNOSTIC %s\n", data)
}

func TestSSHRetainedDirectoryDiagnostic(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "first.txt")
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	scope := newSSHReadScope(sshWindowsBackend{})
	defer scope.Close()
	if _, err := scope.image(path, 1024); err != nil {
		t.Fatal(err)
	}
	held, err := scope.open(root)
	if err != nil {
		t.Fatal(err)
	}
	original := held.(*sshWindowsFile)
	identity, err := handleIdentity(syscall.Handle(original.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	compareReopen := func(label string, file *sshWindowsFile) {
		t.Helper()
		observed, err := handleIdentity(syscall.Handle(file.Fd()))
		if err != nil || observed != identity {
			t.Fatalf("%s identity: %q %v", label, observed, err)
		}
		handle, _, callErr := sshKernel.NewProc("ReOpenFile").Call(file.Fd(), uintptr(syscall.GENERIC_READ), uintptr(syscall.FILE_SHARE_READ), uintptr(syscall.FILE_FLAG_BACKUP_SEMANTICS|syscall.FILE_FLAG_OPEN_REPARSE_POINT))
		row := map[string]any{"kind": "directory", "origin": label, "stage": "ReOpenFile", "success": handle != ^uintptr(0), "same_identity": true}
		if handle == ^uintptr(0) {
			row["error"] = callErr.Error()
			if errno, ok := callErr.(syscall.Errno); ok {
				row["errno"] = uint32(errno)
			}
		} else {
			file := os.NewFile(handle, original.physical)
			entries, readErr := file.ReadDir(17)
			file.Close()
			row["entries"] = len(entries)
			if readErr != nil && readErr != io.EOF {
				row["read_error"] = readErr.Error()
			}
		}
		sshDiagnosticRecord(t, row)
	}
	compareReopen("NtCreateFile", original)
	control, err := (sshWindowsBackend{}).openVolume(original.physical)
	if err != nil {
		t.Fatal("CreateFile control", err)
	}
	compareReopen("CreateFile", control.(*sshWindowsFile))
	control.Close()
	self, err := syscall.GetCurrentProcess()
	if err != nil {
		t.Fatal(err)
	}
	for count := 1; count <= 2; count++ {
		var handle syscall.Handle
		if err := syscall.DuplicateHandle(self, syscall.Handle(original.Fd()), self, &handle, 0, false, syscall.DUPLICATE_SAME_ACCESS); err != nil {
			t.Fatal("DuplicateHandle", err)
		}
		file := os.NewFile(uintptr(handle), original.physical)
		observed, pinErr := handleIdentity(handle)
		entries, readErr := file.ReadDir(17)
		closeErr := file.Close()
		if pinErr != nil || observed != identity || closeErr != nil || readErr != nil && readErr != io.EOF || len(entries) != count {
			t.Fatalf("duplicate enumeration %d: identity=%v entries=%d pin=%v read=%v close=%v", count, observed == identity, len(entries), pinErr, readErr, closeErr)
		}
		sshDiagnosticRecord(t, map[string]any{"kind": "directory", "origin": "DuplicateHandle", "enumeration": count, "entries": len(entries), "same_identity": true})
		if count == 1 {
			if err := os.WriteFile(filepath.Join(root, "second.txt"), []byte("new"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, access := range []uint32{syscall.GENERIC_WRITE, 0x00010000} {
		handle, err := syscall.CreateFile(pointer, access, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, 0, 0)
		if err == nil {
			syscall.CloseHandle(handle)
			t.Fatal("diagnostic released retained writer/delete exclusion")
		}
	}
	if err := scope.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal("diagnostic leaked retained handle", err)
	}
	writer.Close()
}

func TestSSHNativeLaunchPathDiagnostic(t *testing.T) {
	system, err := systemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	reader := &sshNativeReader{newSSHReadScope(sshWindowsBackend{})}
	defer reader.Close()
	home := filepath.Join(system, "WindowsPowerShell", "v1.0")
	logical := filepath.Join(home, "powershell.exe")
	physical, err := reader.executablePath(logical, "")
	if err != nil {
		t.Fatal(err)
	}
	environment, err := reader.commandEnvironment()
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.trusted(filepath.Join(home, "Modules"), ""); err != nil {
		t.Fatal(err)
	}
	modules, err := reader.commandPath(filepath.Join(home, "Modules"))
	if err != nil {
		t.Fatal(err)
	}
	globalRoot, err := sshDiagnosticGlobalRoot(reader, logical)
	if err != nil {
		t.Fatal(err)
	}
	physicalEnvironment := append(environment, "PSModulePath="+modules, "PSModuleAnalysisCachePath=nul")
	logicalEnvironment := []string{"SystemRoot=" + filepath.Dir(system), "WINDIR=" + filepath.Dir(system), "PATH=" + system, "PSModulePath=" + filepath.Join(home, "Modules"), "PSModuleAnalysisCachePath=nul"}
	script := "$ErrorActionPreference='Stop'\n[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)\n[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n$OutputEncoding=[Console]::OutputEncoding\n$r=ConvertFrom-Json ([Console]::In.ReadToEnd())\n" + nativeFunctions + "\n[ordered]@{value=$r.value;cache=$env:PSModuleAnalysisCachePath} | ConvertTo-Json -Compress"
	units := utf16.Encode([]rune(script))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:], unit)
	}
	args := []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded)}
	if len(logical) < 3 || logical[1:3] != `:\` || !filepath.IsAbs(logical) {
		t.Fatal("diagnostic requires a validated absolute DOS executable")
	}
	extended := `\\?\` + logical
	for _, variant := range []struct {
		name                          string
		applicationShape, argv0Shape  string
		application, argv0, directory string
		environment                   []string
	}{
		{"app-D_argv0-D", "D", "D", logical, logical, home, logicalEnvironment},
		{"app-G_argv0-D", "G", "D", physical, logical, home, logicalEnvironment},
		{"app-D_argv0-G", "D", "G", logical, physical, home, logicalEnvironment},
		{"app-R_argv0-D", "R", "D", globalRoot, logical, home, logicalEnvironment},
		{"app-D_argv0-R", "D", "R", logical, globalRoot, home, logicalEnvironment},
		{"app-E_argv0-D", "E", "D", extended, logical, home, logicalEnvironment},
		{"app-D_argv0-E", "D", "E", logical, extended, home, logicalEnvironment},
		{"dos-exe_dos-cwd_dos-env", "D", "D", logical, logical, home, logicalEnvironment},
		{"guid-exe_dos-cwd_dos-env", "G", "G", physical, physical, home, logicalEnvironment},
		{"dos-exe_guid-cwd_dos-env", "D", "D", logical, logical, filepath.Dir(physical), logicalEnvironment},
		{"guid-exe_guid-cwd_dos-env", "G", "G", physical, physical, filepath.Dir(physical), logicalEnvironment},
		{"dos-exe_dos-cwd_guid-env", "D", "D", logical, logical, home, physicalEnvironment},
		{"guid-exe_guid-cwd_guid-env", "G", "G", physical, physical, filepath.Dir(physical), physicalEnvironment},
		{"globalroot-exe_guid-cwd_guid-env", "R", "R", globalRoot, globalRoot, filepath.Dir(physical), physicalEnvironment},
		{"globalroot-exe_globalroot-cwd_guid-env", "R", "R", globalRoot, globalRoot, filepath.Dir(globalRoot), physicalEnvironment},
	} {
		if !t.Run(variant.name, func(t *testing.T) {
			job, err := newNativeJob()
			if err != nil {
				t.Fatal(err)
			}
			defer job.close()
			var files [3]*os.File
			for i := range files {
				read, write, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer read.Close()
				defer write.Close()
				files[i] = read
				if i > 0 {
					files[i] = write
				}
			}
			row := map[string]any{"kind": "process", "variant": variant.name, "application_shape": variant.applicationShape, "argv0_shape": variant.argv0Shape, "suspended": true, "script_units": len(units), "errno": uint32(0)}
			spawn, launchErr := sshDiagnosticStart(job, variant.application, variant.argv0, variant.directory, args, variant.environment, files, 0x00000004, row)
			if spawn.Info.Process != 0 {
				defer syscall.CloseHandle(spawn.Info.Process)
			}
			if spawn.Info.Thread != 0 {
				defer syscall.CloseHandle(spawn.Info.Thread)
			}
			initialCounts, initialCountsErr := (nativeMemberWindows{job.handle}).counts()
			row["initial_total"], row["initial_active"], row["initial_counts_verified"] = initialCounts.total, initialCounts.active, initialCountsErr == nil
			complete := spawn.Info.Process != 0 && spawn.Info.Thread != 0 && spawn.Info.ProcessId != 0
			row["success"], row["pid"], row["created"] = launchErr == nil && complete && initialCountsErr == nil, spawn.Info.ProcessId, spawn.Created
			row["spawned"], row["thread_handle"] = spawn.Info.Process != 0, spawn.Info.Thread != 0
			if launchErr != nil {
				row["error"] = launchErr.Error()
				var errno syscall.Errno
				if errors.As(launchErr, &errno) {
					row["errno"] = uint32(errno)
				}
			}
			if spawn.Info.Process != 0 || spawn.Info.Thread != 0 || spawn.Info.ProcessId != 0 || initialCountsErr != nil || initialCounts.total != 0 || initialCounts.active != 0 {
				var collectErr, waitErr error
				if spawn.Info.Process != 0 {
					collectErr = job.collect(spawn)
				}
				deadline := time.Now().Add(nativeCleanupTimeout)
				row["settlement_attempted"] = true
				cleanupErr := job.settle(deadline)
				if spawn.Info.Process != 0 {
					waitErr = (nativeMemberWindows{}).wait(uintptr(spawn.Info.Process), deadline)
				}
				counts, countsErr := (nativeMemberWindows{job.handle}).counts()
				row["exact_job_member"] = spawn.Info.Process != 0 && collectErr == nil
				row["active_after_cleanup"], row["counts_verified"] = counts.active, countsErr == nil
				row["cleanup"] = cleanupErr == nil && waitErr == nil && collectErr == nil && countsErr == nil && counts.active == 0
				sshDiagnosticRecord(t, row)
				if collectErr != nil || cleanupErr != nil || waitErr != nil || countsErr != nil || counts.active != 0 {
					t.Fatalf("exact Job cleanup: collect=%v settle=%v root=%v counts=%v active=%d", collectErr, cleanupErr, waitErr, countsErr, counts.active)
				}
				if launchErr != nil || !complete || initialCountsErr != nil {
					t.Fatalf("partial creation or authority failed: launch=%v complete=%v initial_counts=%v", launchErr, complete, initialCountsErr)
				}
			} else {
				row["total_after_failure"], row["active_after_cleanup"] = initialCounts.total, initialCounts.active
				row["counts_verified"], row["cleanup"], row["settlement_attempted"] = true, true, false
				sshDiagnosticRecord(t, row)
				if row["stage"] != sshDiagnosticCreateProcess || launchErr == nil {
					t.Fatal("launch setup failed", launchErr)
				}
			}
			if (variant.name == "app-D_argv0-D" || variant.name == "dos-exe_dos-cwd_dos-env") && launchErr != nil {
				t.Fatal("DOS control did not start", launchErr)
			}
		}) {
			t.FailNow()
		}
	}
}

type sshDiagnosticStage string

const sshDiagnosticCreateProcess sshDiagnosticStage = "CreateProcessW"

func sshDiagnosticStart(job *nativeJob, applicationName, argv0, workingDirectory string, args, environment []string, files [3]*os.File, creationFlags uint32, row map[string]any) (nativeSpawn, error) {
	var spawn nativeSpawn
	row["stage"] = sshDiagnosticStage("encode-application")
	applicationUnits, err := syscall.UTF16FromString(applicationName)
	if err != nil {
		return spawn, err
	}
	if !filepath.IsAbs(applicationName) {
		return spawn, fmt.Errorf("native executable must be absolute")
	}
	row["stage"] = sshDiagnosticStage("encode-directory")
	directoryUnits, err := syscall.UTF16FromString(workingDirectory)
	if err != nil {
		return spawn, err
	}
	row["stage"] = sshDiagnosticStage("encode-command")
	quoted := make([]string, 0, len(args)+1)
	for _, arg := range append([]string{argv0}, args...) {
		if strings.ContainsRune(arg, 0) {
			return spawn, fmt.Errorf("native argument contains NUL")
		}
		quoted = append(quoted, syscall.EscapeArg(arg))
	}
	command, err := syscall.UTF16FromString(strings.Join(quoted, " "))
	if err != nil {
		return spawn, err
	}
	if environment == nil {
		environment = os.Environ()
	}
	row["stage"] = sshDiagnosticStage("encode-environment")
	block, err := nativeEnvironmentBlock(environment)
	if err != nil {
		return spawn, err
	}
	row["stage"] = sshDiagnosticStage("GetCurrentProcess")
	self, err := syscall.GetCurrentProcess()
	if err != nil {
		return spawn, err
	}
	var inherited [3]syscall.Handle
	defer func() {
		for _, handle := range inherited {
			if handle != 0 {
				_ = syscall.CloseHandle(handle)
			}
		}
	}()
	row["stage"] = sshDiagnosticStage("DuplicateHandle")
	for i, file := range files {
		if err := syscall.DuplicateHandle(self, syscall.Handle(file.Fd()), self, &inherited[i], 0, true, syscall.DUPLICATE_SAME_ACCESS); err != nil {
			return spawn, err
		}
	}
	row["stage"] = sshDiagnosticStage("InitializeProcThreadAttributeList")
	var size uintptr
	attributeCount := uintptr(1)
	if job != nil {
		attributeCount = 2
	}
	_, _, _ = nativeInitializeAttributes.Call(0, attributeCount, 0, uintptr(unsafe.Pointer(&size)))
	if size == 0 || size > 1<<20 {
		return spawn, fmt.Errorf("invalid native startup attribute size")
	}
	storage := make([]uintptr, (size+unsafe.Sizeof(uintptr(0))-1)/unsafe.Sizeof(uintptr(0)))
	attributes := unsafe.Pointer(&storage[0])
	if ok, _, err := nativeInitializeAttributes.Call(uintptr(attributes), attributeCount, 0, uintptr(unsafe.Pointer(&size))); ok == 0 {
		return spawn, fmt.Errorf("initialize native startup attributes: %w", err)
	}
	var jobs [1]syscall.Handle
	if job != nil {
		jobs[0] = job.handle
	}
	defer func() {
		nativeDeleteAttributes.Call(uintptr(attributes))
		runtime.KeepAlive(storage)
		runtime.KeepAlive(inherited)
		runtime.KeepAlive(jobs)
	}()
	row["stage"] = sshDiagnosticStage("UpdateProcThreadAttribute-handles")
	if ok, _, err := nativeUpdateAttribute.Call(uintptr(attributes), 0, 0x00020002, uintptr(unsafe.Pointer(&inherited[0])), unsafe.Sizeof(inherited), 0, 0); ok == 0 {
		return spawn, fmt.Errorf("set native inherited handles: %w", err)
	}
	row["stage"] = sshDiagnosticStage("UpdateProcThreadAttribute-job")
	// JOB_LIST assigns the process before its initial thread can execute.
	if job != nil {
		if ok, _, err := nativeUpdateAttribute.Call(uintptr(attributes), 0, 0x0002000d, uintptr(unsafe.Pointer(&jobs[0])), unsafe.Sizeof(jobs), 0, 0); ok == 0 {
			return spawn, fmt.Errorf("set native process job: %w", err)
		}
	}
	startup := nativeStartupInfo{Attributes: attributes}
	startup.Cb = uint32(unsafe.Sizeof(startup))
	startup.Flags = syscall.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = inherited[0], inherited[1], inherited[2]
	flags := uint32(0x00080000 | syscall.CREATE_UNICODE_ENVIRONMENT | 0x08000000 | creationFlags)
	row["flags"], row["argv0_escaped"] = flags, quoted[0] != argv0
	row["utf16_lengths_include_terminators"] = true
	argumentUnits, err := syscall.UTF16FromString(strings.Join(quoted[1:], " "))
	if err != nil {
		return spawn, err
	}
	for label, input := range map[string][]uint16{"application": applicationUnits, "command_precall": command, "cwd": directoryUnits, "environment": block, "argument_tail": argumentUnits} {
		encoded := make([]byte, len(input)*2)
		for i, unit := range input {
			binary.LittleEndian.PutUint16(encoded[i*2:], unit)
		}
		row[label+"_utf16_units"] = len(input)
		row[label+"_sha256"] = fmt.Sprintf("%x", sha256.Sum256(encoded))
	}
	row["stage"] = sshDiagnosticCreateProcess
	err = syscall.CreateProcess(&applicationUnits[0], &command[0], nil, nil, true, flags, &block[0], &directoryUnits[0], &startup.StartupInfo, &spawn.Info)
	runtime.KeepAlive(command)
	runtime.KeepAlive(block)
	runtime.KeepAlive(startup)
	if err != nil {
		return spawn, fmt.Errorf("start native process in job: %w", err)
	}
	row["stage"] = sshDiagnosticStage("GetProcessTimes")
	var exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(spawn.Info.Process, &spawn.Created, &exited, &kernel, &user); err != nil {
		return spawn, fmt.Errorf("record native process creation: %w", err)
	}
	row["stage"] = sshDiagnosticStage("created-suspended")
	return spawn, nil
}

func sshDiagnosticGlobalRoot(reader *sshNativeReader, logical string) (string, error) {
	finalPath := func(file sshHeldFile) (string, error) {
		if file == nil {
			return "", fmt.Errorf("missing retained diagnostic handle")
		}
		var buffer [32768]uint16
		length, _, callErr := sshKernel.NewProc("GetFinalPathNameByHandleW").Call(file.(*sshWindowsFile).Fd(), uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), 2)
		if length == 0 {
			return "", fmt.Errorf("query retained NT device path: %w", callErr)
		}
		if length >= uintptr(len(buffer)) {
			return "", fmt.Errorf("retained NT path exceeds bound")
		}
		return syscall.UTF16ToString(buffer[:length]), nil
	}
	root, err := finalPath(reader.held[logical[:3]])
	if err != nil {
		return "", err
	}
	root = strings.TrimSuffix(root, `\`)
	const prefix = `\Device\HarddiskVolume`
	if !strings.HasPrefix(root, prefix) {
		return "", fmt.Errorf("unsupported retained NT volume")
	}
	if number, err := strconv.ParseUint(strings.TrimPrefix(root, prefix), 10, 32); err != nil || number == 0 {
		return "", fmt.Errorf("invalid retained NT volume")
	}
	path, err := finalPath(reader.held[logical])
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(path, root+`\`) {
		return "", fmt.Errorf("executable NT path differs from retained volume")
	}
	return `\\?\GLOBALROOT` + path, nil
}
