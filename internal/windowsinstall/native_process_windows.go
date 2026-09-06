//go:build windows

package windowsinstall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const nativeCleanupTimeout = 5 * time.Second

var errNativeExecutionFailed = errors.New("native process supervision failed")

var nativeProcessKernel = syscall.NewLazyDLL("kernel32.dll")
var nativeCreateJob = nativeProcessKernel.NewProc("CreateJobObjectW")
var nativeSetJob = nativeProcessKernel.NewProc("SetInformationJobObject")
var nativeQueryJob = nativeProcessKernel.NewProc("QueryInformationJobObject")
var nativeTerminateJob = nativeProcessKernel.NewProc("TerminateJobObject")
var nativeCreatePort = nativeProcessKernel.NewProc("CreateIoCompletionPort")
var nativeReadPort = nativeProcessKernel.NewProc("GetQueuedCompletionStatus")
var nativeInitializeAttributes = nativeProcessKernel.NewProc("InitializeProcThreadAttributeList")
var nativeUpdateAttribute = nativeProcessKernel.NewProc("UpdateProcThreadAttribute")
var nativeDeleteAttributes = nativeProcessKernel.NewProc("DeleteProcThreadAttributeList")

type nativeBasicLimits struct {
	ProcessTime, JobTime                 int64
	Flags                                uint32
	MinimumWorkingSet, MaximumWorkingSet uintptr
	ActiveProcessLimit                   uint32
	Affinity                             uintptr
	PriorityClass, SchedulingClass       uint32
}
type nativeExtendedLimits struct {
	Basic                                                      nativeBasicLimits
	IOCounters                                                 [6]uint64
	ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory uintptr
}
type nativeAccounting struct {
	Times                                                            [4]int64
	PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses uint32
}
type nativeJob struct{ handle, port syscall.Handle }
type nativeStartupInfo struct {
	syscall.StartupInfo
	Attributes unsafe.Pointer
}
type nativeSpawn struct {
	Info    syscall.ProcessInformation
	Created syscall.Filetime
}

func newNativeJob() (*nativeJob, error) {
	handle, _, err := nativeCreateJob.Call(0, 0)
	if handle == 0 {
		return nil, fmt.Errorf("create native job: %w", err)
	}
	job := &nativeJob{handle: syscall.Handle(handle)}
	limits := nativeExtendedLimits{Basic: nativeBasicLimits{Flags: 0x00002000}}
	if ok, _, err := nativeSetJob.Call(handle, 9, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits)); ok == 0 {
		job.close()
		return nil, fmt.Errorf("set native job kill-on-close: %w", err)
	}
	port, _, err := nativeCreatePort.Call(^uintptr(0), 0, 0, 1)
	if port == 0 {
		job.close()
		return nil, fmt.Errorf("create native completion port: %w", err)
	}
	job.port = syscall.Handle(port)
	association := struct {
		Key  uintptr
		Port syscall.Handle
	}{handle, job.port}
	if ok, _, err := nativeSetJob.Call(handle, 7, uintptr(unsafe.Pointer(&association)), unsafe.Sizeof(association)); ok == 0 {
		job.close()
		return nil, fmt.Errorf("associate native completion port: %w", err)
	}
	return job, nil
}
func (job *nativeJob) close() {
	if job.handle != 0 {
		_ = syscall.CloseHandle(job.handle)
		job.handle = 0
	}
	if job.port != 0 {
		_ = syscall.CloseHandle(job.port)
		job.port = 0
	}
}
func (job *nativeJob) active() (uint32, error) {
	var accounting nativeAccounting
	if ok, _, err := nativeQueryJob.Call(uintptr(job.handle), 1, uintptr(unsafe.Pointer(&accounting)), unsafe.Sizeof(accounting), 0); ok == 0 {
		return 0, fmt.Errorf("query native job activity: %w", err)
	}
	return accounting.ActiveProcesses, nil
}
func (job *nativeJob) terminateAndWait() error {
	terminated, _, terminateErr := nativeTerminateJob.Call(uintptr(job.handle), 1)
	deadline := time.Now().Add(nativeCleanupTimeout)
	for {
		active, err := job.active()
		if err != nil {
			return errors.Join(errNativeCleanupUnknown, err)
		}
		if active == 0 {
			return nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			if terminated == 0 {
				return errors.Join(errNativeCleanupUnknown, fmt.Errorf("terminate native job: %w", terminateErr))
			}
			return fmt.Errorf("%w: %d processes still active", errNativeCleanupUnknown, active)
		}
		if remaining > 100*time.Millisecond {
			remaining = 100 * time.Millisecond
		}
		var message uint32
		var key, process uintptr
		ok, _, err := nativeReadPort.Call(uintptr(job.port), uintptr(unsafe.Pointer(&message)), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(&process)), uintptr((remaining+time.Millisecond-1)/time.Millisecond))
		if ok == 0 && err != syscall.Errno(syscall.WAIT_TIMEOUT) {
			return errors.Join(errNativeCleanupUnknown, fmt.Errorf("wait native job activity: %w", err))
		}
		if ok != 0 && key != uintptr(job.handle) {
			return fmt.Errorf("%w: unexpected native completion key", errNativeCleanupUnknown)
		}
	}
}

func (job *nativeJob) start(executable string, args, environment []string, files [3]*os.File) (nativeSpawn, error) {
	return job.startFlags(executable, args, environment, files, 0)
}

func (job *nativeJob) startFlags(executable string, args, environment []string, files [3]*os.File, creationFlags uint32) (nativeSpawn, error) {
	var spawn nativeSpawn
	application, err := syscall.UTF16PtrFromString(executable)
	if err != nil {
		return spawn, err
	}
	if !filepath.IsAbs(executable) {
		return spawn, fmt.Errorf("native executable must be absolute")
	}
	directory, err := syscall.UTF16PtrFromString(filepath.Dir(executable))
	if err != nil {
		return spawn, err
	}
	quoted := make([]string, 0, len(args)+1)
	for _, arg := range append([]string{executable}, args...) {
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
	block, err := nativeEnvironmentBlock(environment)
	if err != nil {
		return spawn, err
	}
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
	for i, file := range files {
		if err := syscall.DuplicateHandle(self, syscall.Handle(file.Fd()), self, &inherited[i], 0, true, syscall.DUPLICATE_SAME_ACCESS); err != nil {
			return spawn, err
		}
	}
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
	if ok, _, err := nativeUpdateAttribute.Call(uintptr(attributes), 0, 0x00020002, uintptr(unsafe.Pointer(&inherited[0])), unsafe.Sizeof(inherited), 0, 0); ok == 0 {
		return spawn, fmt.Errorf("set native inherited handles: %w", err)
	}
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
	err = syscall.CreateProcess(application, &command[0], nil, nil, true, 0x00080000|syscall.CREATE_UNICODE_ENVIRONMENT|0x08000000|creationFlags, &block[0], directory, &startup.StartupInfo, &spawn.Info)
	runtime.KeepAlive(command)
	runtime.KeepAlive(block)
	runtime.KeepAlive(startup)
	if err != nil {
		return spawn, fmt.Errorf("start native process in job: %w", err)
	}
	var exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(spawn.Info.Process, &spawn.Created, &exited, &kernel, &user); err != nil {
		return spawn, fmt.Errorf("record native process creation: %w", err)
	}
	return spawn, nil
}

type nativeStream struct {
	kind string
	data []byte
	err  error
}
type nativeExit struct {
	state *os.ProcessState
	err   error
}

type nativeRunGate struct {
	NotStarted func()
	Admit      func(nativeSpawn) error
	TreeExited func(nativeSpawn)
}

func runNativeJob(ctx context.Context, executable string, args []string, input []byte, environment []string) ([]byte, error) {
	return runNativeJobGated(ctx, executable, args, input, environment, nil)
}

func runNativeJobGated(ctx context.Context, executable string, args []string, input []byte, environment []string, gate *nativeRunGate) ([]byte, error) {
	definitelyNotStarted := true
	defer func() {
		if gate != nil && gate.NotStarted != nil && definitelyNotStarted {
			gate.NotStarted()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	job, err := newNativeJob()
	if err != nil {
		return nil, err
	}
	defer job.close()
	var pipeFiles []*os.File
	defer func() {
		for _, file := range pipeFiles {
			_ = file.Close()
		}
	}()
	pipe := func() (*os.File, *os.File, error) {
		read, write, err := os.Pipe()
		if err == nil {
			pipeFiles = append(pipeFiles, read, write)
		}
		return read, write, err
	}
	stdinRead, stdinWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	stdoutRead, stdoutWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	stderrRead, stderrWrite, err := pipe()
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	flags := uint32(0)
	if gate != nil {
		flags = 0x00000004
	}
	definitelyNotStarted = false
	spawn, startErr := job.startFlags(executable, args, environment, [3]*os.File{stdinRead, stdoutWrite, stderrWrite}, flags)
	if spawn.Info.Process == 0 && startErr != nil {
		definitelyNotStarted = true
	}
	_ = stdinRead.Close()
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()
	if spawn.Info.Process == 0 {
		return nil, startErr
	}
	defer syscall.CloseHandle(spawn.Info.Process)
	defer syscall.CloseHandle(spawn.Info.Thread)
	abortStart := func(cause error) ([]byte, error) {
		cleanupErr := job.terminateAndWait()
		wait, err := syscall.WaitForSingleObject(spawn.Info.Process, uint32(nativeCleanupTimeout/time.Millisecond))
		if err != nil || wait != syscall.WAIT_OBJECT_0 {
			cleanupErr = errors.Join(cleanupErr, errNativeCleanupUnknown, fmt.Errorf("wait native spawn %d: event=%d error=%v", spawn.Info.ProcessId, wait, err))
		}
		return nil, errors.Join(cause, cleanupErr)
	}
	if startErr != nil {
		return abortStart(startErr)
	}
	if gate != nil {
		if err := gate.Admit(spawn); err != nil {
			return abortStart(err)
		}
		if result, _, err := nativeResumeThread.Call(uintptr(spawn.Info.Thread)); result != 1 {
			return abortStart(fmt.Errorf("resume owned worker: %w", err))
		}
	}
	// The original spawn handle pins this PID while os.FindProcess opens its wait handle.
	process, err := os.FindProcess(int(spawn.Info.ProcessId))
	if err != nil {
		return abortStart(err)
	}
	exit := make(chan nativeExit, 1)
	go func() { state, err := process.Wait(); exit <- nativeExit{state, err} }()
	streams := make(chan nativeStream, 3)
	readStream := func(kind string, file *os.File, limit int64) {
		data, err := io.ReadAll(io.LimitReader(file, limit+1))
		if int64(len(data)) > limit {
			data = data[:limit]
			err = fmt.Errorf("native %s exceeds limit", kind)
		}
		streams <- nativeStream{kind, data, err}
	}
	stdoutLimit := int64(256 << 10)
	if gate != nil {
		stdoutLimit = maxExecutionRecord
	}
	go readStream("stdout", stdoutRead, stdoutLimit)
	go readStream("stderr", stderrRead, 64<<10)
	go func() {
		_, err := io.Copy(stdinWrite, bytes.NewReader(input))
		_ = stdinWrite.Close()
		if errors.Is(err, syscall.ERROR_BROKEN_PIPE) {
			err = nil
		}
		streams <- nativeStream{kind: "stdin", err: err}
	}()
	var stdout, stderr []byte
	var operationErr error
	var waited *nativeExit
	remainingStreams := 3
	receive := func(stream nativeStream) {
		remainingStreams--
		if stream.kind == "stdout" {
			stdout = stream.data
		}
		if stream.kind == "stderr" {
			stderr = stream.data
		}
		operationErr = errors.Join(operationErr, stream.err)
	}
	running := true
	for running {
		select {
		case <-ctx.Done():
			operationErr = errors.Join(operationErr, ctx.Err())
			running = false
		case result := <-exit:
			waited = &result
			active, err := job.active()
			if err != nil {
				operationErr = errors.Join(operationErr, err)
			} else if active != 0 {
				operationErr = errors.Join(operationErr, fmt.Errorf("native operation left running descendants"))
			}
			running = false
		case stream := <-streams:
			receive(stream)
			if stream.err != nil {
				running = false
			}
		}
	}
	cleanupErr := job.terminateAndWait()
	if cleanupErr != nil {
		job.close()
	}
	if waited == nil {
		select {
		case result := <-exit:
			waited = &result
		case <-time.After(nativeCleanupTimeout):
			cleanupErr = errors.Join(cleanupErr, errNativeCleanupUnknown, fmt.Errorf("native root process did not finish"))
		}
	}
	var exitErr error
	if waited != nil {
		operationErr = errors.Join(operationErr, waited.err)
		if waited.state == nil {
			cleanupErr = errors.Join(cleanupErr, errNativeCleanupUnknown, fmt.Errorf("native root process has no exit state"))
		}
		if waited.state != nil && !waited.state.Success() {
			exitErr = &exec.ExitError{ProcessState: waited.state}
		}
	}
	drain := time.NewTimer(time.Second)
	defer drain.Stop()
	for remainingStreams > 0 {
		select {
		case stream := <-streams:
			receive(stream)
		case <-drain.C:
			for _, file := range pipeFiles {
				_ = file.Close()
			}
			cleanupErr = errors.Join(cleanupErr, errNativeCleanupUnknown, fmt.Errorf("native pipe drain exceeded deadline"))
			remainingStreams = 0
		}
	}
	if cleanupErr == nil && gate != nil {
		gate.TreeExited(spawn)
	}
	if err := errors.Join(operationErr, cleanupErr); err != nil {
		return stdout, fmt.Errorf("native operation failed: %w: %s", errors.Join(errNativeExecutionFailed, err, exitErr), strings.TrimSpace(string(stderr)))
	}
	if exitErr != nil {
		return stdout, fmt.Errorf("native operation failed: %w: %s", exitErr, strings.TrimSpace(string(stderr)))
	}
	return stdout, nil
}
