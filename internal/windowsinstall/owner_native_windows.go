//go:build windows

package windowsinstall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/strictjson"
)

var nativeResumeThread = nativeProcessKernel.NewProc("ResumeThread")
var nativeIsProcessInJob = nativeProcessKernel.NewProc("IsProcessInJob")

func processIdentity(pid uint32, created syscall.Filetime) ProcessIdentity {
	return ProcessIdentity{PID: pid, CreatedFiletime: strconv.FormatUint(uint64(created.HighDateTime)<<32|uint64(created.LowDateTime), 10)}
}
func currentProcessIdentity() (ProcessIdentity, error) {
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return ProcessIdentity{}, err
	}
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(process, &created, &exited, &kernel, &user); err != nil {
		return ProcessIdentity{}, err
	}
	return processIdentity(uint32(os.Getpid()), created), nil
}
func nativeProcessAlive(want ProcessIdentity) (bool, error) {
	if !want.valid() {
		return false, fmt.Errorf("invalid recorded process identity")
	}
	process, err := syscall.OpenProcess(0x00100000|0x1000, false, want.PID)
	if err == syscall.Errno(87) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer syscall.CloseHandle(process)
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(process, &created, &exited, &kernel, &user); err != nil {
		return false, err
	}
	if processIdentity(want.PID, created) != want {
		return false, nil
	}
	wait, err := syscall.WaitForSingleObject(process, 0)
	return wait == syscall.WAIT_TIMEOUT, err
}
func openPinnedSource(path string) (*os.File, error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(pointer, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	if _, err = handleIdentity(handle); err != nil {
		syscall.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func openPinnedDirectory(path string) (*os.File, error) {
	pointer, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	handle, err := syscall.CreateFile(pointer, syscall.GENERIC_READ, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_OPEN_REPARSE_POINT|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, err
	}
	if _, err := handleIdentity(handle); err != nil {
		syscall.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func launchNativeKeeper(ctx context.Context, request Request) (Result, error) {
	return newOwner(nativeMachine{}).keep(ctx, request)
}

func runScheduledKeeper(directory, hash string) (Result, error) {
	var record executionRequest
	if err := readExecutionJSON(filepath.Join(directory, "request.json"), &record); err != nil {
		return Result{}, err
	}
	if record.directory() != directory || string(objectDigest(record)) != hash {
		return Result{}, fmt.Errorf("keeper request identity changed")
	}
	executable, err := os.Executable()
	if err != nil || executable != record.Bootstrap.Path {
		return Result{}, fmt.Errorf("keeper bootstrap changed")
	}
	ctx, cancel := context.WithDeadline(context.Background(), record.Deadline)
	defer cancel()
	self, err := currentProcessIdentity()
	if err != nil {
		return Result{}, err
	}
	owner := newOwner(nativeMachine{})
	release, err := owner.admitKeeper(ctx, record, self)
	if err != nil {
		return Result{}, err
	}
	defer release()
	return owner.keepAdmitted(ctx, record)
}

func runNativeWorker(ctx context.Context, record executionRequest, publish func(executionOwnership) error) (workerOutcome, *treeExit, error) {
	var outcome workerOutcome
	keeper, err := currentProcessIdentity()
	if err != nil {
		return outcome, nil, err
	}
	environment, err := cleanEnvironment()
	if err != nil {
		return outcome, nil, err
	}
	var exit *treeExit
	output, runErr := runNativeJobGated(ctx, record.Bootstrap.Path, []string{"__setup-worker", record.directory(), string(objectDigest(record))}, nil, environment, &nativeRunGate{
		NotStarted: func() { exit = &treeExit{Kind: "not-started", Keeper: keeper, ObservedAt: time.Now().UTC()} },
		Admit: func(spawn nativeSpawn) error {
			return publish(executionOwnership{SchemaVersion: 1, Claim: record.claim(), Keeper: keeper, Worker: processIdentity(spawn.Info.ProcessId, spawn.Created)})
		},
		TreeExited: func(spawn nativeSpawn) {
			exit = &treeExit{Kind: "tree-empty", Keeper: keeper, ObservedAt: time.Now().UTC(), Worker: processIdentity(spawn.Info.ProcessId, spawn.Created), ActiveProcesses: 0, WorkerExitObserved: true}
		},
	})
	if exit != nil && exit.Kind == "not-started" {
		outcome = workerOutcome{Result: record.Preview, TaskMutation: "settled"}
		outcome.Result.State = "partial"
		outcome.Result.Completion = "known"
		if runErr != nil {
			outcome.Error = runErr.Error()
		}
		return outcome, exit, nil
	}
	if err := strictjson.Decode(output, &outcome); err != nil {
		return workerOutcome{}, exit, errors.Join(runErr, fmt.Errorf("invalid worker result: %w", err))
	}
	if outcome.TaskMutation != "settled" && outcome.TaskMutation != "unknown" {
		return workerOutcome{}, exit, fmt.Errorf("invalid worker task completion")
	}
	return outcome, exit, runErr
}

func runSetupWorker(directory, hash string) (workerOutcome, error) {
	var record executionRequest
	if err := readExecutionJSON(filepath.Join(directory, "request.json"), &record); err != nil {
		return workerOutcome{}, err
	}
	if err := record.validate(); err != nil {
		return workerOutcome{}, err
	}
	if record.directory() != directory || string(objectDigest(record)) != hash {
		return workerOutcome{}, fmt.Errorf("worker request identity changed")
	}
	remaining := time.Until(record.Deadline)
	if remaining <= 0 || remaining > executionTimeout {
		return workerOutcome{}, fmt.Errorf("worker execution deadline is invalid")
	}
	watchdog := time.AfterFunc(remaining+nativeCleanupTimeout, func() { os.Exit(1) })
	defer watchdog.Stop()
	ctx, cancel := context.WithTimeout(context.Background(), remaining)
	defer cancel()
	ctx, stopWatching := watchExecutionCancellation(ctx, record)
	defer stopWatching()
	var ownership executionOwnership
	if err := readExecutionJSON(filepath.Join(directory, "ownership.json"), &ownership); err != nil {
		return workerOutcome{}, err
	}
	self, err := currentProcessIdentity()
	if err != nil {
		return workerOutcome{}, err
	}
	if ownership.SchemaVersion != 1 || ownership.Claim != record.claim() || ownership.Worker != self || !ownership.Keeper.valid() {
		return workerOutcome{}, fmt.Errorf("worker process has no exact ownership")
	}
	alive, err := nativeProcessAlive(ownership.Keeper)
	if err != nil || !alive {
		return workerOutcome{}, fmt.Errorf("keeper identity unavailable")
	}
	process, err := syscall.GetCurrentProcess()
	if err != nil {
		return workerOutcome{}, err
	}
	var member int32
	if ok, _, err := nativeIsProcessInJob.Call(uintptr(process), 0, uintptr(unsafe.Pointer(&member))); ok == 0 || member == 0 {
		return workerOutcome{}, fmt.Errorf("worker is outside its Job: %v", err)
	}
	executable, err := os.Executable()
	if err != nil || executable != record.Bootstrap.Path {
		return workerOutcome{}, fmt.Errorf("worker bootstrap changed")
	}
	for _, input := range append([]File{record.Bootstrap}, record.Inputs...) {
		if err := verifyExecutionInput(input); err != nil {
			return workerOutcome{}, err
		}
	}
	observed, err := newOwner(nativeMachine{}).observe(ctx, record.Request)
	if err != nil || observed.request.Token != record.Token || observed.terminal != nil {
		return workerOutcome{}, fmt.Errorf("worker admission changed: %v", err)
	}
	claim := record.claim()
	if err := host.InspectSetupMaintenance(record.Request.StateRoot, &claim); err != nil {
		return workerOutcome{}, err
	}
	installer := &installer{machine: nativeMachine{}, claim: &claim}
	result, workErr := installer.Execute(ctx, record.Request)
	outcome := workerOutcome{Result: result, TaskMutation: "settled"}
	if errors.Is(workErr, errTaskMutationUnknown) || errors.Is(workErr, errNativeCleanupUnknown) {
		outcome.TaskMutation = "unknown"
	}
	if workErr == nil {
		outcome.Result, workErr = PublishTarget(ctx, record.Request, result)
	}
	if workErr == nil {
		outcome.inspectPublication(record.Request)
	}
	if workErr != nil {
		outcome.Error = workErr.Error()
	}
	return outcome, nil
}

// RunInternal accepts only the finite keeper and exact-process worker roles.
func RunInternal(args []string, stdin io.Reader, stdout, stderr io.Writer) (bool, int) {
	if len(args) == 0 || args[0] != "__setup-keeper" && args[0] != "__setup-worker" {
		return false, 0
	}
	watchdog := time.AfterFunc(bootstrapInputTimeout+executionTimeout+2*nativeCleanupTimeout, func() { os.Exit(1) })
	defer watchdog.Stop()
	var value any
	var err error
	if args[0] == "__setup-keeper" && len(args) == 3 {
		value, err = runScheduledKeeper(args[1], args[2])
	} else if args[0] == "__setup-worker" && len(args) == 3 {
		value, err = runSetupWorker(args[1], args[2])
	} else {
		err = fmt.Errorf("invalid internal setup role")
	}
	if value != nil {
		_ = json.NewEncoder(stdout).Encode(value)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return true, 1
	}
	return true, 0
}
