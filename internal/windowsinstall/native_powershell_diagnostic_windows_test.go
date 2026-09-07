//go:build windows

package windowsinstall

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"
)

type powerShellProbeMember struct {
	PID             uint32
	Created         uint64
	Image           string
	ImageError      string
	InJob           bool
	MembershipError string
	Wait            uint32
	WaitError       string
}

type powerShellProbeSnapshot struct {
	Stage         string
	Total, Active uint32
	Listed        []uint32
	Members       []powerShellProbeMember
	Error         string
}

type powerShellProbeStream struct {
	Kind              string
	Bytes             []byte
	Written, Expected int
	Error             string
	Truncated         bool
}

type powerShellProbeOutcome struct {
	FlagsName, Script    string
	EffectiveFlags       uint32
	RootPID              uint32
	RootCreated          syscall.Filetime
	RootExit             *uint32
	RootExitError        string
	RootExitAfterCleanup *uint32
	Stages               string
	StageError           string
	Snapshots            []powerShellProbeSnapshot
	Streams              []powerShellProbeStream
	OperationErrors      []string
	SupervisionError     string
	CollectorStopped     bool
	Cleanup              []powerShellProbeMember
	CleanupError         string
}

func TestNativePowerShellStdioDiagnostic(t *testing.T) {
	for _, flags := range []struct {
		name  string
		value uint32
	}{
		{"current", 0x00000004 | 0x00000008},
		{"without-detached", 0x00000004},
	} {
		for _, script := range []string{"raw", "current-prologue"} {
			t.Run(flags.name+"/"+script, func(t *testing.T) {
				probeNativePowerShell(t, flags.name, flags.value, script)
			})
		}
	}
}

func probeNativePowerShell(t *testing.T, flagsName string, flags uint32, scriptKind string) {
	out := powerShellProbeOutcome{FlagsName: flagsName, Script: scriptKind, EffectiveFlags: flags | 0x08080000 | syscall.CREATE_UNICODE_ENVIRONMENT}
	addError := func(err error) {
		if err != nil {
			out.OperationErrors = append(out.OperationErrors, err.Error())
		}
	}
	defer func() {
		data, err := json.Marshal(out)
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Printf("POWERSHELL_STDIO_DIAGNOSTIC %s\n", data)
	}()
	directory := t.TempDir()
	stagePath := filepath.Join(directory, "stages.txt")
	id, err := newID("powershell-stdio-")
	if err != nil {
		addError(err)
		t.Error(err)
		return
	}
	eventName := `Local\BlenderBox-` + id
	var events [2]syscall.Handle
	for i, name := range []string{eventName, eventName + "-release"} {
		wide, err := syscall.UTF16PtrFromString(name)
		if err != nil {
			addError(err)
			t.Error(err)
			return
		}
		handle, _, err := testCreateEvent.Call(0, 0, 0, uintptr(unsafe.Pointer(wide)))
		if handle == 0 {
			addError(err)
			t.Error(err)
			return
		}
		events[i] = syscall.Handle(handle)
		defer syscall.CloseHandle(events[i])
	}
	quote := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	script := "$probeFile=" + quote(stagePath) + "\n" + `[IO.File]::AppendAllText($probeFile,'entry'+[Environment]::NewLine)
$probeReady=[Threading.EventWaitHandle]::OpenExisting(` + quote(eventName) + `)
$probeRelease=[Threading.EventWaitHandle]::OpenExisting(` + quote(eventName+"-release") + `)
function ProbeStage([string]$stage) {
 [IO.File]::AppendAllText($probeFile,$stage+[Environment]::NewLine)
 [void]$probeReady.Set()
 if(-not $probeRelease.WaitOne(10000)){throw 'probe release deadline exceeded'}
}
try {
 ProbeStage 'events-open'
`
	if scriptKind == "raw" {
		script += `$reader=[IO.StreamReader]::new([Console]::OpenStandardInput(),[Text.UTF8Encoding]::new($false))
$rawInput=$reader.ReadToEnd()
ProbeStage ('stdin-read:'+ $rawInput)
$rawOut=[Console]::OpenStandardOutput()
$rawErr=[Console]::OpenStandardError()
$bytes=[Text.UTF8Encoding]::new($false).GetBytes('RAW_STDOUT_日本語'+[Environment]::NewLine)
$rawOut.Write($bytes,0,$bytes.Length);$rawOut.Flush()
$bytes=[Text.UTF8Encoding]::new($false).GetBytes('RAW_STDERR_日本語'+[Environment]::NewLine)
$rawErr.Write($bytes,0,$bytes.Length);$rawErr.Flush()
ProbeStage 'raw-streams-flushed'
[Console]::Out.WriteLine('CONSOLE_OUT_SENTINEL');[Console]::Out.Flush()
ProbeStage 'console-out-flushed'
Write-Output 'PIPELINE_SENTINEL'
ProbeStage 'pipeline-written'
exit 23
`
	} else {
		script += `$ErrorActionPreference='Stop'
$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')
ProbeStage 'before-input-encoding'
[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)
ProbeStage 'after-input-encoding'
[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)
ProbeStage 'after-output-encoding'
$OutputEncoding=[Console]::OutputEncoding
ProbeStage 'before-stdin-read'
$r=ConvertFrom-Json ([Console]::In.ReadToEnd())
ProbeStage 'after-stdin-read'
` + nativeFunctions + `
ProbeStage 'before-action'
$r | ConvertTo-Json -Compress
ProbeStage 'after-action'
exit 24
`
	}
	script += `} catch {
 [IO.File]::AppendAllText($probeFile,'caught:'+ $_.Exception.ToString()+[Environment]::NewLine)
 [void]$probeReady.Set()
 [void]$probeRelease.WaitOne(10000)
 exit 29
}`
	units := utf16.Encode([]rune(script))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:], unit)
	}
	system, err := systemDirectory()
	if err != nil {
		addError(err)
		t.Error(err)
		return
	}
	job, err := newNativeJob()
	if err != nil {
		addError(err)
		t.Error(err)
		return
	}
	defer job.close()
	var files [6]*os.File
	for i := 0; i < len(files); i += 2 {
		files[i], files[i+1], err = os.Pipe()
		if err != nil {
			addError(err)
			t.Error(err)
			return
		}
		defer files[i].Close()
		defer files[i+1].Close()
	}
	var spawn nativeSpawn
	held := make(map[uint32]nativeMember)
	api := nativeMemberWindows{job.handle}
	memberRow := func(member nativeMember, deadline time.Time) powerShellProbeMember {
		row := powerShellProbeMember{PID: member.pid, Created: member.created}
		var inJob uint32
		if ok, _, err := nativeIsProcessInJob.Call(member.handle, uintptr(job.handle), uintptr(unsafe.Pointer(&inJob))); ok == 0 {
			row.MembershipError = err.Error()
		} else if inJob != 1 {
			row.MembershipError = "process is outside exact probe Job"
		}
		row.InJob = inJob == 1
		var image [1024]uint16
		size := uint32(len(image))
		if ok, _, err := testQueryProcessImage.Call(member.handle, 0, uintptr(unsafe.Pointer(&image[0])), uintptr(unsafe.Pointer(&size))); ok == 0 || size > uint32(len(image)) {
			row.ImageError = fmt.Sprintf("image query: %v", err)
		} else {
			row.Image = syscall.UTF16ToString(image[:size])
		}
		var err error
		row.Wait, err = syscall.WaitForSingleObject(syscall.Handle(member.handle), nativeWaitMillis(deadline))
		if err != nil {
			row.WaitError = err.Error()
		} else if row.Wait != syscall.WAIT_OBJECT_0 && row.Wait != syscall.WAIT_TIMEOUT {
			row.WaitError = fmt.Sprintf("unexpected process wait result %d", row.Wait)
		}
		if row.MembershipError != "" || row.WaitError != "" {
			t.Error("probe member authority or wait evidence incomplete")
		}
		return row
	}
	snapshot := func(stage string) {
		row := powerShellProbeSnapshot{Stage: stage}
		counts, countErr := api.counts()
		row.Total, row.Active = counts.total, counts.active
		list, listErr := api.list()
		row.Listed = list.pids
		if countErr != nil {
			row.Error += countErr.Error()
		}
		if listErr != nil {
			row.Error += listErr.Error()
		}
		for _, pid := range list.pids {
			member, found := held[pid]
			if !found {
				var err error
				member, err = api.open(pid)
				if err != nil {
					row.Error += fmt.Sprintf(" pid=%d: %v", pid, err)
					continue
				}
				held[pid] = member
			}
			row.Members = append(row.Members, memberRow(member, time.Now()))
		}
		out.Snapshots = append(out.Snapshots, row)
		if row.Error != "" {
			t.Error("probe Job snapshot incomplete")
		}
	}
	streams := make(chan powerShellProbeStream, 3)
	streamCount := 0
	defer func() {
		deadline := time.Now().Add(nativeCleanupTimeout)
		if spawn.Info.Process != 0 {
			if err := job.settle(deadline); err != nil {
				out.SupervisionError = err.Error()
			}
			snapshot("after-cleanup")
			type identity struct {
				pid     uint32
				created uint64
			}
			seen := make(map[identity]bool)
			addCleanup := func(member nativeMember) {
				key := identity{member.pid, member.created}
				if !seen[key] {
					seen[key] = true
					out.Cleanup = append(out.Cleanup, memberRow(member, deadline))
				}
			}
			root := nativeMember{uintptr(spawn.Info.Process), spawn.Info.ProcessId, uint64(spawn.Created.HighDateTime)<<32 | uint64(spawn.Created.LowDateTime)}
			addCleanup(root)
			for _, member := range held {
				addCleanup(member)
			}
			if job.collector != nil {
				select {
				case <-job.collector.done:
					out.CollectorStopped = true
					for _, member := range job.collector.members.held {
						addCleanup(member)
					}
				default:
					out.CleanupError += " collector did not stop; lifetime member evidence unavailable"
				}
			}
			for _, row := range out.Cleanup {
				if row.Wait != syscall.WAIT_OBJECT_0 || row.MembershipError != "" || row.WaitError != "" {
					out.CleanupError += fmt.Sprintf(" pid=%d wait=%d membership_error=%s wait_error=%s", row.PID, row.Wait, row.MembershipError, row.WaitError)
				}
			}
			for _, member := range held {
				api.close(member.handle)
			}
			if out.Cleanup[0].Wait == syscall.WAIT_OBJECT_0 {
				var code uint32
				if err := syscall.GetExitCodeProcess(spawn.Info.Process, &code); err == nil {
					out.RootExitAfterCleanup = &code
				} else {
					out.CleanupError += " root exit query: " + err.Error()
				}
			}
			if out.CleanupError != "" || out.SupervisionError != "" {
				t.Error("probe cleanup/supervision evidence requires review")
			}
			syscall.CloseHandle(spawn.Info.Process)
			syscall.CloseHandle(spawn.Info.Thread)
		}
		timer := time.NewTimer(max(time.Until(deadline), 0))
		defer timer.Stop()
		receive := func(stream powerShellProbeStream) {
			out.Streams = append(out.Streams, stream)
			if stream.Truncated || stream.Kind != "stdin" && stream.Error != "" {
				t.Error("probe output stream incomplete")
			}
		}
		for i := 0; i < streamCount; i++ {
			select {
			case stream := <-streams:
				receive(stream)
				continue
			default:
			}
			select {
			case stream := <-streams:
				receive(stream)
			case <-timer.C:
				for _, file := range files {
					file.Close()
				}
				out.CleanupError += " pipe drain deadline exceeded"
				t.Error("probe pipe drain deadline exceeded")
				i = streamCount
			}
		}
		file, err := os.Open(stagePath)
		if err != nil {
			out.StageError = err.Error()
		} else {
			data, err := io.ReadAll(io.LimitReader(file, 16385))
			file.Close()
			out.Stages = string(data)
			if err != nil {
				out.StageError = err.Error()
				t.Error("probe stage file read failed")
			}
			if len(data) > 16384 {
				out.StageError += " stage file exceeds limit"
				out.Stages = string(data[:16384])
				t.Error("probe stage file exceeds limit")
			}
		}
	}()
	executable := filepath.Join(system, "WindowsPowerShell", "v1.0", "powershell.exe")
	spawn, err = job.startFlags(executable, []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded)}, powerShellEnvironment(os.Environ(), system), [3]*os.File{files[0], files[3], files[5]}, flags)
	out.RootPID, out.RootCreated = spawn.Info.ProcessId, spawn.Created
	files[0].Close()
	files[3].Close()
	files[5].Close()
	if err != nil {
		addError(err)
		t.Error(err)
		return
	}
	if err := job.collect(spawn); err != nil {
		addError(err)
		t.Error(err)
		return
	}
	for i, kind := range []string{"stdout", "stderr"} {
		file := files[2+i*2]
		streamCount++
		go func() {
			data, err := io.ReadAll(io.LimitReader(file, 65537))
			row := powerShellProbeStream{Kind: kind, Bytes: data}
			if err != nil {
				row.Error = err.Error()
			}
			if len(data) > 65536 {
				row.Truncated = true
				row.Bytes = data[:65536]
			}
			streams <- row
		}()
	}
	streamCount++
	go func() {
		input := []byte(`{"value":"Données 日本語 🎨"}`)
		n, err := files[1].Write(input)
		closeErr := files[1].Close()
		row := powerShellProbeStream{Kind: "stdin", Written: n, Expected: len(input)}
		if err != nil {
			row.Error = err.Error()
		}
		if closeErr != nil {
			row.Error += closeErr.Error()
		}
		streams <- row
	}()
	if result, _, err := nativeResumeThread.Call(uintptr(spawn.Info.Thread)); result != 1 {
		addError(fmt.Errorf("resume=%d: %v", result, err))
		t.Error("probe resume failed")
		return
	}
	deadline := time.Now().Add(15 * time.Second)
	waitHandles := [2]syscall.Handle{spawn.Info.Process, events[0]}
	waitMultiple := nativeProcessKernel.NewProc("WaitForMultipleObjects")
	for count := 0; count < 16; count++ {
		wait, _, err := waitMultiple.Call(2, uintptr(unsafe.Pointer(&waitHandles[0])), 0, uintptr(nativeWaitMillis(deadline)))
		if wait == syscall.WAIT_OBJECT_0 {
			var code uint32
			if err := syscall.GetExitCodeProcess(spawn.Info.Process, &code); err != nil {
				out.RootExitError = err.Error()
				t.Error("probe root exit code unavailable")
			} else {
				out.RootExit = &code
			}
			snapshot("root-exit")
			return
		}
		if wait != syscall.WAIT_OBJECT_0+1 {
			addError(fmt.Errorf("ready-or-exit wait=%d: %v", wait, err))
			t.Error("probe readiness deadline or wait failure")
			return
		}
		snapshot(fmt.Sprintf("script-checkpoint-%d", count))
		if ok, _, err := testSetEvent.Call(uintptr(events[1])); ok == 0 {
			addError(err)
			t.Error(err)
			return
		}
	}
	addError(fmt.Errorf("probe checkpoint limit exceeded"))
	t.Error("probe checkpoint limit exceeded")
}
