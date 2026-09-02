package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windows"
)

type fakeSSH struct {
	stdout []byte
	host   string
	args   []string
	stdin  []byte
}

type fakeRunService struct {
	runIntent      orchestrator.RunIntent
	statusRun      orchestrator.RunID
	stopRun        orchestrator.RunID
	statusDeadline time.Time
	stopDeadline   time.Time
	statusResult   orchestrator.StatusResult
	stopResult     orchestrator.StopResult
}

func (fake *fakeRunService) Run(_ context.Context, intent orchestrator.RunIntent) (orchestrator.RunResult, error) {
	fake.runIntent = intent
	return orchestrator.RunResult{
		SchemaVersion: 1,
		RunID:         intent.RunID,
		RequestID:     intent.RequestID,
		SessionID:     "bss_exact-cli-session-identity-123456",
		State:         orchestrator.StateComplete,
		Evidence:      orchestrator.EvidenceManifest{SchemaVersion: 1},
		Cleanup: orchestrator.CleanupState{
			SessionStopped: true,
			PayloadRemoved: true,
			RunRootRemoved: true,
			LockReleased:   true,
		},
	}, nil
}

func (fake *fakeRunService) Status(ctx context.Context, _ target.Target, runID orchestrator.RunID) (orchestrator.StatusResult, error) {
	fake.statusRun = runID
	fake.statusDeadline, _ = ctx.Deadline()
	return fake.statusResult, nil
}

func (fake *fakeRunService) Stop(ctx context.Context, _ target.Target, runID orchestrator.RunID) (orchestrator.StopResult, error) {
	fake.stopRun = runID
	fake.stopDeadline, _ = ctx.Deadline()
	return fake.stopResult, nil
}

func TestStatusAndStopCommandsEmitExactVersionedResults(t *testing.T) {
	targetPath := writeTarget(t, t.TempDir())
	runID := orchestrator.RunID("bbx_01CLIRUNIDENTITY000000000000")
	requestID := orchestrator.RequestID("req_01CLIREQUESTIDENTITY000000")
	sessionID := orchestrator.SessionID("bss_exact-cli-session-identity-123456")
	service := &fakeRunService{
		statusResult: orchestrator.StatusResult{
			SchemaVersion: 1,
			RunID:         runID,
			RequestID:     requestID,
			State:         orchestrator.StateRunning,
			SessionID:     sessionID,
		},
		stopResult: orchestrator.StopResult{
			SchemaVersion: 1,
			RunID:         runID,
			RequestID:     requestID,
			SessionID:     sessionID,
			Status:        "settled",
			Cleanup: orchestrator.CleanupState{
				SessionStopped: true,
				PayloadRemoved: true,
				RunRootRemoved: true,
				LockReleased:   true,
			},
		},
	}

	for _, command := range []string{"status", "stop"} {
		t.Run(command, func(t *testing.T) {
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			started := time.Now()
			exitCode := Run(context.Background(), []string{
				command,
				"--target", targetPath,
				"--run", string(runID),
				"--timeout", "45s",
				"--json",
			}, strings.NewReader(""), &stdout, &stderr, Dependencies{Runner: service})
			if exitCode != 0 || stderr.Len() != 0 {
				t.Fatalf("exit = %d, stderr = %q", exitCode, stderr.String())
			}
			var envelope struct {
				SchemaVersion int                    `json:"schema_version"`
				RunID         orchestrator.RunID     `json:"run_id"`
				SessionID     orchestrator.SessionID `json:"session_id"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &envelope); err != nil {
				t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
			}
			if envelope.SchemaVersion != 1 || envelope.RunID != runID || envelope.SessionID != sessionID {
				t.Fatalf("result = %+v", envelope)
			}
			deadline := service.statusDeadline
			calledRun := service.statusRun
			if command == "stop" {
				deadline = service.stopDeadline
				calledRun = service.stopRun
			}
			if calledRun != runID || deadline.Before(started.Add(44*time.Second)) || deadline.After(started.Add(46*time.Second)) {
				t.Fatalf("call = %q, deadline = %s", calledRun, deadline)
			}
		})
	}
}

func TestRunCommandEmitsVersionedJSONAndPassesBoundedIntent(t *testing.T) {
	root := t.TempDir()
	targetPath := writeTarget(t, root)
	if err := os.WriteFile(filepath.Join(root, "scenario.py"), []byte("print('slice 0')\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	payloadPath := filepath.Join(root, "payload.json")
	payloadJSON := `{"schema_version":1,"files":[{"source":"scenario.py","destination":"scenario.py"}],"scenario":{"script":"scenario.py","read_timeout_seconds":600,"capture_viewport":true}}`
	if err := os.WriteFile(payloadPath, []byte(payloadJSON), 0o600); err != nil {
		t.Fatal(err)
	}
	evidenceDir := filepath.Join(root, "evidence")
	service := &fakeRunService{}
	now := time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC)
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run(context.Background(), []string{
		"run",
		"--target", targetPath,
		"--payload", payloadPath,
		"--evidence-dir", evidenceDir,
		"--timeout", "30m",
		"--json",
	}, strings.NewReader(""), &stdout, &stderr, Dependencies{
		Runner: service,
		Now:    func() time.Time { return now },
		NewIdentities: func() (orchestrator.RunID, orchestrator.RequestID, string, error) {
			return "bbx_01CLIRUNIDENTITY000000000000", "req_01CLIREQUESTIDENTITY000000", "ctl_cli-test", nil
		},
	})

	if exitCode != 0 || stderr.String() != "RUN_ID=bbx_01CLIRUNIDENTITY000000000000\n" {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr.String())
	}
	if service.runIntent.RunID != "bbx_01CLIRUNIDENTITY000000000000" || service.runIntent.RequestID != "req_01CLIREQUESTIDENTITY000000" {
		t.Fatalf("intent identities = %+v", service.runIntent)
	}
	if service.runIntent.Deadline != now.Add(30*time.Minute) || service.runIntent.EvidenceDir != evidenceDir {
		t.Fatalf("intent bounds = %+v", service.runIntent)
	}
	if err := service.runIntent.Payload.Validate(); err != nil {
		t.Fatalf("CLI passed an invalid payload: %v", err)
	}
	var result orchestrator.RunResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not one JSON result: %v\n%s", err, stdout.String())
	}
	if result.SchemaVersion != 1 || result.RunID != service.runIntent.RunID || result.SessionID == "" || !result.Cleanup.Known() {
		t.Fatalf("result = %+v", result)
	}
}

func TestRunPublishesRunIDBeforeTargetValidation(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Run(context.Background(), []string{
		"run", "--target", filepath.Join(t.TempDir(), "missing.json"), "--payload", "missing.json", "--json",
	}, strings.NewReader(""), &stdout, &stderr, Dependencies{
		NewIdentities: func() (orchestrator.RunID, orchestrator.RequestID, string, error) {
			return "bbx_01EARLYRUNIDENTITY00000000000", "req_01EARLYREQUESTIDENTITY00000", "ctl_cli-test", nil
		},
	})
	if exitCode != 1 || !strings.HasPrefix(stderr.String(), "RUN_ID=bbx_01EARLYRUNIDENTITY00000000000\n") {
		t.Fatalf("exit = %d, stderr = %q", exitCode, stderr.String())
	}
}

func TestWindowsSetupPlansWithoutSSHAndRequiresApplyForWrite(t *testing.T) {
	root := t.TempDir()
	targetPath := writeTarget(t, root)
	hostBinary := filepath.Join(root, "blender-box.exe")
	contents := []byte("bounded-host-binary")
	if err := os.WriteFile(hostBinary, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &fakeSSH{}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := Run(context.Background(), []string{
		"windows", "setup",
		"--target", targetPath,
		"--host-binary", hostBinary,
		"--json",
	}, strings.NewReader(""), &stdout, &stderr, Dependencies{SSH: fake})
	if exitCode != 0 || stderr.Len() != 0 || fake.host != "" {
		t.Fatalf("plan exit = %d, stderr = %q, SSH host = %q", exitCode, stderr.String(), fake.host)
	}
	var planned windows.SetupResult
	if err := json.Unmarshal(stdout.Bytes(), &planned); err != nil {
		t.Fatal(err)
	}
	if planned.SchemaVersion != 1 || planned.Status != "plan" || planned.Applied || planned.HostSize != int64(len(contents)) {
		t.Fatalf("plan = %+v", planned)
	}

	fake.stdout, _ = json.Marshal(windows.SetupResult{
		SchemaVersion: 1,
		Status:        "applied",
		Applied:       true,
		HostSize:      planned.HostSize,
		HostSHA256:    planned.HostSHA256,
	})
	stdout.Reset()
	stderr.Reset()
	exitCode = Run(context.Background(), []string{
		"windows", "setup",
		"--target", targetPath,
		"--host-binary", hostBinary,
		"--apply",
		"--json",
	}, strings.NewReader(""), &stdout, &stderr, Dependencies{SSH: fake})
	if exitCode != 0 || stderr.Len() != 0 || fake.host != "windows-test" || string(fake.stdin) != string(contents) {
		t.Fatalf("apply exit = %d, stderr = %q, SSH host = %q, stdin = %q", exitCode, stderr.String(), fake.host, fake.stdin)
	}
}

func writeTarget(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, "target.json")
	contents := `{
  "schema_version": 1,
  "ssh_alias": "windows-test",
  "ssh_user": "test-user",
  "work_root": "C:\\BlenderBoxTest",
  "interactive_user": "test-user",
  "task_name": "BlenderBoxTest",
  "blender_executable": "C:\\Program Files\\Blender Foundation\\Blender 5.2\\blender.exe",
  "session_broker_executable": "C:\\BlenderBoxTest\\bin\\blendersessiond.exe",
  "host_executable": "C:\\BlenderBoxTest\\bin\\blender-box.exe"
}`
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (fake *fakeSSH) Run(
	_ context.Context,
	host string,
	args []string,
	stdin []byte,
) ([]byte, error) {
	fake.host = host
	fake.args = append([]string(nil), args...)
	fake.stdin = append([]byte(nil), stdin...)
	return fake.stdout, nil
}

func TestWindowsCheckPrintsVersionedJSONWithoutRemoteWrites(t *testing.T) {
	targetPath := filepath.Join(t.TempDir(), "target.json")
	targetJSON := `{
  "schema_version": 1,
  "ssh_alias": "windows-test",
  "ssh_user": "test-user",
  "work_root": "C:\\BlenderBoxTest",
  "interactive_user": "test-user",
  "task_name": "BlenderBoxTest",
  "blender_executable": "C:\\Program Files\\Blender Foundation\\Blender 5.2\\blender.exe",
  "session_broker_executable": "C:\\BlenderBoxTest\\bin\\blendersessiond.exe",
  "host_executable": "C:\\BlenderBoxTest\\bin\\blender-box.exe"
}`
	if err := os.WriteFile(targetPath, []byte(targetJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	checks := make([]map[string]any, 0, 9)
	for _, id := range []string{
		"host.windows",
		"host.console-user",
		"host.ssh-user",
		"host.limited-token-policy",
		"blender.executable",
		"daemon.executable",
		"host.executable",
		"work-root.access",
		"task.interactive",
	} {
		checks = append(checks, map[string]any{"id": id, "passed": true, "required": true})
	}
	checks[0]["actual"] = "Microsoft Windows 11 Pro"
	checks[0]["expected"] = "Windows"
	checks[0]["message"] = "Windows host detected."
	remote := map[string]any{
		"schema_version": 1,
		"status":         "pass",
		"checks":         checks,
	}
	remoteJSON, err := json.Marshal(remote)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeSSH{stdout: remoteJSON}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := Run(
		context.Background(),
		[]string{"windows", "check", "--target", targetPath, "--json"},
		strings.NewReader(""),
		&stdout,
		&stderr,
		Dependencies{SSH: fake},
	)

	if exitCode != 0 {
		t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr.String())
	}
	if fake.host != "windows-test" {
		t.Fatalf("SSH host = %q", fake.host)
	}
	joinedArguments := strings.Join(fake.args, " ")
	encodedIndex := -1
	for index, argument := range fake.args {
		if argument == "-EncodedCommand" {
			encodedIndex = index + 1
			break
		}
	}
	if encodedIndex < 0 || encodedIndex >= len(fake.args) {
		t.Fatalf("SSH arguments have no PowerShell bootstrap: %q", fake.args)
	}
	if len(joinedArguments) >= 8191 {
		t.Fatalf("SSH arguments exceed the default Windows command limit: %d", len(joinedArguments))
	}
	bootstrapBytes, err := base64.StdEncoding.DecodeString(fake.args[encodedIndex])
	if err != nil || len(bootstrapBytes)%2 != 0 {
		t.Fatalf("invalid PowerShell bootstrap: %v", err)
	}
	bootstrap := make([]byte, len(bootstrapBytes)/2)
	for index := range bootstrap {
		bootstrap[index] = byte(binary.LittleEndian.Uint16(bootstrapBytes[index*2:]))
	}
	if !strings.Contains(string(bootstrap), "ReadToEnd() | Invoke-Expression") {
		t.Fatalf("PowerShell bootstrap does not execute streamed input: %q", bootstrap)
	}
	if strings.Contains(string(bootstrap), "function ") || len(bootstrap) >= 256 {
		t.Fatalf("PowerShell bootstrap contains the inspection script: %q", bootstrap)
	}
	remoteCommand := strings.ToLower(string(fake.stdin))
	marker := "frombase64string('"
	configStart := strings.Index(remoteCommand, marker)
	if configStart < 0 {
		t.Fatalf("PowerShell input has no encoded target contract")
	}
	configStart += len(marker)
	configEnd := strings.Index(remoteCommand[configStart:], "')")
	if configEnd < 0 {
		t.Fatalf("PowerShell input has an incomplete target contract")
	}
	configJSON, err := base64.StdEncoding.DecodeString(string(fake.stdin)[configStart : configStart+configEnd])
	if err != nil {
		t.Fatalf("PowerShell input has invalid target Base64: %v", err)
	}
	for _, forbidden := range []string{
		"register-scheduledtask",
		"start-scheduledtask",
		"new-item",
		"set-content",
		"remove-item",
	} {
		if strings.Contains(remoteCommand, forbidden) {
			t.Errorf("check command contains remote write %q", forbidden)
		}
	}
	for _, required := range []string{
		"securityidentifier",
		"windowsidentity]::getcurrent()",
		"controllercanexecute",
		"iscallback",
		"commonace",
		"trustedmanagers",
		"requiredprivilege",
		"enablelua",
		"utf8encoding]::new($false)",
		"rawsecuritydescriptor",
		"getsecuritydescriptor(7)",
		"[int]$ace.aceflags",
		"genericexecute",
		"genericread",
		"expand-filesystemmask",
		"taskexecute",
		"reparsepoint",
		"normalize-path",
		"allowmask",
		"denymask",
		"inheritonly",
		"protectchildren",
		"s-1-3-0",
		"trustedwriters",
		"try { $acl = get-acl",
		"win32_operatingsystem -erroraction silentlycontinue",
		"takeownership",
		"getdirectoryname",
		"getpathroot",
		"get-volume",
		"drivetype",
		"$parent -ieq $root",
		"deletechild",
		"actions[0].execute",
		"actions[0].arguments",
		"actions[0].workingdirectory",
		"allowdemandstart",
		"allowhardterminate",
		"disallowstartifonbatteries",
		"stopifgoingonbatteries",
		"runonlyifidle",
		"runonlyifnetworkavailable",
		"restartcount",
		"volatile",
		"blender_executable",
		"session_broker_executable",
		"host_executable",
	} {
		if !strings.Contains(remoteCommand, required) {
			t.Errorf("check command does not validate %q", required)
		}
	}
	if strings.Contains(remoteCommand, "get-command") {
		t.Error("check command resolves executables from the SSH user's PATH")
	}
	var checkInput struct {
		ExpectedTaskArguments string `json:"expected_task_arguments"`
	}
	if err := json.Unmarshal(configJSON, &checkInput); err != nil {
		t.Fatalf("check input is not JSON: %v", err)
	}
	if checkInput.ExpectedTaskArguments != `host run-request --state-root "C:\BlenderBoxTest"` {
		t.Fatalf("task arguments use the wrong Windows quoting: %q", checkInput.ExpectedTaskArguments)
	}

	var result struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, stdout.String())
	}
	if result.SchemaVersion != 1 || result.Status != "pass" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}
