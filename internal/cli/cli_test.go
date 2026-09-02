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
)

type fakeSSH struct {
	stdout []byte
	host   string
	args   []string
	stdin  []byte
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

	checks := make([]map[string]any, 0, 8)
	for _, id := range []string{
		"host.windows",
		"host.console-user",
		"host.ssh-user",
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
		"trustedmanagers",
		"requiredprivilege",
		"utf8encoding]::new($false)",
		"rawsecuritydescriptor",
		"getsecuritydescriptor(7)",
		"[int]$ace.aceflags",
		"genericexecute",
		"taskexecute",
		"reparsepoint",
		"normalize-path",
		"allowmask",
		"denymask",
		"inheritonly",
		"trustedwriters",
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
