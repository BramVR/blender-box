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

	remote := map[string]any{
		"schema_version": 1,
		"status":         "pass",
		"checks": []map[string]any{
			{
				"id":       "host.windows",
				"passed":   true,
				"required": true,
				"actual":   "Microsoft Windows 11 Pro",
				"expected": "Windows",
				"message":  "Windows host detected.",
			},
		},
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
	if !strings.Contains(strings.Join(fake.args, " "), "-EncodedCommand") {
		t.Fatalf("SSH arguments do not use an encoded PowerShell command: %q", fake.args)
	}
	encodedIndex := -1
	for index, argument := range fake.args {
		if argument == "-EncodedCommand" {
			encodedIndex = index + 1
			break
		}
	}
	if encodedIndex < 0 || encodedIndex >= len(fake.args) {
		t.Fatalf("missing encoded command payload: %q", fake.args)
	}
	commandBytes, err := base64.StdEncoding.DecodeString(fake.args[encodedIndex])
	if err != nil {
		t.Fatalf("invalid encoded command: %v", err)
	}
	if len(commandBytes)%2 != 0 {
		t.Fatalf("encoded command has odd UTF-16 byte count: %d", len(commandBytes))
	}
	codeUnits := make([]uint16, len(commandBytes)/2)
	for index := range codeUnits {
		codeUnits[index] = binary.LittleEndian.Uint16(commandBytes[index*2:])
	}
	var decoded strings.Builder
	for _, codeUnit := range codeUnits {
		decoded.WriteRune(rune(codeUnit))
	}
	remoteCommand := strings.ToLower(decoded.String())
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
		"normalize-path",
		"allowmask",
		"denymask",
		"actions[0].execute",
		"actions[0].arguments",
		"actions[0].workingdirectory",
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
	if !bytes.Contains(fake.stdin, []byte(`"work_root":"C:\\BlenderBoxTest"`)) {
		t.Fatalf("check input does not contain target contract: %s", fake.stdin)
	}
	var checkInput struct {
		ExpectedTaskArguments string `json:"expected_task_arguments"`
	}
	if err := json.Unmarshal(fake.stdin, &checkInput); err != nil {
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
