package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/BramVR/blender-box/internal/orchestrator"
)

func TestRuntimeChecksAndCapturesTheWindowsVirtualDesktop(t *testing.T) {
	fake := &fakeProcessRunner{outputs: [][]byte{nil, nil}}
	runtime := NewRuntime(fake)
	path := `C:\Run\screenshots\desktop's proof.png`

	if err := runtime.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Capture(context.Background(), path); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(fake.executables, []string{"powershell.exe", "powershell.exe"}) {
		t.Fatalf("executables = %v", fake.executables)
	}
	check := decodePowerShellCommand(t, fake.arguments[0])
	if !strings.Contains(check, "System.Drawing.Bitmap") || !strings.Contains(check, "System.Windows.Forms.SystemInformation") || strings.Contains(check, "VirtualScreen") || strings.Contains(check, "CopyFromScreen") {
		t.Fatalf("check script = %q", check)
	}
	capture := decodePowerShellCommand(t, fake.arguments[1])
	for _, required := range []string{"SystemInformation]::VirtualScreen", "CopyFromScreen", "CaptureBlt", base64.StdEncoding.EncodeToString([]byte(path))} {
		if !strings.Contains(capture, required) {
			t.Fatalf("capture script lacks %q: %q", required, capture)
		}
	}
	if strings.Contains(capture, path) {
		t.Fatalf("capture path was interpolated into PowerShell: %q", capture)
	}
}

func decodePowerShellCommand(t *testing.T, arguments []string) string {
	t.Helper()
	assertArguments(t, arguments[:3], "-NoLogo", "-NoProfile", "-NonInteractive")
	if len(arguments) != 5 || arguments[3] != "-EncodedCommand" {
		t.Fatalf("PowerShell arguments = %v", arguments)
	}
	encoded, err := base64.StdEncoding.DecodeString(arguments[4])
	if err != nil || len(encoded)%2 != 0 {
		t.Fatalf("encoded PowerShell = %q, error = %v", arguments[4], err)
	}
	units := make([]uint16, len(encoded)/2)
	for index := range units {
		units[index] = binary.LittleEndian.Uint16(encoded[index*2:])
	}
	return string(utf16.Decode(units))
}

func TestProcessOutputLimitCoversNestedMaximumScenarioResult(t *testing.T) {
	inner := bytes.Repeat([]byte{'\\'}, maxScenarioJSON)
	envelope, err := json.Marshal(map[string]any{"executed": true, "result": string(inner)})
	if err != nil {
		t.Fatal(err)
	}
	if len(envelope) <= 2*maxScenarioJSON || len(envelope) > maxProcessOutput {
		t.Fatalf("nested envelope size = %d, process limit = %d", len(envelope), maxProcessOutput)
	}
}

func TestProcessOutputLimitCoversNestedMaximumUnicodeScenarioResult(t *testing.T) {
	padding := strings.Repeat("é", (maxScenarioJSON-128)/2)
	inner := []byte(`{"schema_version":1,"status":"pass","padding":"` + padding + `"}`)
	if len(inner) > maxScenarioJSON {
		t.Fatalf("inner result size = %d", len(inner))
	}
	envelope := []byte(`{"executed":true,"result":` + strconv.QuoteToASCII(string(inner)) + `}`)
	if len(envelope) <= 2*maxScenarioJSON || len(envelope) > maxProcessOutput {
		t.Fatalf("unicode envelope size = %d, process limit = %d", len(envelope), maxProcessOutput)
	}
}

type fakeProcessRunner struct {
	outputs      [][]byte
	errors       []error
	executables  []string
	arguments    [][]string
	environments []map[string]string
}

func TestRuntimeTypesDaemonReadTimeoutAsDeadlineExceeded(t *testing.T) {
	fake := &fakeProcessRunner{
		outputs: [][]byte{[]byte(`{"schema_version":1,"status":"error","command":"call","reason":"timeout","message":"Timed out waiting for Blender"}`)},
		errors:  []error{errors.New("exit status 1")},
	}

	_, err := NewRuntime(fake).Call(context.Background(), DaemonCall{
		Executable:         `C:\Bin\blendersessiond.exe`,
		Name:               "blender-box-test",
		SessionID:          "bss_exact-runtime-session-identity-123456",
		Command:            "execute_code",
		Parameters:         json.RawMessage(`{"code":"pass"}`),
		ReadTimeoutSeconds: 600,
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Call() error = %v, want deadline exceeded", err)
	}
}

func TestRuntimeTreatsExactStoppedSessionAbsenceAsIdempotent(t *testing.T) {
	fake := &fakeProcessRunner{
		outputs: [][]byte{[]byte(`{"schema_version":1,"status":"not-found","session":{"name":"blender-box-test","status":"not-found"}}`)},
		errors:  []error{errors.New("exit status 1")},
	}
	runtime := NewRuntime(fake)
	err := runtime.Stop(context.Background(), DaemonStop{
		Executable:  `C:\Bin\blendersessiond.exe`,
		Name:        "blender-box-test",
		SessionID:   "bss_exact-runtime-session-identity-123456",
		Environment: map[string]string{"BLENDERSESSIOND_STATE_DIR": `C:\Run\daemon`},
	})
	if err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	assertArguments(t, fake.arguments[0], "stop", "--name", "blender-box-test", "--expect-session-id", "bss_exact-runtime-session-identity-123456", "--json")
}

func TestRuntimePreservesStartedIdentityAlongsideProcessError(t *testing.T) {
	fake := &fakeProcessRunner{
		outputs: [][]byte{[]byte(`{"schema_version":1,"status":"started","session":{"session_id":"bss_ambiguous-start-session-identity-123456"}}`)},
		errors:  []error{errors.New("connection closed after response")},
	}
	sessionID, err := NewRuntime(fake).Start(context.Background(), DaemonStart{Executable: `C:\Bin\blendersessiond.exe`, Name: "blender-box-test"})
	if sessionID != "bss_ambiguous-start-session-identity-123456" || err == nil {
		t.Fatalf("Start() Session ID = %q, error = %v", sessionID, err)
	}
}

func TestRuntimeRejectsNotFoundWithAReplacementIdentity(t *testing.T) {
	fake := &fakeProcessRunner{
		outputs: [][]byte{[]byte(`{"schema_version":1,"status":"not-found","session":{"session_id":"bss_replacement-runtime-session-identity-123456"}}`)},
		errors:  []error{errors.New("exit status 1")},
	}
	runtime := NewRuntime(fake)
	err := runtime.Stop(context.Background(), DaemonStop{
		Executable: `C:\Bin\blendersessiond.exe`,
		Name:       "blender-box-test",
		SessionID:  "bss_exact-runtime-session-identity-123456",
	})
	if err == nil {
		t.Fatal("Stop() accepted not-found for a replacement Session identity")
	}
}

func TestRuntimeRejectsReadinessFromReplacementSession(t *testing.T) {
	fake := &fakeProcessRunner{outputs: [][]byte{
		[]byte(`{"schema_version":1,"status":"healthy","session":{"session_id":"bss_replacement-runtime-session-identity-123456","health":{"status":"healthy","process":{"alive":true},"socket":{"answered":true}}}}`),
	}}
	runtime := NewRuntime(fake)
	err := runtime.WaitReady(context.Background(), DaemonReady{
		Executable: `C:\Bin\blendersessiond.exe`,
		Name:       "blender-box-test",
		SessionID:  "bss_expected-runtime-session-identity-123456",
	})
	if err == nil || !strings.Contains(err.Error(), "different Session identity") {
		t.Fatalf("WaitReady() error = %v", err)
	}
}

func TestRuntimeRecoversExactIdentityFromDaemonStatus(t *testing.T) {
	sessionID := orchestrator.SessionID("bss_exact-recovery-session-identity-123456")
	fake := &fakeProcessRunner{outputs: [][]byte{
		[]byte(`{"schema_version":1,"status":"starting","session":{"session_id":"bss_exact-recovery-session-identity-123456"}}`),
		[]byte(`{"schema_version":1,"status":"not-found","session":{"name":"blender-box-test"}}`),
	}}
	runtime := NewRuntime(fake)
	request := DaemonRecover{Executable: `C:\Bin\blendersessiond.exe`, Name: "blender-box-test", Environment: map[string]string{"BLENDERSESSIOND_STATE_DIR": `C:\Run\daemon`}}
	recovered, found, err := runtime.Recover(context.Background(), request)
	if err != nil || !found || recovered != sessionID {
		t.Fatalf("recovered = %q, found = %v, error = %v", recovered, found, err)
	}
	recovered, found, err = runtime.Recover(context.Background(), request)
	if err != nil || found || recovered != "" {
		t.Fatalf("missing recovery = %q, found = %v, error = %v", recovered, found, err)
	}
	for index := range fake.arguments {
		assertArguments(t, fake.arguments[index], "status", "--name", "blender-box-test", "--json")
	}
}

func (fake *fakeProcessRunner) Run(_ context.Context, executable string, arguments []string, environment map[string]string) ([]byte, error) {
	fake.executables = append(fake.executables, executable)
	fake.arguments = append(fake.arguments, append([]string(nil), arguments...))
	copyEnvironment := make(map[string]string, len(environment))
	for key, value := range environment {
		copyEnvironment[key] = value
	}
	fake.environments = append(fake.environments, copyEnvironment)
	output := fake.outputs[0]
	fake.outputs = fake.outputs[1:]
	var err error
	if len(fake.errors) > 0 {
		err = fake.errors[0]
		fake.errors = fake.errors[1:]
	}
	return output, err
}

func TestRuntimeFencesEveryDaemonOperationAndLaunchesExactTask(t *testing.T) {
	sessionID := orchestrator.SessionID("bss_exact-runtime-session-identity-123456")
	fake := &fakeProcessRunner{outputs: [][]byte{
		[]byte("SUCCESS: task started"),
		[]byte(`{"schema_version":1,"status":"started","session":{"session_id":"bss_exact-runtime-session-identity-123456"}}`),
		[]byte(`{"schema_version":1,"status":"unhealthy","session":{"session_id":"bss_exact-runtime-session-identity-123456","health":{"status":"unhealthy","process":{"alive":true},"socket":{"answered":false}}}}`),
		[]byte(`{"schema_version":1,"status":"healthy","session":{"session_id":"bss_exact-runtime-session-identity-123456","health":{"status":"healthy","process":{"alive":true},"socket":{"answered":true}}}}`),
		[]byte(`{"executed":true,"result":"{}"}`),
		[]byte(`{"schema_version":1,"status":"stopped"}`),
	}}
	runtime := NewRuntime(fake)
	runtime.readyPollInterval = 0
	environment := map[string]string{"BLENDERSESSIOND_STATE_DIR": `C:\Run\daemon`}

	if err := runtime.Launch(context.Background(), "BlenderBoxTest"); err != nil {
		t.Fatal(err)
	}
	started, err := runtime.Start(context.Background(), DaemonStart{
		Executable:        `C:\Bin\blendersessiond.exe`,
		Name:              "blender-box-test",
		BlenderExecutable: `C:\Blender\blender.exe`,
		Environment:       environment,
	})
	if err != nil {
		t.Fatal(err)
	}
	if started != sessionID {
		t.Fatalf("Session ID = %q", started)
	}
	if err := runtime.WaitReady(context.Background(), DaemonReady{
		Executable:  `C:\Bin\blendersessiond.exe`,
		Name:        "blender-box-test",
		SessionID:   sessionID,
		Environment: environment,
	}); err != nil {
		t.Fatal(err)
	}
	parameters := json.RawMessage(`{"code":"pass"}`)
	if _, err := runtime.Call(context.Background(), DaemonCall{
		Executable:         `C:\Bin\blendersessiond.exe`,
		Name:               "blender-box-test",
		SessionID:          sessionID,
		Command:            "execute_code",
		Parameters:         parameters,
		ReadTimeoutSeconds: 600,
		Environment:        environment,
	}); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Stop(context.Background(), DaemonStop{
		Executable:  `C:\Bin\blendersessiond.exe`,
		Name:        "blender-box-test",
		SessionID:   sessionID,
		Environment: environment,
	}); err != nil {
		t.Fatal(err)
	}

	wantExecutables := []string{"schtasks.exe", `C:\Bin\blendersessiond.exe`, `C:\Bin\blendersessiond.exe`, `C:\Bin\blendersessiond.exe`, `C:\Bin\blendersessiond.exe`, `C:\Bin\blendersessiond.exe`}
	if !reflect.DeepEqual(fake.executables, wantExecutables) {
		t.Fatalf("executables = %v", fake.executables)
	}
	if !reflect.DeepEqual(fake.arguments[0], []string{"/Run", "/TN", "BlenderBoxTest"}) {
		t.Fatalf("task arguments = %v", fake.arguments[0])
	}
	assertArguments(t, fake.arguments[1], "start", "--name", "blender-box-test", "--blender", `C:\Blender\blender.exe`, "--json")
	assertArguments(t, fake.arguments[2], "status", "--name", "blender-box-test", "--json")
	assertArguments(t, fake.arguments[3], "status", "--name", "blender-box-test", "--json")
	assertArguments(t, fake.arguments[4], "call", "execute_code", "--name", "blender-box-test", "--expect-session-id", string(sessionID), "--read-timeout", "600", "--params", string(parameters), "--json")
	assertArguments(t, fake.arguments[5], "stop", "--name", "blender-box-test", "--expect-session-id", string(sessionID), "--json")
	for index := 1; index < 6; index++ {
		if fake.environments[index]["BLENDERSESSIOND_STATE_DIR"] != environment["BLENDERSESSIOND_STATE_DIR"] {
			t.Fatalf("operation %d lost environment: %v", index, fake.environments[index])
		}
	}
}

func assertArguments(t *testing.T, actual []string, expected ...string) {
	t.Helper()
	if !reflect.DeepEqual(actual, expected) {
		t.Fatalf("arguments = %#v, want %#v", actual, expected)
	}
}
