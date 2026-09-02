package host

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/orchestrator"
)

type fakeProcessRunner struct {
	outputs      [][]byte
	executables  []string
	arguments    [][]string
	environments []map[string]string
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
	return output, nil
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
