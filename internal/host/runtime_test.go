package host

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/BramVR/blender-box/internal/orchestrator"
)

type fakeProcessRunner struct {
	outputs      [][]byte
	executables  []string
	arguments    [][]string
	environments []map[string]string
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
		[]byte(`{"executed":true,"result":"{}"}`),
		[]byte(`{"schema_version":1,"status":"stopped"}`),
	}}
	runtime := NewRuntime(fake)
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

	wantExecutables := []string{"schtasks.exe", `C:\Bin\blendersessiond.exe`, `C:\Bin\blendersessiond.exe`, `C:\Bin\blendersessiond.exe`}
	if !reflect.DeepEqual(fake.executables, wantExecutables) {
		t.Fatalf("executables = %v", fake.executables)
	}
	if !reflect.DeepEqual(fake.arguments[0], []string{"/Run", "/TN", "BlenderBoxTest"}) {
		t.Fatalf("task arguments = %v", fake.arguments[0])
	}
	assertArguments(t, fake.arguments[1], "start", "--name", "blender-box-test", "--blender", `C:\Blender\blender.exe`, "--json")
	assertArguments(t, fake.arguments[2], "call", "execute_code", "--name", "blender-box-test", "--expect-session-id", string(sessionID), "--read-timeout", "600", "--params", string(parameters), "--json")
	assertArguments(t, fake.arguments[3], "stop", "--name", "blender-box-test", "--expect-session-id", string(sessionID), "--json")
	for index := 1; index < 4; index++ {
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
