package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/payload"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windows"
)

type diskHost struct{ root, receiptPath, auditPath string }

func (host diskHost) record(operation string) error {
	file, err := os.OpenFile(host.auditPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = fmt.Fprintln(file, operation)
	return err
}
func (host diskHost) read() (orchestrator.RunReceipt, error) {
	var receipt orchestrator.RunReceipt
	data, err := os.ReadFile(host.receiptPath)
	if err == nil {
		err = json.Unmarshal(data, &receipt)
	}
	return receipt, err
}
func (host diskHost) write(receipt orchestrator.RunReceipt) error {
	data, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	return os.WriteFile(host.receiptPath, data, 0o600)
}
func (host diskHost) Inspect(context.Context, target.Target, orchestrator.HostRequirements) (orchestrator.HostInspection, error) {
	return orchestrator.HostInspection{SchemaVersion: 1, Status: "pass"}, host.record("inspect")
}
func (host diskHost) Acquire(_ context.Context, _ target.Target, claim orchestrator.LockClaim) error {
	if err := host.record("acquire"); err != nil {
		return err
	}
	return host.write(orchestrator.RunReceipt{SchemaVersion: 1, Claim: claim, State: orchestrator.StateAccepted})
}
func (host diskHost) Stage(context.Context, target.Target, orchestrator.LockClaim, payload.Payload) error {
	return host.record("stage")
}
func (host diskHost) Start(_ context.Context, _ target.Target, request orchestrator.RunRequest) (orchestrator.RunReceipt, error) {
	if err := host.record("start"); err != nil {
		return orchestrator.RunReceipt{}, err
	}
	data := []byte(`{"status":"pass"}`)
	hash := sha256.Sum256(data)
	receipt := orchestrator.RunReceipt{SchemaVersion: 1, Claim: request.Claim, State: orchestrator.StateComplete, SessionID: "bss_cli-process-session-identity-123456", Evidence: orchestrator.EvidenceManifest{SchemaVersion: 1, Files: []orchestrator.EvidenceFile{{Path: "scenario-result.json", Type: "scenario-result", Size: int64(len(data)), SHA256: hex.EncodeToString(hash[:])}}}}
	if err := host.write(receipt); err != nil {
		return receipt, err
	}
	if os.Getenv("BBX_TEST_PIN_FAILURE") == "1" {
		if err := os.Mkdir(filepath.Join(host.root, "runs", string(request.Claim.RunID)+".session.json"), 0o700); err != nil {
			return receipt, err
		}
	}
	return receipt, nil
}
func (host diskHost) Observe(context.Context, target.Target, orchestrator.RunID) (orchestrator.RunReceipt, error) {
	if err := host.record("observe"); err != nil {
		return orchestrator.RunReceipt{}, err
	}
	return host.read()
}
func (host diskHost) Fetch(context.Context, target.Target, orchestrator.RunReceipt, orchestrator.EvidenceFile) ([]byte, error) {
	return []byte(`{"status":"pass"}`), host.record("fetch")
}
func (host diskHost) Settle(_ context.Context, _ target.Target, receipt orchestrator.RunReceipt) (orchestrator.CleanupState, error) {
	if err := host.record("settle"); err != nil {
		return orchestrator.CleanupState{}, err
	}
	stored, err := host.read()
	if err != nil {
		return orchestrator.CleanupState{}, err
	}
	if !receipt.Claim.Equal(stored.Claim) || receipt.SessionID != stored.SessionID {
		return orchestrator.CleanupState{}, fmt.Errorf("settlement authority changed")
	}
	stored.Cleanup = orchestrator.CleanupState{SessionStopped: true, PayloadRemoved: true, RunRootRemoved: true, LockReleased: true}
	return stored.Cleanup, host.write(stored)
}
func passingChecks() []byte {
	checks := []windows.CheckEvidence{}
	for _, id := range []string{"host.windows", "host.console-user", "host.ssh-user", "host.limited-token-policy", "blender.executable", "daemon.executable", "host.executable", "work-root.access", "work-root.state-tree", "task.interactive"} {
		checks = append(checks, windows.CheckEvidence{ID: id, Passed: true, Required: true})
	}
	data, _ := json.Marshal(windows.CheckResult{SchemaVersion: 1, Status: "pass", Checks: checks})
	return data
}
func TestTargetsCLIProcessHelper(t *testing.T) {
	if os.Getenv("BBX_TEST_CLI_HELPER") != "1" {
		return
	}
	separator := 0
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i + 1
			break
		}
	}
	args := os.Args[separator:]
	root := os.Getenv("BLENDER_BOX_CONFIG_DIR")
	host := diskHost{root: root, receiptPath: os.Getenv("BBX_TEST_RECEIPT"), auditPath: os.Getenv("BBX_TEST_AUDIT")}
	ssh := &fakeSSH{stdout: passingChecks()}

	code := Run(context.Background(), args, strings.NewReader(""), os.Stdout, os.Stderr, Dependencies{Runner: orchestrator.New(host, root), SSH: ssh})
	if ssh.host != "" {
		if err := host.record("ssh"); err != nil {
			t.Fatal(err)
		}
	}
	os.Exit(code)
}

type processCLI struct {
	t           *testing.T
	env         []string
	audit, root string
}

func newProcessCLI(t *testing.T) processCLI {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "private")
	audit := filepath.Join(base, "audit.txt")
	env := []string{}
	for _, item := range os.Environ() {
		if !strings.HasPrefix(item, "BLENDER_BOX_CONFIG_DIR=") && !strings.HasPrefix(item, "BBX_TEST_") {
			env = append(env, item)
		}
	}
	env = append(env, "BBX_TEST_CLI_HELPER=1", "BLENDER_BOX_CONFIG_DIR="+root, "BBX_TEST_RECEIPT="+filepath.Join(base, "remote.json"), "BBX_TEST_AUDIT="+audit)
	return processCLI{t: t, env: env, audit: audit, root: root}
}
func (cli processCLI) call(want int, args ...string) string {
	cli.t.Helper()
	binary, err := os.Executable()
	if err != nil {
		cli.t.Fatal(err)
	}
	command := exec.Command(binary, append([]string{"-test.run=^TestTargetsCLIProcessHelper$", "--"}, args...)...)
	command.Env = cli.env
	command.Dir = cli.t.TempDir()
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = command.Run()
	code := 0
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			code = exit.ExitCode()
		} else {
			cli.t.Fatal(err)
		}
	}
	if code != want {
		cli.t.Fatalf("args=%v exit=%d want=%d stderr=%s stdout=%s", args, code, want, stderr.String(), stdout.String())
	}
	if want != 0 {
		return stderr.String() + stdout.String()
	}
	return stdout.String()
}
func (cli processCLI) calls() string {
	cli.t.Helper()
	data, err := os.ReadFile(cli.audit)
	if os.IsNotExist(err) {
		return ""
	}
	if err != nil {
		cli.t.Fatal(err)
	}
	return string(data)
}
func cliPayload(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "scenario.py"), []byte("print('test')"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "payload.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"files":[{"source":"scenario.py","destination":"scenario.py"}],"scenario":{"script":"scenario.py"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
func TestPublicNamedTargetsAcrossProcessesAndBothVersions(t *testing.T) {
	cli := newProcessCLI(t)
	source := writeTarget(t, t.TempDir())
	original, err := target.Load(source)
	if err != nil {
		t.Fatal(err)
	}
	cli.call(0, "targets", "list", "--json")
	if _, err := os.Lstat(cli.root); !os.IsNotExist(err) {
		t.Fatal("list created storage")
	}
	output := cli.call(0, "targets", "import", "studio", "--file", source, "--json")
	if !strings.Contains(output, `"status": "imported"`) {
		t.Fatal(output)
	}
	var shown struct {
		SchemaVersion int             `json:"schema_version"`
		Name          string          `json:"name"`
		Platform      string          `json:"platform"`
		Target        json.RawMessage `json:"target"`
	}
	if err := json.Unmarshal([]byte(cli.call(0, "targets", "show", "studio", "--json")), &shown); err != nil {
		t.Fatal(err)
	}
	normalized, err := target.Decode(shown.Target)
	if err != nil || normalized != original || shown.SchemaVersion != 1 || shown.Name != "studio" || shown.Platform != "windows" {
		t.Fatalf("show=%+v %v", shown, err)
	}
	v2path := filepath.Join(t.TempDir(), "v2.json")
	if err := os.WriteFile(v2path, shown.Target, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cli.call(0, "targets", "show", "studio", "--json")
	if cli.calls() != "" {
		t.Fatal("local target commands contacted host")
	}
	cli.call(1, "targets", "import", "studio", "--file", v2path)
	hostBinary := filepath.Join(t.TempDir(), "host.exe")
	if err := os.WriteFile(hostBinary, []byte("host-binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, selector := range [][]string{{"--target-name", "studio"}, {"--target", v2path}} {
		before := cli.calls()
		cli.call(0, append([]string{"windows", "setup", "--host-binary", hostBinary, "--json"}, selector...)...)
		if cli.calls() != before {
			t.Fatal("setup preview contacted host")
		}
		cli.call(1, append([]string{"windows", "setup", "--host-binary", hostBinary, "--apply", "--json"}, selector...)...)
		if cli.calls() != before {
			t.Fatal("legacy apply refusal contacted host")
		}
		cli.call(0, append([]string{"windows", "check", "--json"}, selector...)...)
		before = cli.calls()
		cli.call(0, append([]string{"plan", "--payload", cliPayload(t), "--json"}, selector...)...)
		if cli.calls() != before {
			t.Fatal("plan contacted host")
		}
		cli.call(0, append([]string{"doctor", "--payload", cliPayload(t), "--json"}, selector...)...)
		if cli.calls() != before+"inspect\n" {
			t.Fatal("doctor did not inspect exactly once")
		}
		var result orchestrator.RunResult
		output := cli.call(0, append([]string{"run", "--payload", cliPayload(t), "--evidence-dir", filepath.Join(t.TempDir(), "evidence"), "--json"}, selector...)...)
		if err := json.Unmarshal([]byte(output), &result); err != nil || !result.Cleanup.Known() || result.SessionID == "" {
			t.Fatalf("run=%s %v", output, err)
		}
		for _, operation := range []string{"status", "stop"} {
			cli.call(0, append([]string{operation, "--run", string(result.RunID), "--json"}, selector...)...)
		}
		changed, err := target.NewWindows("replacement", original.Windows())
		if err != nil {
			t.Fatal(err)
		}
		changedData, _ := json.Marshal(changed)
		replacement := filepath.Join(t.TempDir(), "replacement.json")
		if err := os.WriteFile(replacement, changedData, 0o600); err != nil {
			t.Fatal(err)
		}
		cli.call(0, "targets", "import", "studio", "--file", replacement, "--replace", "--json")
		before = cli.calls()
		for _, operation := range []string{"status", "stop"} {
			if output := cli.call(1, operation, "--target-name", "studio", "--run", string(result.RunID), "--json"); !strings.Contains(output, "target does not match original Run") {
				t.Fatal(output)
			}
		}
		if cli.calls() != before {
			t.Fatal("replacement contacted host")
		}
		cli.call(0, "targets", "forget", "studio", "--json")
		cli.call(1, "status", "--target-name", "studio", "--run", string(result.RunID))
		cli.call(0, "targets", "import", "recovered", "--file", v2path, "--json")
		cli.call(0, "stop", "--target-name", "recovered", "--run", string(result.RunID), "--json")
		cli.call(0, "targets", "forget", "recovered", "--json")
		cli.call(0, "targets", "import", "studio", "--file", v2path, "--json")
	}
}
func TestAllSelectorsRejectAmbiguousEmptyAndMissingBeforeEffects(t *testing.T) {
	cli := newProcessCLI(t)
	source := writeTarget(t, t.TempDir())
	cli.call(0, "targets", "import", "studio", "--file", source)
	commands := [][]string{{"plan", "--payload", "unused"}, {"doctor", "--payload", "unused"}, {"windows", "setup", "--host-binary", "unused"}, {"windows", "check"}, {"run", "--payload", "unused"}, {"status", "--run", "bbx_test-run-identity-123456"}, {"stop", "--run", "bbx_test-run-identity-123456"}}
	for _, command := range commands {
		for _, selection := range [][]string{nil, {"--target", ""}, {"--target-name", ""}, {"--target", source, "--target-name", "studio"}, {"--target", "", "--target-name", "studio"}, {"--target", source, "--target-name", ""}} {
			cli.call(2, append(append([]string{}, command...), selection...)...)
		}
		for _, name := range []string{"missing", "../bad", "CON"} {
			cli.call(1, append(append([]string{}, command...), "--target-name", name)...)
		}
	}
	if cli.calls() != "" {
		t.Fatal("invalid selector reached host")
	}
}
func TestFailedJSONRunPinErrorSkipsStatusAndCleanupAcrossCLI(t *testing.T) {
	cli := newProcessCLI(t)
	source := writeTarget(t, t.TempDir())
	cli.env = append(cli.env, "BBX_TEST_PIN_FAILURE=1")
	output := cli.call(1, "run", "--target", source, "--payload", cliPayload(t), "--evidence-dir", filepath.Join(t.TempDir(), "evidence"), "--json")
	if !strings.Contains(output, "insufficient recovery authority") {
		t.Fatal(output)
	}
	if got := strings.Fields(cli.calls()); !reflect.DeepEqual(got, []string{"inspect", "acquire", "stage", "start"}) {
		t.Fatalf("effects after failed pin=%v", got)
	}
}

func TestFileSelectorsReportInvalidConfigOverrideBeforeEffects(t *testing.T) {
	cli := newProcessCLI(t)
	source := writeTarget(t, t.TempDir())
	for i, value := range cli.env {
		if strings.HasPrefix(value, "BLENDER_BOX_CONFIG_DIR=") {
			cli.env[i] = "BLENDER_BOX_CONFIG_DIR=relative"
		}
	}
	commands := [][]string{{"plan", "--payload", "unused"}, {"doctor", "--payload", "unused"}, {"windows", "setup", "--host-binary", "unused"}, {"windows", "check"}, {"run", "--payload", "unused"}, {"status", "--run", "bbx_test-run-identity-123456"}, {"stop", "--run", "bbx_test-run-identity-123456"}}
	for _, command := range commands {
		output := cli.call(1, append(command, "--target", source)...)
		if !strings.Contains(output, "BLENDER_BOX_CONFIG_DIR must be absolute") {
			t.Fatalf("configuration error lost: %s", output)
		}
	}
	if cli.calls() != "" {
		t.Fatal("invalid configuration reached host")
	}
}
