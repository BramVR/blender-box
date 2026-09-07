package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windowsinstall"
)

type setupExecutor struct {
	result   windowsinstall.Result
	err      error
	requests []windowsinstall.Request
}

func (e *setupExecutor) Execute(ctx context.Context, r windowsinstall.Request) (windowsinstall.Result, error) {
	e.requests = append(e.requests, r)
	if e.err != nil {
		return e.result, e.err
	}
	return windowsinstall.PublishTarget(ctx, r, e.result)
}
func TestSetupHelpAndUnsupportedPlatform(t *testing.T) {
	for _, args := range [][]string{{"setup", "--help"}, {"setup", "-h"}, {"setup", "install", "--help"}, {"setup", "remove", "--help"}, {"setup", "manifest", "--help"}} {
		var out, stderr bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(""), &out, &stderr, Dependencies{})
		if code != 0 {
			t.Fatalf("help=%d %s", code, stderr.String())
		}
	}
	root := filepath.Join(t.TempDir(), "missing")
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"setup", "install", "--platform", "linux", "--state-root", root, "--apply", "--json"}, strings.NewReader(""), &out, &stderr, Dependencies{})
	if code != 1 || !strings.Contains(out.String(), "unsupported-platform") {
		t.Fatalf("unsupported=%d %s %s", code, out.String(), stderr.String())
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatal("unsupported platform wrote root")
	}
}
func TestSetupPreservesPartialResultAndInstallationOnTargetCollision(t *testing.T) {
	root := t.TempDir()
	selected, err := target.Load(writeTarget(t, root))
	if err != nil {
		t.Fatal(err)
	}
	executor := &setupExecutor{result: windowsinstall.Result{SchemaVersion: 1, State: "installed", Completion: "known", InstallationID: "bbxi_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Target: &selected}}
	destination := filepath.Join(root, "existing.json")
	if err := os.WriteFile(destination, []byte("operator"), 0600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"setup", "install", "--platform", "windows", "--state-root", `C:\Box`, "--apply", "--target-out", destination, "--json"}, strings.NewReader(""), &out, &stderr, Dependencies{Setup: executor})
	var result struct {
		State             string            `json:"state"`
		TargetPublication targetPublication `json:"target_publication"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if code != 1 || result.State != "installed" || result.TargetPublication.Status != "failed" {
		t.Fatalf("result=%s err=%s", out.String(), stderr.String())
	}
	data, _ := os.ReadFile(destination)
	if string(data) != "operator" {
		t.Fatal("target overwritten")
	}
	executor.result.State = "partial"
	executor.err = errors.New("interrupted receipt")
	out.Reset()
	stderr.Reset()
	code = Run(context.Background(), []string{"setup", "install", "--platform", "windows", "--state-root", `C:\Box`, "--apply", "--json"}, strings.NewReader(""), &out, &stderr, Dependencies{Setup: executor})
	if code != 1 || !strings.Contains(out.String(), `"state": "partial"`) || !strings.Contains(out.String(), string(executor.result.InstallationID)) {
		t.Fatalf("partial=%d %s", code, out.String())
	}
}
func TestSetupSaveTargetUsesExclusiveStore(t *testing.T) {
	root := t.TempDir()
	t.Setenv("BLENDER_BOX_CONFIG_DIR", filepath.Join(root, "config"))
	selected, err := target.Load(writeTarget(t, root))
	if err != nil {
		t.Fatal(err)
	}
	executor := &setupExecutor{result: windowsinstall.Result{SchemaVersion: 1, State: "installed", Completion: "known", Target: &selected}}
	args := []string{"setup", "install", "--platform", "windows", "--state-root", `C:\Box`, "--apply", "--save-target", "studio", "--json"}
	for index, want := range []int{0, 1} {
		var out, stderr bytes.Buffer
		code := Run(context.Background(), args, strings.NewReader(""), &out, &stderr, Dependencies{Setup: executor})
		if code != want {
			t.Fatalf("save %d=%d %s", index, code, stderr.String())
		}
	}
	saved, err := (target.Store{Root: filepath.Join(root, "config")}).Show("studio")
	if err != nil || saved != selected {
		t.Fatalf("saved=%+v %v", saved, err)
	}
}

func TestSetupRefusesTargetPublicationInsideStateRootBeforeInstallation(t *testing.T) {
	for _, destination := range []string{"export", "saved"} {
		t.Run(destination, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "state")
			runtime := filepath.Join(root, "installations", "bbxi_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "runtime")
			args := []string{"setup", "install", "--platform", "windows", "--state-root", root, "--apply", "--json"}
			if destination == "export" {
				args = append(args, "--target-out", filepath.Join(runtime, "target.json"))
			} else {
				t.Setenv("BLENDER_BOX_CONFIG_DIR", runtime)
				args = append(args, "--save-target", "studio")
			}
			executor := &setupExecutor{}
			var out, stderr bytes.Buffer
			code := Run(context.Background(), args, strings.NewReader(""), &out, &stderr, Dependencies{Setup: executor})
			if code != 1 || len(executor.requests) != 0 || !strings.Contains(stderr.String(), "outside the setup state root") {
				t.Fatalf("code=%d calls=%d error=%s", code, len(executor.requests), stderr.String())
			}
			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Fatal("publication validation created state root")
			}
		})
	}
}

func TestSetupRefusesTargetPublicationThroughStateRootAlias(t *testing.T) {
	root := t.TempDir()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(root, alias); err != nil {
		t.Skipf("symlink privilege unavailable: %v", err)
	}
	executor := &setupExecutor{}
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"setup", "install", "--platform", "windows", "--state-root", root, "--apply", "--target-out", filepath.Join(alias, "new", "target.json"), "--json"}, strings.NewReader(""), &out, &stderr, Dependencies{Setup: executor})
	if code != 1 || len(executor.requests) != 0 || !strings.Contains(stderr.String(), "outside the setup state root") {
		t.Fatalf("code=%d calls=%d error=%s", code, len(executor.requests), stderr.String())
	}
}

func TestSetupStatusAndStopRouteExactExecution(t *testing.T) {
	executor := &setupExecutor{result: windowsinstall.Result{SchemaVersion: 1, State: "running", Completion: "unknown", Execution: &windowsinstall.Execution{Token: "bbxe_" + strings.Repeat("c", 32), State: "running", TreeCleanup: "unknown"}}}
	for _, operation := range []string{"status", "stop"} {
		args := []string{"setup", operation, "--platform", "windows", "--state-root", `C:\Fixture`, "--installation", "bbxi_" + strings.Repeat("a", 32), "--operation", "bbxo_" + strings.Repeat("b", 32), "--json"}
		if operation == "stop" {
			args = append(args, "--apply", "--execution", executor.result.Execution.Token)
		}
		var out, stderr bytes.Buffer
		if code := Run(context.Background(), args, strings.NewReader(""), &out, &stderr, Dependencies{Setup: executor}); code != 0 {
			t.Fatalf("%s code=%d err=%s", operation, code, stderr.String())
		}
		var decoded map[string]json.RawMessage
		if err := json.Unmarshal(out.Bytes(), &decoded); err != nil || !bytes.Contains(decoded["execution"], []byte(executor.result.Execution.Token)) {
			t.Fatal("execution identity missing from public JSON")
		}
		got := executor.requests[len(executor.requests)-1]
		if got.Operation != operation || got.Apply != (operation == "stop") || operation == "stop" && got.ExecutionToken != executor.result.Execution.Token {
			t.Fatalf("wrong execution request: %+v", got)
		}
	}
}
func TestSetupPublicationPreviewIsReadOnlyAndBindsDestination(t *testing.T) {
	root := t.TempDir()
	executor := &setupExecutor{result: windowsinstall.Result{SchemaVersion: 1, State: "planned", Completion: "known"}}
	destination := filepath.Join(root, "target.json")
	var out, stderr bytes.Buffer
	args := []string{"setup", "install", "--platform", "windows", "--state-root", filepath.Join(root, "state"), "--target-out", destination, "--json"}
	if code := Run(context.Background(), args, strings.NewReader(""), &out, &stderr, Dependencies{Setup: executor}); code != 0 {
		t.Fatalf("preview code=%d err=%s", code, stderr.String())
	}
	if executor.requests[0].Apply || executor.requests[0].TargetOut != destination {
		t.Fatal("preview destination was dropped")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("preview published target")
	}
}
