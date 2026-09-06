package linux

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BramVR/blender-box/internal/host"
	"github.com/BramVR/blender-box/internal/linuxruntime"
	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/payload"
	"github.com/BramVR/blender-box/internal/target"
)

type scenarioDaemon struct {
	current orchestrator.SessionID
	starts  []host.DaemonStart
	stops   []host.DaemonStop
	crash   bool
}

func (daemon *scenarioDaemon) Start(_ context.Context, request host.DaemonStart) (orchestrator.SessionID, error) {
	daemon.starts = append(daemon.starts, request)
	if daemon.crash {
		return daemon.current, errors.New("supervisor exited after publishing exact identity")
	}
	return daemon.current, nil
}
func (daemon *scenarioDaemon) Recover(context.Context, host.DaemonRecover) (orchestrator.SessionID, bool, error) {
	return daemon.current, daemon.current != "", nil
}
func (daemon *scenarioDaemon) WaitReady(_ context.Context, request host.DaemonReady) error {
	if request.SessionID != daemon.current {
		return errors.New("replacement Session")
	}
	return nil
}
func (daemon *scenarioDaemon) Call(_ context.Context, request host.DaemonCall) (json.RawMessage, error) {
	if request.SessionID != daemon.current {
		return nil, errors.New("replacement Session")
	}
	if request.Command == "execute_code" {
		return json.RawMessage(`{"executed":true,"result":"{\"schema_version\":1,\"status\":\"pass\"}"}`), nil
	}
	if request.Command != "get_viewport_screenshot" {
		return nil, errors.New("unexpected daemon command")
	}
	var capture struct {
		Filepath string `json:"filepath"`
	}
	if err := json.Unmarshal(request.Parameters, &capture); err != nil {
		return nil, err
	}
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewRGBA(image.Rect(0, 0, 64, 48))); err != nil {
		return nil, err
	}
	if err := os.WriteFile(capture.Filepath, encoded.Bytes(), 0600); err != nil {
		return nil, err
	}
	response, err := json.Marshal(map[string]any{"success": true, "width": 64, "height": 48, "filepath": capture.Filepath, "method": "offscreen"})
	return response, err
}
func (daemon *scenarioDaemon) Stop(_ context.Context, request host.DaemonStop) error {
	daemon.stops = append(daemon.stops, request)
	if request.SessionID != daemon.current {
		return errors.New("exact Session mismatch; replacement preserved")
	}
	return nil
}

type desktopServiceFake struct {
	service  *host.Service
	done     chan struct{}
	err      error
	launches int
}

func (launcher *desktopServiceFake) Prepare(context.Context, host.LaunchRequest) error { return nil }
func (launcher *desktopServiceFake) Launch(_ context.Context, request host.LaunchRequest) error {
	launcher.launches++
	if launcher.done != nil {
		return nil
	}
	launcher.done = make(chan struct{})
	go func() {
		launcher.err = launcher.service.ExecutePending(context.Background(), request.StateRoot)
		close(launcher.done)
	}()
	return nil
}

type localServiceSSH struct {
	selected               target.Target
	root                   string
	service                *host.Service
	launcher               *desktopServiceFake
	daemon                 *scenarioDaemon
	operations             []string
	dropStart, replacement bool
}

func (boundary *localServiceSSH) Run(ctx context.Context, alias string, args []string, input []byte) ([]byte, error) {
	if alias != boundary.selected.SSHAlias() || len(args) != 1 {
		return nil, errors.New("unexpected SSH routing")
	}
	config := boundary.selected.Linux()
	operation := ""
	for _, candidate := range []string{"linux-check", "acquire", "stage", "start", "status", "fetch", "settle"} {
		if args[0] == Quote(config.HostExecutable)+" host "+Quote(candidate)+" --state-root "+Quote(config.WorkRoot) {
			operation = candidate
			break
		}
	}
	if operation == "" {
		return nil, fmt.Errorf("unexpected POSIX host command %q", args)
	}
	boundary.operations = append(boundary.operations, operation)
	if operation == "linux-check" {
		result := linuxruntime.CheckResult{SchemaVersion: 1, Status: "pass", BlenderVersion: "5.2.0"}
		for _, id := range []string{"host.linux", "host.desktop", "daemon.runtime", "host.unit", "work-root.access", "blender.executable"} {
			result.Checks = append(result.Checks, linuxruntime.CheckEvidence{ID: id, Passed: true, Required: true})
		}
		return json.Marshal(result)
	}
	if operation == "settle" && boundary.replacement {
		boundary.daemon.current = "bss_replacement-session-must-survive-12345"
	}
	var output, stderr bytes.Buffer
	code := boundary.service.Run(ctx, []string{operation, "--state-root", boundary.root}, bytes.NewReader(input), &output, &stderr)
	if code != 0 {
		return nil, fmt.Errorf("host command: %s", stderr.String())
	}
	if operation == "start" && boundary.launcher.done != nil {
		select {
		case <-boundary.launcher.done:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		if boundary.dropStart {
			boundary.dropStart = false
			return nil, errors.New("SSH response dropped after service accepted Run")
		}
	}
	return output.Bytes(), nil
}

func TestLinuxRunnerAdapterAndHostServiceLifecycle(t *testing.T) {
	for _, mode := range []string{"complete", "dropped-start-response", "startup-crash", "replacement-session"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			selected := linuxTarget(t)
			daemon := &scenarioDaemon{current: "bss_exact-linux-integrated-session-12345", crash: mode == "startup-crash"}
			launcher := &desktopServiceFake{}
			service := host.NewService(host.Dependencies{Platform: "linux", Tasks: launcher, Daemon: daemon})
			launcher.service = service
			boundary := &localServiceSSH{selected: selected, root: root, service: service, launcher: launcher, daemon: daemon, dropStart: mode == "dropped-start-response", replacement: mode == "replacement-session"}
			adapter := NewAdapter(boundary)
			adapter.pollInterval = 0
			runner := orchestrator.New(adapter, filepath.Join(t.TempDir(), "private"))
			intent := orchestrator.RunIntent{RunID: "bbx_linux-integrated-run-12345678", RequestID: "req_linux-integrated-request-123456", ControllerID: "fake-controller", Deadline: time.Now().Add(time.Minute).UTC(), Target: selected, Payload: scenarioPayload(t), EvidenceDir: filepath.Join(t.TempDir(), "evidence")}
			result, runErr := runner.Run(context.Background(), intent)
			if mode == "complete" {
				if runErr != nil || result.State != orchestrator.StateComplete || !result.Cleanup.Known() || len(result.Evidence.Files) != 2 {
					t.Fatalf("Run %+v %v", result, runErr)
				}
				for _, file := range result.Evidence.Files {
					contents, err := os.ReadFile(filepath.Join(intent.EvidenceDir, file.Path))
					if err != nil {
						t.Fatal(err)
					}
					hash := sha256.Sum256(contents)
					if hex.EncodeToString(hash[:]) != file.SHA256 || len(contents) != int(file.Size) {
						t.Fatal("returned evidence hash mismatch")
					}
					if file.Type == "viewport" && (file.CaptureMethod != "offscreen" || file.Width != 64 || file.Height != 48) {
						t.Fatalf("capture provenance %+v", file)
					}
				}
			} else if runErr == nil {
				t.Fatal("failed external boundary reported successful Run")
			}
			status, err := runner.Status(context.Background(), selected, intent.RunID)
			if err != nil {
				t.Fatal(err)
			}
			if status.SessionID != "bss_exact-linux-integrated-session-12345" {
				t.Fatalf("lost exact Session identity %+v", status)
			}
			if mode == "replacement-session" {
				if status.Cleanup.Known() || daemon.current != "bss_replacement-session-must-survive-12345" {
					t.Fatal("replacement cleanup fabricated")
				}
			} else {
				if !status.Cleanup.Known() {
					t.Fatalf("cleanup unresolved %+v", status)
				}
				for i := 0; i < 2; i++ {
					stopped, err := runner.Stop(context.Background(), selected, intent.RunID)
					if err != nil || !stopped.Cleanup.Known() || stopped.SessionID != status.SessionID {
						t.Fatalf("repeat Stop %+v %v", stopped, err)
					}
				}
				if len(daemon.stops) != 1 {
					t.Fatalf("repeated cleanup invoked daemon %d times", len(daemon.stops))
				}
			}
			if len(daemon.starts) != 1 || daemon.starts[0].Runtime.Linux == nil || *daemon.starts[0].Runtime.Linux != selected.Linux().Daemon {
				t.Fatalf("Linux start binding %+v", daemon.starts)
			}
			for _, stop := range daemon.stops {
				if stop.SessionID != "bss_exact-linux-integrated-session-12345" || stop.Runtime.Linux == nil || *stop.Runtime.Linux != selected.Linux().Daemon {
					t.Fatalf("settlement authority %+v", stop)
				}
			}
			if len(boundary.operations) == 0 || boundary.operations[0] != "linux-check" {
				t.Fatal("Run skipped readiness boundary")
			}
		})
	}
}
func scenarioPayload(t *testing.T) payload.Payload {
	t.Helper()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "scenario.py"), []byte("print('fake Scenario')"), 0600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "payload.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"files":[{"source":"scenario.py","destination":"scenario.py"}],"scenario":{"script":"scenario.py","capture_viewport":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := payload.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return loaded
}
func TestLinuxCheckFailurePreservesActionableRuntimeReason(t *testing.T) {
	result := linuxruntime.CheckResult{SchemaVersion: 1, Status: "fail"}
	for _, id := range []string{"host.linux", "host.desktop", "daemon.runtime", "host.unit", "work-root.access", "blender.executable"} {
		result.Checks = append(result.Checks, linuxruntime.CheckEvidence{ID: id, Passed: id != "daemon.runtime", Required: true, Message: "provision reviewed corrected runtime externally"})
	}
	output, _ := json.Marshal(result)
	_, err := NewAdapter(&recordingSSH{output: output}).Inspect(context.Background(), linuxTarget(t), orchestrator.HostRequirements{})
	if err == nil || !strings.Contains(err.Error(), "daemon.runtime: provision reviewed corrected runtime externally") {
		t.Fatalf("readiness error %v", err)
	}
}
