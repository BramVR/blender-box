package host

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/BramVR/blender-box/internal/orchestrator"
)

const (
	maxProcessOutput        = (3 * maxScenarioJSON) + (64 << 10)
	defaultReadyPoll        = 250 * time.Millisecond
	defaultReadinessTimeout = 2 * time.Minute
)

type ProcessRunner interface {
	Run(context.Context, string, []string, map[string]string) ([]byte, error)
}

type Runtime struct {
	processes         ProcessRunner
	readyPollInterval time.Duration
}

func NewRuntime(processes ProcessRunner) *Runtime {
	return &Runtime{processes: processes, readyPollInterval: defaultReadyPoll}
}

func (runtime *Runtime) Check(ctx context.Context) error {
	script := `$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Drawing; Add-Type -AssemblyName System.Windows.Forms; if ($null -eq [System.Drawing.Bitmap] -or $null -eq [System.Windows.Forms.SystemInformation]) { throw 'Windows desktop capture APIs are unavailable' }`
	_, err := runtime.processes.Run(ctx, "powershell.exe", powershellArguments(script), nil)
	return err
}

func (runtime *Runtime) Capture(ctx context.Context, path string) error {
	encodedPath := base64.StdEncoding.EncodeToString([]byte(path))
	script := fmt.Sprintf(`$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Drawing; Add-Type -AssemblyName System.Windows.Forms; $path=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%s')); $bounds=[System.Windows.Forms.SystemInformation]::VirtualScreen; if ($bounds.Width -le 0 -or $bounds.Height -le 0) { throw 'Windows virtual desktop is unavailable' }; $bitmap=New-Object System.Drawing.Bitmap($bounds.Width,$bounds.Height); $graphics=[System.Drawing.Graphics]::FromImage($bitmap); try { $graphics.CopyFromScreen($bounds.X,$bounds.Y,0,0,$bounds.Size,([System.Drawing.CopyPixelOperation]::SourceCopy -bor [System.Drawing.CopyPixelOperation]::CaptureBlt)); $bitmap.Save($path,[System.Drawing.Imaging.ImageFormat]::Png) } finally { $graphics.Dispose(); $bitmap.Dispose() }`, encodedPath)
	_, err := runtime.processes.Run(ctx, "powershell.exe", powershellArguments(script), nil)
	return err
}

func powershellArguments(script string) []string {
	units := utf16.Encode([]rune(script))
	encoded := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(encoded[index*2:], unit)
	}
	return []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded)}
}

func (runtime *Runtime) Launch(ctx context.Context, taskName string) error {
	_, err := runtime.processes.Run(ctx, "schtasks.exe", []string{"/Run", "/TN", taskName}, nil)
	return err
}

func (runtime *Runtime) Start(ctx context.Context, request DaemonStart) (orchestrator.SessionID, error) {
	output, runErr := runtime.processes.Run(ctx, request.Executable, []string{
		"start",
		"--name", request.Name,
		"--blender", request.BlenderExecutable,
		"--json",
	}, request.Environment)
	var result struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		Session       struct {
			SessionID orchestrator.SessionID `json:"session_id"`
		} `json:"session"`
	}
	if err := decodeExtensibleJSON(output, &result, maxProcessOutput); err != nil || result.SchemaVersion != 1 || result.Status != "started" {
		if runErr != nil {
			return "", runErr
		}
		return "", fmt.Errorf("blendersessiond start returned an invalid contract")
	}
	if err := result.Session.SessionID.Validate(); err != nil {
		return "", err
	}
	return result.Session.SessionID, runErr
}

func (runtime *Runtime) Recover(ctx context.Context, request DaemonRecover) (orchestrator.SessionID, bool, error) {
	output, runErr := runtime.processes.Run(ctx, request.Executable, []string{
		"status", "--name", request.Name, "--json",
	}, request.Environment)
	var result struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		Session       struct {
			SessionID orchestrator.SessionID `json:"session_id"`
		} `json:"session"`
	}
	if err := decodeExtensibleJSON(output, &result, maxProcessOutput); err != nil {
		if runErr != nil {
			return "", false, runErr
		}
		return "", false, fmt.Errorf("blendersessiond recovery status returned invalid JSON")
	}
	if result.SchemaVersion != 1 {
		return "", false, fmt.Errorf("blendersessiond recovery status returned an invalid contract")
	}
	if result.Status == "not-found" && result.Session.SessionID == "" {
		return "", false, nil
	}
	if err := result.Session.SessionID.Validate(); err != nil {
		return "", false, fmt.Errorf("blendersessiond recovery status returned an invalid Session identity")
	}
	return result.Session.SessionID, true, nil
}

func (runtime *Runtime) WaitReady(ctx context.Context, request DaemonReady) error {
	if err := request.SessionID.Validate(); err != nil {
		return err
	}
	readyCtx, cancel := context.WithTimeout(ctx, defaultReadinessTimeout)
	defer cancel()
	for {
		if err := readyCtx.Err(); err != nil {
			return fmt.Errorf("blendersessiond readiness: %w", err)
		}
		output, runErr := runtime.processes.Run(readyCtx, request.Executable, []string{
			"status", "--name", request.Name, "--json",
		}, request.Environment)
		var result struct {
			SchemaVersion int    `json:"schema_version"`
			Status        string `json:"status"`
			Session       struct {
				SessionID orchestrator.SessionID `json:"session_id"`
				Health    struct {
					Status  string `json:"status"`
					Process struct {
						Alive bool `json:"alive"`
					} `json:"process"`
					Socket struct {
						Answered bool `json:"answered"`
					} `json:"socket"`
				} `json:"health"`
			} `json:"session"`
		}
		if err := decodeExtensibleJSON(output, &result, maxProcessOutput); err != nil {
			if runErr != nil {
				return runErr
			}
			return fmt.Errorf("blendersessiond status returned invalid JSON")
		}
		if result.SchemaVersion != 1 || result.Session.SessionID != request.SessionID {
			return fmt.Errorf("blendersessiond status returned a different Session identity")
		}
		if result.Status == "healthy" && result.Session.Health.Status == "healthy" && result.Session.Health.Process.Alive && result.Session.Health.Socket.Answered {
			if runErr != nil {
				return runErr
			}
			return nil
		}
		if !result.Session.Health.Process.Alive {
			return fmt.Errorf("blendersessiond Session stopped before readiness")
		}
		if runtime.readyPollInterval <= 0 {
			continue
		}
		timer := time.NewTimer(runtime.readyPollInterval)
		select {
		case <-readyCtx.Done():
			timer.Stop()
			return fmt.Errorf("blendersessiond readiness: %w", readyCtx.Err())
		case <-timer.C:
		}
	}
}

func (runtime *Runtime) Call(ctx context.Context, request DaemonCall) (json.RawMessage, error) {
	if err := request.SessionID.Validate(); err != nil {
		return nil, err
	}
	if request.ReadTimeoutSeconds < 1 || request.ReadTimeoutSeconds > 3600 {
		return nil, fmt.Errorf("daemon read timeout is outside 1..3600 seconds")
	}
	var parameters map[string]json.RawMessage
	if err := decodeExtensibleJSON(request.Parameters, &parameters, maxScenarioJSON); err != nil {
		return nil, fmt.Errorf("invalid daemon parameters: %w", err)
	}
	output, err := runtime.processes.Run(ctx, request.Executable, []string{
		"call", request.Command,
		"--name", request.Name,
		"--expect-session-id", string(request.SessionID),
		"--read-timeout", strconv.Itoa(request.ReadTimeoutSeconds),
		"--params", string(request.Parameters),
		"--json",
	}, request.Environment)
	if err != nil {
		var failure struct {
			SchemaVersion int    `json:"schema_version"`
			Status        string `json:"status"`
			Command       string `json:"command"`
			Reason        string `json:"reason"`
		}
		if decodeExtensibleJSON(output, &failure, maxProcessOutput) == nil &&
			failure.SchemaVersion == 1 && failure.Status == "error" &&
			failure.Command == "call" && failure.Reason == "timeout" {
			return nil, fmt.Errorf("blendersessiond call read timeout: %w", context.DeadlineExceeded)
		}
		return nil, err
	}
	var contract any
	if err := decodeExtensibleJSON(output, &contract, maxProcessOutput); err != nil {
		return nil, fmt.Errorf("blendersessiond call returned invalid JSON: %w", err)
	}
	return append(json.RawMessage(nil), output...), nil
}

func (runtime *Runtime) Stop(ctx context.Context, request DaemonStop) error {
	if err := request.SessionID.Validate(); err != nil {
		return err
	}
	output, err := runtime.processes.Run(ctx, request.Executable, []string{
		"stop",
		"--name", request.Name,
		"--expect-session-id", string(request.SessionID),
		"--json",
	}, request.Environment)
	var result struct {
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		Session       struct {
			SessionID orchestrator.SessionID `json:"session_id"`
		} `json:"session"`
	}
	if decodeErr := decodeExtensibleJSON(output, &result, maxProcessOutput); decodeErr != nil {
		if err != nil {
			return err
		}
		return fmt.Errorf("blendersessiond stop returned an invalid contract")
	}
	if result.SchemaVersion != 1 {
		return fmt.Errorf("blendersessiond stop returned an invalid contract")
	}
	switch result.Status {
	case "stopped":
		if err != nil {
			return err
		}
		return nil
	case "not-found":
		if err != nil && result.Session.SessionID == "" {
			return nil
		}
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("blendersessiond stop returned an invalid contract")
}

type ExecProcessRunner struct{}

func (ExecProcessRunner) Run(ctx context.Context, executable string, arguments []string, environment map[string]string) ([]byte, error) {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = mergedEnvironment(environment)
	stdout := &limitedBuffer{limit: maxProcessOutput}
	stderr := &limitedBuffer{limit: 64 << 10}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		output := append([]byte(nil), stdout.buffer.Bytes()...)
		if stdout.exceeded || stderr.exceeded {
			return output, fmt.Errorf("process output exceeded its limit")
		}
		if message := strings.TrimSpace(stderr.buffer.String()); message != "" {
			return output, fmt.Errorf("process failed: %s", message)
		}
		return output, fmt.Errorf("process failed: %w", err)
	}
	if stdout.exceeded || stderr.exceeded {
		return nil, fmt.Errorf("process output exceeded its limit")
	}
	return append([]byte(nil), stdout.buffer.Bytes()...), nil
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *limitedBuffer) Write(contents []byte) (int, error) {
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining <= 0 {
		buffer.exceeded = true
		return len(contents), nil
	}
	if len(contents) > remaining {
		_, _ = buffer.buffer.Write(contents[:remaining])
		buffer.exceeded = true
		return len(contents), nil
	}
	return buffer.buffer.Write(contents)
}

func mergedEnvironment(overrides map[string]string) []string {
	if len(overrides) == 0 {
		return os.Environ()
	}
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]string, 0, len(os.Environ())+len(keys))
	for _, entry := range os.Environ() {
		name := entry
		if index := strings.IndexByte(entry, '='); index >= 0 {
			name = entry[:index]
		}
		replaced := false
		for _, key := range keys {
			if strings.EqualFold(name, key) {
				replaced = true
				break
			}
		}
		if !replaced {
			result = append(result, entry)
		}
	}
	for _, key := range keys {
		result = append(result, key+"="+overrides[key])
	}
	return result
}
