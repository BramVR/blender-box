package windows

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const testSetupAttemptID = "bbsa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type noEOFSSH struct {
	*scriptedSSH
}

func (fake *noEOFSSH) Run(ctx context.Context, host string, arguments []string, input []byte) ([]byte, error) {
	if len(input) != 0 {
		<-ctx.Done()
		return nil, fmt.Errorf("stdin remained open: %w", ctx.Err())
	}
	return fake.scriptedSSH.Run(ctx, host, arguments, input)
}

func TestSetupDoesNotDependOnSSHStdinEOF(t *testing.T) {
	binary := []byte("bounded-windows-host-binary")
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(binary)
	transport := &scriptedSSH{}
	setSetupOwnerTerminalResponse(t, transport, mustJSON(t, SetupResult{
		SchemaVersion: 1,
		Status:        "applied",
		Applied:       true,
		HostSize:      int64(len(binary)),
		HostSHA256:    hex.EncodeToString(hash[:]),
	}))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	if _, err := Setup(ctx, &noEOFSSH{scriptedSSH: transport}, adapterTarget(), path, true); err != nil {
		t.Fatalf("Setup() waited for SSH stdin EOF: %v", err)
	}
}

func TestSetupRunsApplyThroughFencedSetupOwner(t *testing.T) {
	binary := []byte("bounded-windows-host-binary")
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	hostHash := sha256.Sum256(binary)
	selected := adapterTarget()
	fake := &scriptedSSH{}
	fake.runResult = func(_ context.Context, call int, arguments []string, input []byte) ([]byte, error) {
		if call == 0 {
			return nil, nil
		}
		if call == 2 {
			return nil, nil
		}
		var request struct {
			SchemaVersion     int    `json:"schema_version"`
			AttemptID         string `json:"attempt_id"`
			LaunchID          string `json:"launch_id"`
			DeadlineUTC       string `json:"deadline_utc"`
			OperationRevision string `json:"operation_revision"`
			Script            struct {
				ArtifactID string `json:"artifact_id"`
				Size       int    `json:"size"`
				SHA256     string `json:"sha256"`
			} `json:"script"`
		}
		if err := json.Unmarshal(input, &request); err != nil {
			t.Fatal(err)
		}
		requestHash := sha256.Sum256(input)
		applied := SetupResult{SchemaVersion: 1, Status: "applied", Applied: true, HostSize: int64(len(binary)), HostSHA256: hex.EncodeToString(hostHash[:])}
		return mustJSON(t, map[string]any{
			"schema_version":   1,
			"attempt_id":       request.AttemptID,
			"launch_id":        request.LaunchID,
			"request_sha256":   hex.EncodeToString(requestHash[:]),
			"status":           "terminal",
			"outcome":          "process_succeeded",
			"process":          "exited",
			"cleanup":          "tree_gone",
			"exit_code":        0,
			"stdout":           string(mustJSON(t, applied)),
			"stderr":           "",
			"stdout_truncated": false,
			"stderr_truncated": false,
			"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
		}), nil
	}

	applied, err := Setup(context.Background(), fake, selected, path, true)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Status != "applied" || !applied.Applied {
		t.Fatalf("apply = %+v", applied)
	}
	if len(fake.arguments) != 3 || len(fake.uploads) != 2 {
		t.Fatalf("SSH calls = %d, uploads = %d", len(fake.arguments), len(fake.uploads))
	}
	prepare := string(fake.inputs[0])
	if !strings.Contains(prepare, "$setupOwnerRoot") || !strings.Contains(prepare, "$setupOwnerAttempt") || !strings.Contains(prepare, "SetAccessRuleProtection($true, $false)") {
		t.Fatalf("prepare does not provision private setup-owner authority: %s", prepare)
	}
	var request struct {
		SchemaVersion     int    `json:"schema_version"`
		AttemptID         string `json:"attempt_id"`
		LaunchID          string `json:"launch_id"`
		DeadlineUTC       string `json:"deadline_utc"`
		OperationRevision string `json:"operation_revision"`
		Script            struct {
			ArtifactID string `json:"artifact_id"`
			Size       int    `json:"size"`
			SHA256     string `json:"sha256"`
		} `json:"script"`
	}
	if err := json.Unmarshal(fake.inputs[1], &request); err != nil {
		t.Fatal(err)
	}
	idPattern := regexp.MustCompile(`^bbs[al]_[A-Za-z0-9_-]{43}$`)
	if request.SchemaVersion != 1 || !idPattern.MatchString(request.AttemptID) || !idPattern.MatchString(request.LaunchID) || request.OperationRevision != "windows-setup-owner-v1" {
		t.Fatalf("request identity = %+v", request)
	}
	deadline, err := time.Parse(time.RFC3339Nano, request.DeadlineUTC)
	if err != nil || time.Until(deadline) <= 0 || time.Until(deadline) > 5*time.Minute {
		t.Fatalf("request deadline = %q, error = %v", request.DeadlineUTC, err)
	}
	scriptUpload := fake.uploads[1]
	wantSuffix := `\setup-owner\setup-attempts\` + request.AttemptID + `\` + request.AttemptID + `.ps1`
	if scriptUpload.destination != selected.WorkRoot+wantSuffix || request.Script.ArtifactID != request.AttemptID+".ps1" || request.Script.Size != len(scriptUpload.contents) {
		t.Fatalf("request script = %+v, upload = %+v", request.Script, scriptUpload)
	}
	scriptHash := sha256.Sum256(scriptUpload.contents)
	if request.Script.SHA256 != hex.EncodeToString(scriptHash[:]) {
		t.Fatalf("request script hash = %q", request.Script.SHA256)
	}
	launch := decodedAdapterScript(t, fake.arguments[1])
	if !strings.Contains(launch, `$env:BLENDERSESSIOND_STATE_DIR = '`+selected.WorkRoot+`\setup-owner'`) || !strings.Contains(launch, selected.SessionBrokerExecutable) || !strings.Contains(launch, `'setup-owner' 'launch' '--json'`) || strings.Contains(launch, "ScriptBlock") {
		t.Fatalf("launch does not use setup owner: %s", launch)
	}
	cleanup := decodedAdapterScript(t, fake.arguments[2])
	if !strings.Contains(cleanup, scriptUpload.destination) || !strings.Contains(cleanup, fake.uploads[0].destination) {
		t.Fatalf("terminal setup did not clean exact uploads: %s", cleanup)
	}
	if _, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(request.AttemptID, "bbsa_")); err != nil {
		t.Fatalf("Attempt ID is not random URL-safe bytes: %v", err)
	}
}

func TestSetupReconcilesLostLaunchResponseThroughExactFence(t *testing.T) {
	binary := []byte("bounded-windows-host-binary")
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	hostHash := sha256.Sum256(binary)
	var request struct {
		AttemptID string `json:"attempt_id"`
		LaunchID  string `json:"launch_id"`
	}
	var requestHash string
	fake := &scriptedSSH{}
	fake.runResult = func(_ context.Context, call int, _ []string, input []byte) ([]byte, error) {
		switch {
		case call == 0:
			return nil, nil
		case call == 1:
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(input)
			requestHash = hex.EncodeToString(hash[:])
			return nil, errors.New("lost launch response")
		case call >= 2 && call < 14:
			return mustJSON(t, map[string]any{
				"schema_version": 1,
				"status":         "error",
				"command":        "setup-owner status",
				"message":        "Setup attempt does not exist.",
			}), nil
		case call == 14:
			applied := SetupResult{SchemaVersion: 1, Status: "applied", Applied: true, HostSize: int64(len(binary)), HostSHA256: hex.EncodeToString(hostHash[:])}
			return mustJSON(t, map[string]any{
				"schema_version":   1,
				"attempt_id":       request.AttemptID,
				"launch_id":        request.LaunchID,
				"request_sha256":   requestHash,
				"status":           "terminal",
				"outcome":          "process_succeeded",
				"process":          "exited",
				"cleanup":          "tree_gone",
				"exit_code":        0,
				"stdout":           string(mustJSON(t, applied)),
				"stderr":           "",
				"stdout_truncated": false,
				"stderr_truncated": false,
				"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
			}), nil
		case call == 15:
			return nil, nil
		default:
			t.Fatalf("unexpected SSH call %d", call)
			return nil, nil
		}
	}

	applied, err := Setup(context.Background(), fake, adapterTarget(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	if !applied.Applied || len(fake.arguments) != 16 {
		t.Fatalf("apply = %+v, SSH calls = %d", applied, len(fake.arguments))
	}
	for _, call := range []int{2, 14} {
		recovered := decodedAdapterScript(t, fake.arguments[call])
		for _, required := range []string{
			`'setup-owner' 'status'`,
			`'--attempt-id' '` + request.AttemptID + `'`,
			`'--expect-request-sha256' '` + requestHash + `'`,
			`'--expect-launch-id' '` + request.LaunchID + `'`,
		} {
			if !strings.Contains(recovered, required) {
				t.Fatalf("recovery command %d missing %q: %s", call, required, recovered)
			}
		}
		if len(fake.inputs[call]) != 0 {
			t.Fatalf("status input %d = %q", call, fake.inputs[call])
		}
	}
}

func TestSetupPollsOwnedAttemptUntilTerminal(t *testing.T) {
	binary := []byte("bounded-windows-host-binary")
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	hostHash := sha256.Sum256(binary)
	var request struct {
		AttemptID string `json:"attempt_id"`
		LaunchID  string `json:"launch_id"`
	}
	var requestHash string
	fake := &scriptedSSH{}
	fake.runResult = func(_ context.Context, call int, _ []string, input []byte) ([]byte, error) {
		switch call {
		case 0:
			return nil, nil
		case 1:
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(input)
			requestHash = hex.EncodeToString(hash[:])
			return mustJSON(t, map[string]any{
				"schema_version": 1,
				"attempt_id":     request.AttemptID,
				"launch_id":      request.LaunchID,
				"request_sha256": requestHash,
				"status":         "owned",
				"receipt": map[string]any{
					"schema_version":       1,
					"attempt_id":           request.AttemptID,
					"launch_id":            request.LaunchID,
					"request_sha256":       requestHash,
					"keeper_pid":           100,
					"keeper_creation_time": "windows:100",
					"root_pid":             101,
					"root_creation_time":   "windows:101",
					"job_scope":            "unnamed-kill-on-close",
					"owned_at":             time.Now().UTC().Format(time.RFC3339Nano),
				},
			}), nil
		case 2:
			applied := SetupResult{SchemaVersion: 1, Status: "applied", Applied: true, HostSize: int64(len(binary)), HostSHA256: hex.EncodeToString(hostHash[:])}
			return mustJSON(t, map[string]any{
				"schema_version":   1,
				"attempt_id":       request.AttemptID,
				"launch_id":        request.LaunchID,
				"request_sha256":   requestHash,
				"status":           "terminal",
				"outcome":          "process_succeeded",
				"process":          "exited",
				"cleanup":          "tree_gone",
				"exit_code":        0,
				"stdout":           string(mustJSON(t, applied)),
				"stderr":           "",
				"stdout_truncated": false,
				"stderr_truncated": false,
				"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
			}), nil
		case 3:
			return nil, nil
		default:
			t.Fatalf("unexpected SSH call %d", call)
			return nil, nil
		}
	}

	applied, err := Setup(context.Background(), fake, adapterTarget(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	if !applied.Applied || len(fake.arguments) != 4 {
		t.Fatalf("apply = %+v, SSH calls = %d", applied, len(fake.arguments))
	}
	if status := decodedAdapterScript(t, fake.arguments[2]); !strings.Contains(status, `'setup-owner' 'status'`) || !strings.Contains(status, requestHash) {
		t.Fatalf("status command lost its fence: %s", status)
	}
}

func TestSetupCancellationStopsOnlyTheExactAttemptWithFreshContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, []byte("bounded-windows-host-binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var request struct {
		AttemptID string `json:"attempt_id"`
		LaunchID  string `json:"launch_id"`
	}
	var requestHash string
	fake := &scriptedSSH{}
	fake.runResult = func(callCtx context.Context, call int, arguments []string, input []byte) ([]byte, error) {
		switch call {
		case 0:
			return nil, nil
		case 1:
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(input)
			requestHash = hex.EncodeToString(hash[:])
			cancel()
			return nil, context.Canceled
		case 2:
			if callCtx.Err() != nil {
				t.Fatalf("stop reused canceled context: %v", callCtx.Err())
			}
			stop := decodedAdapterScript(t, arguments)
			if !strings.Contains(stop, `'setup-owner' 'stop'`) {
				t.Fatalf("cancellation did not stop the owner: %s", stop)
			}
			return mustJSON(t, map[string]any{
				"schema_version":   1,
				"attempt_id":       request.AttemptID,
				"launch_id":        request.LaunchID,
				"request_sha256":   requestHash,
				"status":           "terminal",
				"outcome":          "stopped_before_ownership",
				"process":          "not_started",
				"cleanup":          "tree_gone",
				"exit_code":        nil,
				"stdout":           "",
				"stderr":           "",
				"stdout_truncated": false,
				"stderr_truncated": false,
				"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
			}), nil
		case 3:
			if callCtx.Err() != nil {
				t.Fatalf("upload cleanup reused canceled context: %v", callCtx.Err())
			}
			return nil, nil
		default:
			t.Fatalf("unexpected SSH call %d", call)
			return nil, nil
		}
	}

	_, err := Setup(ctx, fake, adapterTarget(), path, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Setup() error = %v", err)
	}
	if len(fake.arguments) != 4 {
		t.Fatalf("SSH calls = %d", len(fake.arguments))
	}
	stop := decodedAdapterScript(t, fake.arguments[2])
	for _, required := range []string{
		`'--attempt-id' '` + request.AttemptID + `'`,
		`'--expect-request-sha256' '` + requestHash + `'`,
		`'--expect-launch-id' '` + request.LaunchID + `'`,
	} {
		if !strings.Contains(stop, required) {
			t.Fatalf("stop command missing %q: %s", required, stop)
		}
	}
}

func TestSetupRetriesStatusWhenLostLaunchIsNotYetVisible(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	binary := []byte("bounded-windows-host-binary")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	hostHash := sha256.Sum256(binary)
	var request struct {
		AttemptID string `json:"attempt_id"`
		LaunchID  string `json:"launch_id"`
	}
	var requestHash string
	fake := &scriptedSSH{}
	fake.runResult = func(_ context.Context, call int, arguments []string, input []byte) ([]byte, error) {
		switch call {
		case 0:
			return nil, nil
		case 1:
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(input)
			requestHash = hex.EncodeToString(hash[:])
			return nil, errors.New("lost launch response")
		case 2:
			return mustJSON(t, map[string]any{
				"schema_version": 1,
				"status":         "error",
				"command":        "setup-owner status",
				"message":        "Setup attempt does not exist.",
			}), nil
		case 3:
			status := decodedAdapterScript(t, arguments)
			if !strings.Contains(status, `'setup-owner' 'status'`) {
				t.Fatalf("lost launch recovery did not retry status: %s", status)
			}
			applied := SetupResult{SchemaVersion: 1, Status: "applied", Applied: true, HostSize: int64(len(binary)), HostSHA256: hex.EncodeToString(hostHash[:])}
			return mustJSON(t, map[string]any{
				"schema_version":   1,
				"attempt_id":       request.AttemptID,
				"launch_id":        request.LaunchID,
				"request_sha256":   requestHash,
				"status":           "terminal",
				"outcome":          "process_succeeded",
				"process":          "exited",
				"cleanup":          "tree_gone",
				"exit_code":        0,
				"stdout":           string(mustJSON(t, applied)),
				"stderr":           "",
				"stdout_truncated": false,
				"stderr_truncated": false,
				"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
			}), nil
		case 4:
			return nil, nil
		default:
			t.Fatalf("unexpected SSH call %d", call)
			return nil, nil
		}
	}

	applied, err := Setup(context.Background(), fake, adapterTarget(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	if !applied.Applied || len(fake.arguments) != 5 {
		t.Fatalf("apply = %+v, SSH calls = %d", applied, len(fake.arguments))
	}
	for _, call := range []int{2, 3} {
		status := decodedAdapterScript(t, fake.arguments[call])
		for _, required := range []string{request.AttemptID, request.LaunchID, requestHash} {
			if !strings.Contains(status, required) {
				t.Fatalf("status retry %d lost fence %q: %s", call, required, status)
			}
		}
	}
}

func TestSetupRetriesStatusAfterTransportLoss(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	binary := []byte("bounded-windows-host-binary")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	hostHash := sha256.Sum256(binary)
	var request setupOwnerRequest
	var requestHash string
	fake := &scriptedSSH{}
	fake.runResult = func(_ context.Context, call int, arguments []string, input []byte) ([]byte, error) {
		switch call {
		case 0:
			return nil, nil
		case 1:
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(input)
			requestHash = hex.EncodeToString(hash[:])
			return mustJSON(t, map[string]any{
				"schema_version": 1,
				"attempt_id":     request.AttemptID,
				"launch_id":      request.LaunchID,
				"request_sha256": requestHash,
				"status":         "owned",
				"receipt": map[string]any{
					"schema_version":       1,
					"attempt_id":           request.AttemptID,
					"launch_id":            request.LaunchID,
					"request_sha256":       requestHash,
					"keeper_pid":           100,
					"keeper_creation_time": "windows:100",
					"root_pid":             101,
					"root_creation_time":   "windows:101",
					"job_scope":            "unnamed-kill-on-close",
					"owned_at":             time.Now().UTC().Format(time.RFC3339Nano),
				},
			}), nil
		case 2:
			return nil, errors.New("SSH response lost")
		case 3:
			status := decodedAdapterScript(t, arguments)
			if !strings.Contains(status, `'setup-owner' 'status'`) {
				t.Fatalf("status transport recovery did not retry status: %s", status)
			}
			applied := SetupResult{SchemaVersion: 1, Status: "applied", Applied: true, HostSize: int64(len(binary)), HostSHA256: hex.EncodeToString(hostHash[:])}
			return mustJSON(t, map[string]any{
				"schema_version":   1,
				"attempt_id":       request.AttemptID,
				"launch_id":        request.LaunchID,
				"request_sha256":   requestHash,
				"status":           "terminal",
				"outcome":          "process_succeeded",
				"process":          "exited",
				"cleanup":          "tree_gone",
				"exit_code":        0,
				"stdout":           string(mustJSON(t, applied)),
				"stderr":           "",
				"stdout_truncated": false,
				"stderr_truncated": false,
				"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
			}), nil
		case 4:
			return nil, nil
		default:
			t.Fatalf("unexpected SSH call %d", call)
			return nil, nil
		}
	}

	applied, err := Setup(context.Background(), fake, adapterTarget(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	if !applied.Applied || len(fake.arguments) != 5 {
		t.Fatalf("apply = %+v, SSH calls = %d", applied, len(fake.arguments))
	}
}

func TestSetupRetriesExactStopAfterLostResponse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, []byte("bounded-windows-host-binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var request setupOwnerRequest
	var requestHash string
	fake := &scriptedSSH{}
	fake.runResult = func(callCtx context.Context, call int, arguments []string, input []byte) ([]byte, error) {
		switch call {
		case 0:
			return nil, nil
		case 1:
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(input)
			requestHash = hex.EncodeToString(hash[:])
			cancel()
			return nil, context.Canceled
		case 2:
			if callCtx.Err() != nil {
				t.Fatalf("first stop reused canceled context: %v", callCtx.Err())
			}
			return nil, errors.New("lost stop response")
		case 3:
			if callCtx.Err() != nil {
				t.Fatalf("stop retry reused canceled context: %v", callCtx.Err())
			}
			stop := decodedAdapterScript(t, arguments)
			if !strings.Contains(stop, `'setup-owner' 'stop'`) {
				t.Fatalf("lost stop response did not retry stop: %s", stop)
			}
			return mustJSON(t, map[string]any{
				"schema_version":   1,
				"attempt_id":       request.AttemptID,
				"launch_id":        request.LaunchID,
				"request_sha256":   requestHash,
				"status":           "terminal",
				"outcome":          "stopped_before_ownership",
				"process":          "not_started",
				"cleanup":          "tree_gone",
				"exit_code":        nil,
				"stdout":           "",
				"stderr":           "",
				"stdout_truncated": false,
				"stderr_truncated": false,
				"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
			}), nil
		case 4:
			return nil, nil
		default:
			t.Fatalf("unexpected SSH call %d", call)
			return nil, nil
		}
	}

	_, err := Setup(ctx, fake, adapterTarget(), path, true)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Setup() error = %v", err)
	}
	if len(fake.arguments) != 5 {
		t.Fatalf("SSH calls = %d", len(fake.arguments))
	}
	for _, call := range []int{2, 3} {
		stop := decodedAdapterScript(t, fake.arguments[call])
		for _, required := range []string{request.AttemptID, request.LaunchID, requestHash} {
			if !strings.Contains(stop, required) {
				t.Fatalf("stop retry %d lost fence %q: %s", call, required, stop)
			}
		}
	}
}

func TestSetupLeavesAttemptFilesWhenOwnerCannotProveCleanup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, []byte("bounded-windows-host-binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	var request setupOwnerRequest
	var requestHash string
	fake := &scriptedSSH{}
	fake.runResult = func(_ context.Context, call int, _ []string, input []byte) ([]byte, error) {
		switch {
		case call == 0:
			return nil, nil
		case call == 1:
			if err := json.Unmarshal(input, &request); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(input)
			requestHash = hex.EncodeToString(hash[:])
			cancel()
			return nil, context.Canceled
		case call == 2:
			return mustJSON(t, map[string]any{
				"schema_version":   1,
				"attempt_id":       request.AttemptID,
				"launch_id":        request.LaunchID,
				"request_sha256":   requestHash,
				"status":           "terminal",
				"outcome":          "cleanup_unverified",
				"process":          "cancelled",
				"cleanup":          "cleanup_unverified",
				"exit_code":        nil,
				"stdout":           "",
				"stderr":           "",
				"stdout_truncated": false,
				"stderr_truncated": false,
				"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
			}), nil
		default:
			t.Fatalf("remote upload cleanup ran without proof that the setup tree was gone")
			return nil, nil
		}
	}

	_, err := Setup(ctx, fake, adapterTarget(), path, true)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "cleanup not proved") {
		t.Fatalf("Setup() error = %v", err)
	}
	if len(fake.arguments) != 3 {
		t.Fatalf("SSH calls = %d", len(fake.arguments))
	}
}

func TestSetupPlansWithoutSSHAndAppliesOneBoundedHostBinary(t *testing.T) {
	binary := []byte("bounded-windows-host-binary")
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(binary)
	fake := &scriptedSSH{}
	planned, err := Setup(context.Background(), fake, adapterTarget(), path, false)
	if err != nil {
		t.Fatal(err)
	}
	if planned.Status != "plan" || planned.Applied || planned.HostSHA256 != hex.EncodeToString(hash[:]) || len(fake.inputs) != 0 {
		t.Fatalf("plan = %+v, SSH calls = %d", planned, len(fake.inputs))
	}

	setSetupOwnerTerminalResponse(t, fake, mustJSON(t, SetupResult{
		SchemaVersion: 1,
		Status:        "applied",
		Applied:       true,
		HostSize:      int64(len(binary)),
		HostSHA256:    hex.EncodeToString(hash[:]),
	}))
	applied, err := Setup(context.Background(), fake, adapterTarget(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Status != "applied" || !applied.Applied || len(fake.inputs) != 3 || len(fake.uploads) != 2 {
		t.Fatalf("apply = %+v, SSH calls = %d", applied, len(fake.inputs))
	}
	prepare := string(fake.inputs[0])
	if !strings.Contains(prepare, "Set-Acl -LiteralPath $root") || !strings.Contains(prepare, "Configured SSH user does not match the authenticated controller SID") || !strings.Contains(prepare, "Assert-TrustedAncestors $root $controllerSid") || !strings.Contains(prepare, "provision blendersessiond inside it first") || !strings.Contains(prepare, "host-lock.json") || !strings.Contains(prepare, "Assert-NoReparsePath") || !strings.Contains(prepare, "$operation.Lock(0, 1)") || strings.Contains(prepare, "Register-ScheduledTask") {
		t.Fatalf("unexpected setup prepare script: %s", prepare)
	}
	if strings.Count(prepare, "Assert-NoReparsePath $hostPath") < 2 || strings.Count(prepare, "Assert-RegularFileOrMissing $hostPath") < 2 {
		t.Fatal("setup prepare does not revalidate the existing host executable")
	}
	for index, arguments := range fake.arguments {
		if len(arguments[5]) >= 8_000 {
			t.Fatalf("encoded setup command %d is too large for the Windows command boundary: %d bytes", index, len(arguments[5]))
		}
	}
	if len(fake.inputs[0]) == 0 || len(fake.inputs[0]) > maxSetupScript {
		t.Fatalf("setup guard stdin = %d bytes", len(fake.inputs[0]))
	}
	if len(fake.inputs[1]) == 0 {
		t.Fatal("setup owner launch omitted its immutable request")
	}
	if fake.uploads[0].host != adapterTarget().SSHAlias || fake.uploads[0].source == path || !strings.HasPrefix(fake.uploads[0].destination, adapterTarget().WorkRoot+`\.setup-`) || !strings.HasSuffix(fake.uploads[0].destination, ".bin") || string(fake.uploads[0].contents) != string(binary) {
		t.Fatalf("upload = %+v", fake.uploads[0])
	}
	if _, err := os.Lstat(fake.uploads[0].source); !os.IsNotExist(err) {
		t.Fatalf("local binary snapshot remains after setup: %v", err)
	}
	if fake.uploads[1].host != adapterTarget().SSHAlias || !strings.HasSuffix(fake.uploads[1].destination, ".ps1") || len(fake.uploads[1].contents) == 0 {
		t.Fatalf("script upload = %+v", fake.uploads[1])
	}
	launch := decodedAdapterScript(t, fake.arguments[1])
	if !strings.Contains(launch, `'setup-owner' 'launch'`) || !strings.Contains(launch, "$env:BLENDERSESSIOND_STATE_DIR") || strings.Contains(launch, "ScriptBlock") {
		t.Fatalf("unexpected setup owner launch: %s", launch)
	}
	script := setupScript(adapterTarget(), SetupResult{HostSize: int64(len(binary)), HostSHA256: hex.EncodeToString(hash[:])}, fake.uploads[0].destination)
	if strings.Count(script, "Assert-NoReparsePath $hostPath") < 2 || strings.Count(script, "Assert-RegularFileOrMissing $hostPath") < 2 {
		t.Fatal("setup apply does not revalidate the existing host executable")
	}
	for _, required := range []string{
		fake.uploads[0].destination,
		"$total -lt $expectedSize",
		"[Math]::Min($buffer.Length, $expectedSize - $total)",
		"SHA256",
		"Register-ScheduledTask",
		"New-ScheduledTaskPrincipal",
		"LogonType Interactive",
		"RunLevel Limited",
		"MultipleInstances IgnoreNew",
		"ExecutionTimeLimit ([TimeSpan]::Zero)",
		"SetSecurityDescriptor",
		"(A;;GA;;;",
		"Slice 0 requires the SSH controller and interactive task to use the same Windows identity",
		"[System.IO.File]::Replace($temporary, $hostPath, $backup)",
		"Remove-Item -Force -LiteralPath $backup",
		"FileSecurity",
		"SetOwner($controllerSid)",
		"Set-Acl -LiteralPath $hostPath",
		"Set-Acl -LiteralPath $daemonPath",
		"Set-BlenderBoxStateTree",
		"Set-BlenderBoxDirectoryPath",
		"FileAttributes]::ReparsePoint",
		"host-lock.json",
		"Assert-NoReparsePath",
		"Configured SSH user does not match the authenticated controller SID",
		"$operation.Lock(0, 1)",
		"$operation.Unlock(0, 1)",
		"host run-request --state-root",
		adapterTarget().HostExecutable,
		adapterTarget().SessionBrokerExecutable,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("setup script missing %q", required)
		}
	}
}

func TestSetupUploadsTheValidatedBinarySnapshot(t *testing.T) {
	original := []byte("validated-host-binary")
	changed := []byte("changed-after-validation")
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, original, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(original)
	fake := &scriptedSSH{}
	setSetupOwnerTerminalResponse(t, fake, mustJSON(t, SetupResult{
		SchemaVersion: 1,
		Status:        "applied",
		Applied:       true,
		HostSize:      int64(len(original)),
		HostSHA256:    hex.EncodeToString(hash[:]),
	}))
	fake.runHook = func() {
		if err := os.WriteFile(path, changed, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := Setup(context.Background(), fake, adapterTarget(), path, true); err != nil {
		t.Fatal(err)
	}
	if len(fake.uploads) != 2 || string(fake.uploads[0].contents) != string(original) || fake.uploads[0].source == path {
		t.Fatalf("binary upload did not use validated snapshot: %+v", fake.uploads)
	}
}

func TestSetupAncestorsTrustOnlyControllerAndSystemAuthority(t *testing.T) {
	prepare := prepareSetupScript(adapterTarget(), testSetupAttemptID)
	apply := setupScript(adapterTarget(), SetupResult{HostSize: 1, HostSHA256: strings.Repeat("a", 64)}, `C:\BlenderBoxTest\.setup-host.bin`)
	if !strings.Contains(prepare, "function Assert-TrustedAncestors([string]$Path, [System.Security.Principal.SecurityIdentifier]$ControllerSid)") ||
		!strings.Contains(prepare, "$trusted = @($ControllerSid.Value, 'S-1-5-18'") ||
		strings.Contains(prepare, "$trusted = @($PrincipalSid.Value, $ControllerSid.Value") ||
		!strings.Contains(apply, "Assert-TrustedAncestors $root $controllerSid") ||
		strings.Contains(apply, "Assert-TrustedAncestors $root $interactiveSid $controllerSid") {
		t.Fatal("setup trusts the interactive task user to replace a work-root ancestor")
	}
}

func TestSetupTrustsExistingManagedPathsBeforePathBasedMutation(t *testing.T) {
	for name, script := range map[string]string{
		"prepare": prepareSetupScript(adapterTarget(), testSetupAttemptID),
		"apply":   setupScript(adapterTarget(), SetupResult{HostSize: 1, HostSHA256: strings.Repeat("a", 64)}, `C:\BlenderBoxTest\.setup-host.bin`),
	} {
		for _, required := range []string{
			"function Assert-TrustedManagedPath",
			"[System.Security.AccessControl.FileSystemRights]::Write",
			"[System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles",
			"Assert-TrustedManagedPath $current $ControllerSid",
			"Assert-TrustedManagedPath $root $controllerSid",
			"Assert-TrustedManagedPath $daemonPath $controllerSid",
			"Assert-TrustedManagedPath $launchPath $controllerSid",
		} {
			if !strings.Contains(script, required) {
				t.Fatalf("%s script does not fail closed on existing managed authority: missing %q", name, required)
			}
		}
		trustRoot := strings.LastIndex(script, "Assert-TrustedManagedPath $root $controllerSid")
		setRoot := strings.LastIndex(script, "Set-Acl -LiteralPath $root")
		if trustRoot < 0 || setRoot < 0 || trustRoot > setRoot {
			t.Fatalf("%s script mutates the work root before trusting its current ACL", name)
		}
	}
	apply := setupScript(adapterTarget(), SetupResult{HostSize: 1, HostSHA256: strings.Repeat("a", 64)}, `C:\BlenderBoxTest\.setup-host.bin`)
	for _, required := range []string{
		"Assert-TrustedManagedPath $directory.FullName $controllerSid",
		"Assert-TrustedManagedPath $child.FullName $controllerSid",
	} {
		if !strings.Contains(apply, required) {
			t.Fatalf("apply script does not seal existing state descendants: missing %q", required)
		}
	}
}

func TestSetupRequiresControllerToOwnInteractiveTaskIdentityBeforeMutation(t *testing.T) {
	selected := adapterTarget()
	selected.InteractiveUser = "task-user"
	selected.SSHUser = "controller-user"
	prepare := prepareSetupScript(selected, testSetupAttemptID)
	apply := setupScript(selected, SetupResult{HostSize: 1, HostSHA256: strings.Repeat("a", 64)}, `C:\BlenderBoxTest\.setup-host.bin`)
	guard := "if ($interactiveSid -ne $authenticatedControllerSid) { throw 'Slice 0 requires the SSH controller and interactive task to use the same Windows identity.' }"
	for name, script := range map[string]string{"prepare": prepare, "apply": apply} {
		guardIndex := strings.Index(script, guard)
		mutationIndex := strings.Index(script, "$operation = Enter-BlenderBoxOperation $operationPath")
		if guardIndex < 0 || mutationIndex < 0 || guardIndex > mutationIndex {
			t.Fatalf("%s script does not reject a split identity before mutation", name)
		}
	}
}

func TestSetupCreatesAndSealsBothHostLockFiles(t *testing.T) {
	prepare := prepareSetupScript(adapterTarget(), testSetupAttemptID)
	apply := setupScript(adapterTarget(), SetupResult{HostSize: 1, HostSHA256: strings.Repeat("a", 64)}, `C:\BlenderBoxTest\.setup-host.bin`)
	for name, script := range map[string]string{"prepare": prepare, "apply": apply} {
		for _, required := range []string{
			"$launchPath = [System.IO.Path]::Combine($root, '.launch.lock')",
			"Assert-NoReparsePath $launchPath",
			"Set-Acl -LiteralPath $launchPath -AclObject",
		} {
			if !strings.Contains(script, required) {
				t.Fatalf("%s script does not seal launch lock: missing %q", name, required)
			}
		}
	}
}

func TestSetupRequiresCompatibleSessionBrokerBeforeTaskRegistration(t *testing.T) {
	for name, script := range map[string]string{
		"prepare": prepareSetupScript(adapterTarget(), testSetupAttemptID),
		"apply":   setupScript(adapterTarget(), SetupResult{HostSize: 1, HostSHA256: strings.Repeat("a", 64)}, `C:\BlenderBoxTest\.setup-host.bin`),
	} {
		for _, required := range []string{
			"function Assert-CompatibleSessionBroker",
			"function Invoke-SessionBrokerProbe",
			"'capabilities', '--require', 'blender-box-v1', '--require-capability', 'typed-call-error-reason', '--require-capability', 'windows-setup-owner-v1'",
			"Start-Process -FilePath $Path",
			"-RedirectStandardOutput 'NUL'",
			"-RedirectStandardError '\\\\.\\NUL'",
			"$null = $process.Handle",
			"WaitForExit(10000)",
			"Assert-CompatibleSessionBroker $daemonPath",
		} {
			if !strings.Contains(script, required) {
				t.Fatalf("%s script does not enforce daemon contract: missing %q", name, required)
			}
		}
		for _, forbidden := range []string{"$process.WaitForExit()", ".GetAwaiter().GetResult()", "ReadToEndAsync", "CopyToAsync", "MemoryStream"} {
			if strings.Contains(script, forbidden) {
				t.Fatalf("%s script contains unbounded probe operation %q", name, forbidden)
			}
		}
	}
}

func TestSetupPreservesSingleIdentityUpdateAuthority(t *testing.T) {
	selected := adapterTarget()
	prepare := prepareSetupScript(selected, testSetupAttemptID)
	script := setupScript(selected, SetupResult{HostSize: 1, HostSHA256: strings.Repeat("a", 64)}, `C:\BlenderBoxTest\.setup-host.bin`)

	if !strings.Contains(prepare, "$fileAcl.SetOwner($controllerSid)") || !strings.Contains(prepare, "$controllerSid, [System.Security.AccessControl.FileSystemRights]::FullControl") {
		t.Fatal("setup prepare does not preserve existing executable update authority")
	}
	if !strings.Contains(prepare, "$executableDirectoryAcl.SetOwner($controllerSid)") || !strings.Contains(prepare, "Set-BlenderBoxDirectoryPath $root $hostDirectory $executableDirectoryAcl") || !strings.Contains(prepare, "Set-BlenderBoxDirectoryPath $root $daemonDirectory $executableDirectoryAcl") {
		t.Fatal("setup prepare does not isolate executable directory authority")
	}
	if !strings.Contains(script, "$acl.SetOwner($controllerSid)") || !strings.Contains(script, "$controllerSid, [System.Security.AccessControl.FileSystemRights]::FullControl") {
		t.Fatal("managed paths do not preserve controller update authority")
	}
	if strings.Contains(script, "$controllerSid -ne $interactiveSid") || strings.Contains(script, "$interactiveSid, [System.Security.AccessControl.FileSystemRights]") {
		t.Fatal("setup retains unreachable split-user ACL grants")
	}
	if !strings.Contains(script, "function New-BlenderBoxExecutableDirectoryAcl") || !strings.Contains(script, "Set-BlenderBoxDirectoryPath $root $hostDirectory (New-BlenderBoxExecutableDirectoryAcl)") || !strings.Contains(script, "Set-BlenderBoxDirectoryPath $root $daemonDirectory (New-BlenderBoxExecutableDirectoryAcl)") {
		t.Fatal("setup apply does not isolate executable directory authority")
	}
	if !strings.Contains(script, "Set-Acl -LiteralPath $root -AclObject (New-BlenderBoxRootAcl)") {
		t.Fatal("work root does not receive the single-identity ACL")
	}
}

func TestSetupEscapesEveryPowerShellLiteralBoundary(t *testing.T) {
	selected := adapterTarget()
	selected.WorkRoot = `C:\Operator's Box`
	selected.HostExecutable = `C:\Operator's Box\bin\blender-box.exe`
	selected.SessionBrokerExecutable = `C:\Operator's Box\daemon\blendersessiond.exe`
	selected.BlenderExecutable = `C:\Program Files\Blender's Build\blender.exe`
	selected.InteractiveUser = `HOST\O'Brien`
	selected.SSHUser = `HOST\O'Brien`
	selected.TaskName = `Blender's Box`
	stagedBinary := `C:\Operator's Box\.setup-host.bin`
	stagedScript := `C:\Operator's Box\.setup-script.ps1`

	prepare := prepareSetupScript(selected, testSetupAttemptID)
	for _, want := range []string{
		`$root = 'C:\Operator''s Box'`,
		`$daemonPath = 'C:\Operator''s Box\daemon\blendersessiond.exe'`,
		`$blenderPath = 'C:\Program Files\Blender''s Build\blender.exe'`,
		`$interactiveUser = 'HOST\O''Brien'`,
	} {
		if !strings.Contains(prepare, want) {
			t.Fatalf("prepare script missing escaped literal %q", want)
		}
	}

	apply := setupScript(selected, SetupResult{HostSize: 1, HostSHA256: strings.Repeat("a", 64)}, stagedBinary)
	for _, want := range []string{
		`$root = 'C:\Operator''s Box'`,
		`$taskName = 'Blender''s Box'`,
		`$expectedArguments = 'host run-request --state-root "C:\Operator''s Box"'`,
		`$stagedBinary = 'C:\Operator''s Box\.setup-host.bin'`,
	} {
		if !strings.Contains(apply, want) {
			t.Fatalf("apply script missing escaped literal %q", want)
		}
	}

	fake := &scriptedSSH{outputs: [][]byte{mustJSON(t, map[string]any{
		"schema_version": 1,
		"status":         "error",
		"command":        "setup-owner launch",
		"message":        "test response",
	}), nil}}
	if _, err := invokeSetupOwner(context.Background(), fake, selected, "launch", nil, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	launch := decodedAdapterScript(t, fake.arguments[0])
	if !strings.Contains(launch, `$env:BLENDERSESSIOND_STATE_DIR = 'C:\Operator''s Box\setup-owner'`) || !strings.Contains(launch, `& 'C:\Operator''s Box\daemon\blendersessiond.exe'`) {
		t.Fatalf("setup owner command does not escape paths: %s", launch)
	}
	_ = cleanupSetupUploads(context.Background(), fake, selected, []string{stagedBinary, stagedScript}, context.Canceled)
	cleanup := decodedAdapterScript(t, fake.arguments[1])
	if strings.Count(cleanup, `'C:\Operator''s Box\`) != 4 {
		t.Fatalf("cleanup paths are not escaped: %s", cleanup)
	}
}

func TestSetupRejectsEmptyHostBinaryBeforeSSH(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &scriptedSSH{}
	if _, err := Setup(context.Background(), fake, adapterTarget(), path, true); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("Setup() error = %v", err)
	}
	if len(fake.arguments) != 0 || len(fake.uploads) != 0 {
		t.Fatal("empty host binary reached SSH")
	}
}

func TestSetupValidatesTargetBeforeAnySSHCall(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}
	selected := adapterTarget()
	selected.HostExecutable = `C:\Outside\blender-box.exe`
	fake := &scriptedSSH{}
	_, err := Setup(context.Background(), fake, selected, path, true)
	if err == nil || !strings.Contains(err.Error(), "inside work_root") {
		t.Fatalf("Setup() error = %v", err)
	}
	if len(fake.arguments) != 0 || len(fake.uploads) != 0 {
		t.Fatal("invalid target reached SSH")
	}
}

func TestSetupRejectsRemoteResultThatOmitsBinaryAttestation(t *testing.T) {
	binary := []byte("bounded-windows-host-binary")
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &scriptedSSH{}
	setSetupOwnerTerminalResponse(t, fake, []byte(`{"status":"applied","applied":true}`))

	_, err := Setup(context.Background(), fake, adapterTarget(), path, true)
	if err == nil || !strings.Contains(err.Error(), "invalid contract") {
		t.Fatalf("Setup() error = %v", err)
	}
	if len(fake.arguments) != 3 {
		t.Fatalf("SSH calls = %d; terminal invalid output did not clean exact uploads", len(fake.arguments))
	}
	cleanup := decodedAdapterScript(t, fake.arguments[2])
	for _, upload := range fake.uploads {
		if !strings.Contains(cleanup, upload.destination) {
			t.Fatalf("cleanup omitted %q: %s", upload.destination, cleanup)
		}
	}
}

func TestSetupRejectsUnknownRemoteResultField(t *testing.T) {
	binary := []byte("bounded-windows-host-binary")
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(binary)
	fake := &scriptedSSH{}
	setSetupOwnerTerminalResponse(t, fake, mustJSON(t, map[string]any{
		"schema_version": 1,
		"status":         "applied",
		"applied":        true,
		"host_size":      len(binary),
		"host_sha256":    hex.EncodeToString(hash[:]),
		"unexpected":     true,
	}))

	_, err := Setup(context.Background(), fake, adapterTarget(), path, true)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("Setup() error = %v", err)
	}
	if len(fake.arguments) != 3 {
		t.Fatalf("SSH calls = %d; strict decode failure did not clean exact uploads", len(fake.arguments))
	}
}

func TestSetupRejectsTrailingRemoteResultJSON(t *testing.T) {
	binary := []byte("bounded-windows-host-binary")
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(binary)
	output := mustJSON(t, SetupResult{SchemaVersion: 1, Status: "applied", Applied: true, HostSize: int64(len(binary)), HostSHA256: hex.EncodeToString(hash[:])})
	output = append(output, []byte("\n{}")...)
	fake := &scriptedSSH{}
	setSetupOwnerTerminalResponse(t, fake, output)

	_, err := Setup(context.Background(), fake, adapterTarget(), path, true)
	if err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("Setup() error = %v", err)
	}
	if len(fake.arguments) != 3 {
		t.Fatalf("SSH calls = %d; trailing result cleanup did not run", len(fake.arguments))
	}
}

func TestSetupDoesNotSucceedWhenTerminalUploadCleanupFails(t *testing.T) {
	binary := []byte("bounded-windows-host-binary")
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(binary)
	fake := &scriptedSSH{}
	setSetupOwnerTerminalResponse(t, fake, mustJSON(t, SetupResult{SchemaVersion: 1, Status: "applied", Applied: true, HostSize: int64(len(binary)), HostSHA256: hex.EncodeToString(hash[:])}))
	terminalResult := fake.runResult
	fake.runResult = func(ctx context.Context, call int, arguments []string, input []byte) ([]byte, error) {
		if call == 2 {
			return nil, errors.New("cleanup unavailable")
		}
		return terminalResult(ctx, call, arguments, input)
	}

	_, err := Setup(context.Background(), fake, adapterTarget(), path, true)
	if err == nil || !strings.Contains(err.Error(), "clean setup uploads") || !strings.Contains(err.Error(), "cleanup unavailable") {
		t.Fatalf("Setup() error = %v", err)
	}
}

func setSetupOwnerTerminalResponse(t *testing.T, fake *scriptedSSH, stdout []byte) {
	t.Helper()
	fake.runResult = func(_ context.Context, call int, _ []string, input []byte) ([]byte, error) {
		if call == 0 {
			return nil, nil
		}
		if call == 2 {
			return nil, nil
		}
		if call != 1 {
			t.Fatalf("unexpected SSH call %d", call)
		}
		var request setupOwnerRequest
		if err := json.Unmarshal(input, &request); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(input)
		return mustJSON(t, map[string]any{
			"schema_version":   1,
			"attempt_id":       request.AttemptID,
			"launch_id":        request.LaunchID,
			"request_sha256":   hex.EncodeToString(hash[:]),
			"status":           "terminal",
			"outcome":          "process_succeeded",
			"process":          "exited",
			"cleanup":          "tree_gone",
			"exit_code":        0,
			"stdout":           string(stdout),
			"stderr":           "",
			"stdout_truncated": false,
			"stderr_truncated": false,
			"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
		}), nil
	}
}
