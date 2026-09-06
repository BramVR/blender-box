package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestRunOwnedSetupBoundsOwnerCallsByRequestDeadline(t *testing.T) {
	fake := &scriptedSSH{}
	fake.runResult = func(callCtx context.Context, call int, arguments []string, input []byte) ([]byte, error) {
		if call != 0 {
			t.Fatalf("unexpected SSH call %d", call)
		}
		var request setupOwnerRequest
		rawRequest := setupOwnerRequestBytes(t, arguments, input)
		if err := json.Unmarshal(rawRequest, &request); err != nil {
			t.Fatal(err)
		}
		deadline, ok := callCtx.Deadline()
		if !ok || !deadline.Equal(request.DeadlineUTC) {
			t.Fatalf("SSH deadline = %v, present = %v; request deadline = %v", deadline, ok, request.DeadlineUTC)
		}
		hash := sha256.Sum256(rawRequest)
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
			"stdout":           "ok",
			"stderr":           "",
			"stdout_truncated": false,
			"stderr_truncated": false,
			"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
		}), nil
	}

	output, err := runOwnedSetup(context.Background(), fake, adapterTarget(), testSetupAttemptID, "bbsl_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", []byte("setup"))
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != "ok" {
		t.Fatalf("output = %q", output)
	}
}

func TestRunOwnedSetupClampsRequestDeadlineToCaller(t *testing.T) {
	callerDeadline := time.Now().Add(time.Minute)
	ctx, cancel := context.WithDeadline(context.Background(), callerDeadline)
	defer cancel()
	fake := &scriptedSSH{}
	fake.runResult = func(callCtx context.Context, call int, arguments []string, input []byte) ([]byte, error) {
		if call != 0 {
			t.Fatalf("unexpected SSH call %d", call)
		}
		var request setupOwnerRequest
		rawRequest := setupOwnerRequestBytes(t, arguments, input)
		if err := json.Unmarshal(rawRequest, &request); err != nil {
			t.Fatal(err)
		}
		callDeadline, ok := callCtx.Deadline()
		if !ok || !callDeadline.Equal(callerDeadline) || !request.DeadlineUTC.Equal(callerDeadline) {
			t.Fatalf("caller = %v, SSH = %v, present = %v, request = %v", callerDeadline, callDeadline, ok, request.DeadlineUTC)
		}
		hash := sha256.Sum256(rawRequest)
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
			"stdout":           "ok",
			"stderr":           "",
			"stdout_truncated": false,
			"stderr_truncated": false,
			"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
		}), nil
	}

	if _, err := runOwnedSetup(ctx, fake, adapterTarget(), testSetupAttemptID, "bbsl_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", []byte("setup")); err != nil {
		t.Fatal(err)
	}
}

func TestRunOwnedSetupPreservesProvenCleanupOnTerminalFailure(t *testing.T) {
	fake := &scriptedSSH{}
	fake.runResult = func(_ context.Context, call int, arguments []string, input []byte) ([]byte, error) {
		if call != 0 {
			t.Fatalf("terminal tree_gone triggered redundant SSH call %d", call)
		}
		var request setupOwnerRequest
		rawRequest := setupOwnerRequestBytes(t, arguments, input)
		if err := json.Unmarshal(rawRequest, &request); err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(rawRequest)
		return mustJSON(t, map[string]any{
			"schema_version":   1,
			"attempt_id":       request.AttemptID,
			"launch_id":        request.LaunchID,
			"request_sha256":   hex.EncodeToString(hash[:]),
			"status":           "terminal",
			"outcome":          "process_failed",
			"process":          "exited",
			"cleanup":          "tree_gone",
			"exit_code":        1,
			"stdout":           "",
			"stderr":           "failed",
			"stdout_truncated": false,
			"stderr_truncated": false,
			"finished_at":      time.Now().UTC().Format(time.RFC3339Nano),
		}), nil
	}

	_, err := runOwnedSetup(context.Background(), fake, adapterTarget(), testSetupAttemptID, "bbsl_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", []byte("setup"))
	if err == nil || !strings.Contains(err.Error(), "terminal failed") || !setupOwnerCleanupProved(err) {
		t.Fatalf("runOwnedSetup() error = %v, cleanup proved = %v", err, setupOwnerCleanupProved(err))
	}
}

func TestInvokeSetupOwnerRejectsTerminalWithoutCompleteCleanupEvidence(t *testing.T) {
	fake := &scriptedSSH{outputs: [][]byte{[]byte(`{
        "schema_version": 1,
        "attempt_id": "bbsa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "launch_id": "bbsl_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "request_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "status": "terminal",
        "outcome": "process_succeeded",
        "process": "exited",
        "cleanup": "tree_gone",
        "exit_code": 0,
        "stdout": "{}",
        "stderr": "",
        "stdout_truncated": false,
        "finished_at": "2026-09-03T10:00:00Z"
    }`)}}

	_, err := invokeSetupOwner(context.Background(), fake, adapterTarget(), "status", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "missing stderr_truncated") {
		t.Fatalf("invokeSetupOwner() error = %v", err)
	}
}

func TestInvokeSetupOwnerRejectsNullTruncationAttestations(t *testing.T) {
	response := `{
        "schema_version": 1,
        "attempt_id": "bbsa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "launch_id": "bbsl_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "request_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "status": "terminal",
        "outcome": "process_succeeded",
        "process": "exited",
        "cleanup": "tree_gone",
        "exit_code": 0,
        "stdout": "{}",
        "stderr": "",
        "stdout_truncated": false,
        "stderr_truncated": false,
        "finished_at": "2026-09-03T10:00:00Z"
    }`
	for _, field := range []string{"stdout_truncated", "stderr_truncated"} {
		t.Run(field, func(t *testing.T) {
			invalid := strings.Replace(response, `"`+field+`": false`, `"`+field+`": null`, 1)
			fake := &scriptedSSH{outputs: [][]byte{[]byte(invalid)}}
			_, err := invokeSetupOwner(context.Background(), fake, adapterTarget(), "status", nil, nil)
			if err == nil || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "boolean") {
				t.Fatalf("invokeSetupOwner() error = %v", err)
			}
		})
	}
}

func TestInvokeSetupOwnerRejectsNullTerminalStrings(t *testing.T) {
	response := `{
        "schema_version": 1,
        "attempt_id": "bbsa_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "launch_id": "bbsl_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "request_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "status": "terminal",
        "outcome": "process_succeeded",
        "process": "exited",
        "cleanup": "tree_gone",
        "exit_code": 0,
        "stdout": "{}",
        "stderr": "",
        "stdout_truncated": false,
        "stderr_truncated": false,
        "finished_at": "2026-09-03T10:00:00Z",
        "message": "done"
    }`
	for _, field := range []string{"attempt_id", "launch_id", "request_sha256", "status", "outcome", "process", "cleanup", "stdout", "stderr", "finished_at", "message"} {
		t.Run(field, func(t *testing.T) {
			pattern := regexp.MustCompile(`"` + field + `": ("(?:[^"\\]|\\.)*")`)
			invalid := pattern.ReplaceAllString(response, `"`+field+`": null`)
			if invalid == response {
				t.Fatalf("test did not replace %s", field)
			}
			fake := &scriptedSSH{outputs: [][]byte{[]byte(invalid)}}
			_, err := invokeSetupOwner(context.Background(), fake, adapterTarget(), "status", nil, nil)
			if err == nil || !strings.Contains(err.Error(), field) || !strings.Contains(err.Error(), "string") {
				t.Fatalf("invokeSetupOwner() error = %v", err)
			}
		})
	}
}

func TestRunOwnedSetupPreservesStructuredLaunchError(t *testing.T) {
	var request setupOwnerRequest
	var requestHash string
	fake := &scriptedSSH{}
	fake.runResult = func(_ context.Context, call int, arguments []string, input []byte) ([]byte, error) {
		switch call {
		case 0:
			rawRequest := setupOwnerRequestBytes(t, arguments, input)
			if err := json.Unmarshal(rawRequest, &request); err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(rawRequest)
			requestHash = hex.EncodeToString(hash[:])
			return mustJSON(t, map[string]any{
				"schema_version": 1,
				"status":         "error",
				"command":        "setup-owner launch",
				"message":        "staged setup script is missing",
				"reason":         "invalid-request",
			}), nil
		case 1:
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
		default:
			t.Fatalf("unexpected SSH call %d", call)
			return nil, nil
		}
	}

	_, err := runOwnedSetup(context.Background(), fake, adapterTarget(), testSetupAttemptID, "bbsl_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", []byte("setup"))
	if err == nil || !strings.Contains(err.Error(), "staged setup script is missing") || !strings.Contains(err.Error(), "invalid-request") || strings.Contains(err.Error(), "stale or invalid fence") || !setupOwnerCleanupProved(err) {
		t.Fatalf("runOwnedSetup() error = %v, cleanup proved = %v", err, setupOwnerCleanupProved(err))
	}
}
