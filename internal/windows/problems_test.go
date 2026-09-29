package windows

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/BramVR/blender-box/internal/orchestrator"
	"github.com/BramVR/blender-box/internal/pairing"
	sshtransport "github.com/BramVR/blender-box/internal/ssh"
	"github.com/BramVR/blender-box/internal/target"
)

func failedCheckResult(failed map[string]string) map[string]any {
	checks := make([]map[string]any, 0, 10)
	for _, id := range []string{
		"host.windows", "host.console-user", "host.ssh-user", "host.limited-token-policy",
		"blender.executable", "daemon.executable", "host.executable", "work-root.access",
		"work-root.state-tree", "task.interactive",
	} {
		message, fails := failed[id]
		checks = append(checks, map[string]any{"id": id, "passed": !fails, "required": true, "message": message})
	}
	return map[string]any{"schema_version": 1, "status": "fail", "checks": checks}
}

func problem(class, check, message, next string) orchestrator.HostProblem {
	return orchestrator.HostProblem{Class: class, Check: check, Message: message, Next: next}
}

func TestInspectClassifiesFailedReadinessChecks(t *testing.T) {
	fake := &scriptedSSH{outputs: [][]byte{mustJSON(t, failedCheckResult(map[string]string{
		"host.console-user": "Configured interactive user SID must own the console session.",
		"daemon.executable": "The staged session broker and parent must carry the setup ACL and the required CLI contract.",
		"task.interactive":  "The static task must match the complete Blender Box action, principal, and controller contract.",
	}))}}
	inspection, err := NewAdapter(fake).Inspect(context.Background(), adapterTarget(), orchestrator.HostRequirements{PayloadSchemaVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	want := []orchestrator.HostProblem{
		problem("interactive-desktop-unavailable", "host.console-user", "Configured interactive user SID must own the console session.", "sign in to the host desktop as the target's interactive user and leave that session signed in"),
		problem("runtime-incompatible", "daemon.executable", "The staged session broker and parent must carry the setup ACL and the required CLI contract.", "on the host, run `blender-box setup inspect --platform windows --state-root C:\\BlenderBoxTest` and reinstall the runtime it reports"),
		problem("setup-incomplete", "task.interactive", "The static task must match the complete Blender Box action, principal, and controller contract.", "on the host, run `blender-box setup inspect --platform windows --state-root C:\\BlenderBoxTest` and apply the reviewed plan"),
	}
	if inspection.Status != "fail" || !reflect.DeepEqual(inspection.Problems, want) {
		t.Fatalf("inspection = %+v", inspection)
	}
}

func TestInspectReportsTransportFailureAsProblem(t *testing.T) {
	fake := &scriptedSSH{runResult: func(context.Context, int, []string, []byte) ([]byte, error) {
		return nil, &sshtransport.Failure{Class: sshtransport.TailscaleUnreachable, Detail: "ssh: connect to host 100.101.102.103 port 22: Operation timed out"}
	}}
	inspection, err := NewAdapter(fake).Inspect(context.Background(), adapterTarget(), orchestrator.HostRequirements{PayloadSchemaVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	want := []orchestrator.HostProblem{problem("tailscale-unreachable", "ssh.connection", "ssh: connect to host 100.101.102.103 port 22: Operation timed out", "connect this machine to the tailnet (`tailscale status`) and check that the host is online there")}
	if inspection.Status != "fail" || !reflect.DeepEqual(inspection.Problems, want) {
		t.Fatalf("inspection = %+v", inspection)
	}
}

func TestRevokePairingSendsTypedRequestAndRequiresConfirmedResult(t *testing.T) {
	hash := strings.Repeat("a", 64)
	request := pairing.RevokeRequest{SchemaVersion: 1, PairID: "pair-1", ClientPublicKeyHash: strings.Repeat("f", 64)}
	confirmed := fmt.Sprintf(`{"schema_version":1,"pair_id":"pair-1","state":"revoked","keys_sha256_before":"%s","keys_sha256_after":"%s","tombstone_sha256":"%s"}`, hash, hash, hash)
	fake := &scriptedSSH{outputs: [][]byte{[]byte(confirmed), []byte(strings.Replace(confirmed, `"revoked"`, `"revoking"`, 1))}}
	adapter := NewAdapter(fake)
	result, err := adapter.RevokePairing(context.Background(), adapterTarget(), request)
	if err != nil || result != (pairing.RevokeResult{SchemaVersion: 1, PairID: "pair-1", State: "revoked", KeysSHA256Before: hash, KeysSHA256After: hash, TombstoneSHA256: hash}) {
		t.Fatalf("result = %+v, %v", result, err)
	}
	if want := `{"schema_version":1,"pair_id":"pair-1","client_public_key_hash":"` + strings.Repeat("f", 64) + `"}`; string(fake.inputs[0]) != want {
		t.Fatalf("request = %s", fake.inputs[0])
	}
	if script := decodedAdapterScript(t, fake.arguments[0]); !strings.Contains(script, `'host' 'pair-revoke' '--state-root' 'C:\BlenderBoxTest'`) {
		t.Fatalf("script = %s", script)
	}
	if _, err := adapter.RevokePairing(context.Background(), adapterTarget(), request); err == nil {
		t.Fatal("unfinished revocation accepted")
	}
}

func TestProbeReturnsTheTransportOutcome(t *testing.T) {
	rejected := &sshtransport.Failure{Class: sshtransport.AuthRejected, Detail: "operator@host: Permission denied (publickey)."}
	fake := &scriptedSSH{runResult: func(_ context.Context, call int, _ []string, _ []byte) ([]byte, error) {
		if call == 0 {
			return nil, nil
		}
		return nil, rejected
	}}
	adapter := NewAdapter(fake)
	if err := adapter.Probe(context.Background(), adapterTarget()); err != nil {
		t.Fatalf("authenticated probe = %v", err)
	}
	if err := adapter.Probe(context.Background(), adapterTarget()); err != rejected {
		t.Fatalf("rejected probe = %v", err)
	}
	if err := adapter.Probe(context.Background(), target.Target{}); err == nil || len(fake.arguments) != 2 {
		t.Fatal("zero target reached SSH")
	}
}
