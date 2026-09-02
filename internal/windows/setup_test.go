package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

	fake.outputs = [][]byte{nil, mustJSON(t, SetupResult{
		SchemaVersion: 1,
		Status:        "applied",
		Applied:       true,
		HostSize:      int64(len(binary)),
		HostSHA256:    hex.EncodeToString(hash[:]),
	})}
	applied, err := Setup(context.Background(), fake, adapterTarget(), path, true)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Status != "applied" || !applied.Applied || len(fake.inputs) != 2 || len(fake.uploads) != 1 {
		t.Fatalf("apply = %+v, SSH calls = %d", applied, len(fake.inputs))
	}
	prepare := decodedAdapterScript(t, fake.arguments[0])
	if !strings.Contains(prepare, "Set-Acl -LiteralPath $root") || strings.Contains(prepare, "Register-ScheduledTask") {
		t.Fatalf("unexpected setup prepare script: %s", prepare)
	}
	for index, arguments := range fake.arguments {
		if len(arguments[5]) >= 8_000 {
			t.Fatalf("encoded setup command %d is too large for the Windows command boundary: %d bytes", index, len(arguments[5]))
		}
	}
	for index, input := range fake.inputs {
		if len(input) != 0 {
			t.Fatalf("setup command %d used stdin for %d bytes", index, len(input))
		}
	}
	if fake.uploads[0].host != adapterTarget().SSHAlias || fake.uploads[0].source != path || !strings.HasPrefix(fake.uploads[0].destination, adapterTarget().WorkRoot+`\.setup-`) {
		t.Fatalf("upload = %+v", fake.uploads[0])
	}
	finalize := decodedAdapterScript(t, fake.arguments[1])
	if !strings.Contains(finalize, "[IO.Compression.CompressionMode]0") || !strings.Contains(finalize, "ScriptBlock") {
		t.Fatalf("unexpected setup finalize bootstrap: %s", finalize)
	}
	script := setupScript(adapterTarget(), SetupResult{HostSize: int64(len(binary)), HostSHA256: hex.EncodeToString(hash[:])}, fake.uploads[0].destination)
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
		"$controllerSid -ne $interactiveSid",
		"[System.IO.File]::Replace($temporary, $hostPath, $backup)",
		"Remove-Item -Force -LiteralPath $backup",
		"FileSecurity",
		"SetOwner($interactiveSid)",
		"Set-Acl -LiteralPath $hostPath",
		"Set-Acl -LiteralPath $daemonPath",
		"host run-request --state-root",
		adapterTarget().HostExecutable,
		adapterTarget().SessionBrokerExecutable,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("setup script missing %q", required)
		}
	}
}
