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
	if applied.Status != "applied" || !applied.Applied || len(fake.inputs) != 2 || len(fake.uploads) != 2 {
		t.Fatalf("apply = %+v, SSH calls = %d", applied, len(fake.inputs))
	}
	prepare := string(fake.inputs[0])
	if !strings.Contains(prepare, "Set-Acl -LiteralPath $root") || !strings.Contains(prepare, "host-lock.json") || !strings.Contains(prepare, "Assert-NoReparsePath") || !strings.Contains(prepare, "$operation.Lock(0, 1)") || strings.Contains(prepare, "Register-ScheduledTask") {
		t.Fatalf("unexpected setup prepare script: %s", prepare)
	}
	for index, arguments := range fake.arguments {
		if len(arguments[5]) >= 8_000 {
			t.Fatalf("encoded setup command %d is too large for the Windows command boundary: %d bytes", index, len(arguments[5]))
		}
	}
	if len(fake.inputs[0]) == 0 || len(fake.inputs[0]) > maxSetupScript {
		t.Fatalf("setup guard stdin = %d bytes", len(fake.inputs[0]))
	}
	if len(fake.inputs[1]) != 0 {
		t.Fatalf("setup finalize used stdin for %d bytes", len(fake.inputs[1]))
	}
	if fake.uploads[0].host != adapterTarget().SSHAlias || fake.uploads[0].source != path || !strings.HasPrefix(fake.uploads[0].destination, adapterTarget().WorkRoot+`\.setup-`) || !strings.HasSuffix(fake.uploads[0].destination, ".bin") || string(fake.uploads[0].contents) != string(binary) {
		t.Fatalf("upload = %+v", fake.uploads[0])
	}
	if fake.uploads[1].host != adapterTarget().SSHAlias || !strings.HasSuffix(fake.uploads[1].destination, ".ps1") || len(fake.uploads[1].contents) == 0 {
		t.Fatalf("script upload = %+v", fake.uploads[1])
	}
	finalize := decodedAdapterScript(t, fake.arguments[1])
	if !strings.Contains(finalize, "ReadAllBytes") || !strings.Contains(finalize, "SHA256") || !strings.Contains(finalize, "ScriptBlock") || !strings.Contains(finalize, fake.uploads[1].destination) {
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
		"Set-BlenderBoxStateTree",
		"Set-BlenderBoxDirectoryPath",
		"FileAttributes]::ReparsePoint",
		"host-lock.json",
		"Assert-NoReparsePath",
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
