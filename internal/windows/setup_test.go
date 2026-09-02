package windows

import (
	"context"
	"crypto/sha256"
	binaryencoding "encoding/binary"
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

	fake.outputs = [][]byte{mustJSON(t, SetupResult{
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
	if applied.Status != "applied" || !applied.Applied || len(fake.inputs) != 1 {
		t.Fatalf("apply = %+v, SSH calls = %d", applied, len(fake.inputs))
	}
	bootstrap := decodedAdapterScript(t, fake.arguments[0])
	if len(fake.arguments[0][5]) >= 8_000 {
		t.Fatalf("encoded bootstrap is too large for the Windows command boundary: %d bytes", len(fake.arguments[0][5]))
	}
	for _, required := range []string{"BBXSET01", "BlenderBoxSetupPayloadStream", "Read-Exact"} {
		if !strings.Contains(bootstrap, required) {
			t.Errorf("setup bootstrap missing %q", required)
		}
	}
	framed := fake.inputs[0]
	if len(framed) < 12 || string(framed[:8]) != "BBXSET01" {
		t.Fatalf("invalid setup frame header")
	}
	scriptSize := int(binaryencoding.LittleEndian.Uint32(framed[8:12]))
	if scriptSize <= 0 || 12+scriptSize > len(framed) {
		t.Fatalf("invalid framed script size %d", scriptSize)
	}
	script := string(framed[12 : 12+scriptSize])
	if got := framed[12+scriptSize:]; string(got) != string(binary) {
		t.Fatalf("transferred binary = %q", got)
	}
	for _, required := range []string{
		"BlenderBoxSetupPayloadStream",
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
		"[System.IO.File]::Replace",
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
