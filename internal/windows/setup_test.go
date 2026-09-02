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

func TestSetupAncestorsTrustOnlyControllerAndSystemAuthority(t *testing.T) {
	prepare := prepareSetupScript(adapterTarget())
	apply := setupScript(adapterTarget(), SetupResult{HostSize: 1, HostSHA256: strings.Repeat("a", 64)}, `C:\BlenderBoxTest\.setup-host.bin`)
	if !strings.Contains(prepare, "function Assert-TrustedAncestors([string]$Path, [System.Security.Principal.SecurityIdentifier]$ControllerSid)") ||
		!strings.Contains(prepare, "$trusted = @($ControllerSid.Value, 'S-1-5-18'") ||
		strings.Contains(prepare, "$trusted = @($PrincipalSid.Value, $ControllerSid.Value") ||
		!strings.Contains(apply, "Assert-TrustedAncestors $root $controllerSid") ||
		strings.Contains(apply, "Assert-TrustedAncestors $root $interactiveSid $controllerSid") {
		t.Fatal("setup trusts the interactive task user to replace a work-root ancestor")
	}
}

func TestSetupRequiresControllerToOwnInteractiveTaskIdentityBeforeMutation(t *testing.T) {
	selected := adapterTarget()
	selected.InteractiveUser = "task-user"
	selected.SSHUser = "controller-user"
	prepare := prepareSetupScript(selected)
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

func TestSetupPreservesSingleIdentityUpdateAuthority(t *testing.T) {
	selected := adapterTarget()
	prepare := prepareSetupScript(selected)
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

	prepare := prepareSetupScript(selected)
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

	bootstrap := setupScriptBootstrap(stagedScript, 1, strings.Repeat("a", 64))
	if !strings.Contains(bootstrap, `$path = 'C:\Operator''s Box\.setup-script.ps1'`) {
		t.Fatalf("bootstrap path is not escaped: %s", bootstrap)
	}
	fake := &scriptedSSH{outputs: [][]byte{nil}}
	_ = cleanupSetupUploads(context.Background(), fake, selected, []string{stagedBinary, stagedScript}, context.Canceled)
	cleanup := decodedAdapterScript(t, fake.arguments[0])
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

func TestSetupRejectsRemoteResultThatOmitsBinaryAttestation(t *testing.T) {
	binary := []byte("bounded-windows-host-binary")
	path := filepath.Join(t.TempDir(), "blender-box.exe")
	if err := os.WriteFile(path, binary, 0o600); err != nil {
		t.Fatal(err)
	}
	fake := &scriptedSSH{outputs: [][]byte{nil, []byte(`{"status":"applied","applied":true}`)}}

	_, err := Setup(context.Background(), fake, adapterTarget(), path, true)
	if err == nil || !strings.Contains(err.Error(), "invalid contract") {
		t.Fatalf("Setup() error = %v", err)
	}
}
