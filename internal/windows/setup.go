package windows

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/BramVR/blender-box/internal/target"
)

const (
	maxHostBinary  = 64 << 20
	maxSetupScript = 128 << 10
	setupTimeout   = 5 * time.Minute
)

type SetupResult struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Applied       bool   `json:"applied"`
	HostSize      int64  `json:"host_size"`
	HostSHA256    string `json:"host_sha256"`
}

func Setup(ctx context.Context, ssh SetupSSH, selected target.Target, source string, apply bool) (SetupResult, error) {
	contents, err := readHostBinary(source)
	if err != nil {
		return SetupResult{}, err
	}
	hash := sha256.Sum256(contents)
	result := SetupResult{
		SchemaVersion: 1,
		Status:        "plan",
		Applied:       false,
		HostSize:      int64(len(contents)),
		HostSHA256:    hex.EncodeToString(hash[:]),
	}
	if !apply {
		return result, nil
	}
	if ssh == nil {
		return SetupResult{}, fmt.Errorf("SSH transport is unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	var nonce [16]byte
	if _, err := cryptorand.Read(nonce[:]); err != nil {
		return SetupResult{}, fmt.Errorf("create setup transfer identity: %w", err)
	}
	transferID := hex.EncodeToString(nonce[:])
	stagedBinary := fmt.Sprintf(`%s\.setup-%s.bin`, selected.WorkRoot, transferID)
	stagedScript := fmt.Sprintf(`%s\.setup-%s.ps1`, selected.WorkRoot, transferID)
	script := setupScript(selected, result, stagedBinary)
	localScript, err := writeSetupScript(script)
	if err != nil {
		return SetupResult{}, err
	}
	defer os.Remove(localScript)
	if _, err := ssh.Run(ctx, selected.SSHAlias, powerShellArguments(prepareSetupScript(selected)), nil); err != nil {
		return SetupResult{}, fmt.Errorf("prepare Windows setup: %w", err)
	}
	if err := ssh.Upload(ctx, selected.SSHAlias, source, stagedBinary); err != nil {
		return SetupResult{}, cleanupSetupUploads(ctx, ssh, selected, []string{stagedBinary, stagedScript}, fmt.Errorf("upload Windows host binary: %w", err))
	}
	if err := ssh.Upload(ctx, selected.SSHAlias, localScript, stagedScript); err != nil {
		return SetupResult{}, cleanupSetupUploads(ctx, ssh, selected, []string{stagedBinary, stagedScript}, fmt.Errorf("upload Windows setup script: %w", err))
	}
	scriptHash := sha256.Sum256([]byte(script))
	bootstrap := setupScriptBootstrap(stagedScript, int64(len(script)), hex.EncodeToString(scriptHash[:]))
	output, err := ssh.Run(ctx, selected.SSHAlias, powerShellArguments(bootstrap), nil)
	if err != nil {
		return SetupResult{}, cleanupSetupUploads(ctx, ssh, selected, []string{stagedBinary, stagedScript}, fmt.Errorf("apply Windows setup: %w", err))
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return SetupResult{}, fmt.Errorf("decode Windows setup result: %w", err)
	}
	if result.SchemaVersion != 1 || result.Status != "applied" || !result.Applied || result.HostSize != int64(len(contents)) || result.HostSHA256 != hex.EncodeToString(hash[:]) {
		return SetupResult{}, fmt.Errorf("Windows setup returned an invalid contract")
	}
	return result, nil
}

func powerShellArguments(script string) []string {
	return []string{"powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(script)}
}

func writeSetupScript(script string) (string, error) {
	if len(script) == 0 || len(script) > maxSetupScript {
		return "", fmt.Errorf("setup script exceeds its limit")
	}
	file, err := os.CreateTemp("", "blender-box-setup-*.ps1")
	if err != nil {
		return "", fmt.Errorf("create local setup script: %w", err)
	}
	path := file.Name()
	ok := false
	defer func() {
		file.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", fmt.Errorf("secure local setup script: %w", err)
	}
	if _, err := file.WriteString(script); err != nil {
		return "", fmt.Errorf("write local setup script: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("sync local setup script: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close local setup script: %w", err)
	}
	ok = true
	return path, nil
}

func setupScriptBootstrap(path string, size int64, expectedHash string) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$path = '%s'
try {
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ne %d) { throw 'Setup script size changed in transfer.' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actualHash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($actualHash -cne '%s') { throw 'Setup script SHA256 changed in transfer.' }
    $script = [Text.Encoding]::UTF8.GetString($bytes)
    Remove-Item -Force -LiteralPath $path
    & ([ScriptBlock]::Create($script))
} finally {
    if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -Force -LiteralPath $path }
}`, path, size, expectedHash)
}

func cleanupSetupUploads(ctx context.Context, ssh SetupSSH, selected target.Target, paths []string, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	cleanupScript := "$ErrorActionPreference = 'Stop'\n"
	for _, path := range paths {
		cleanupScript += fmt.Sprintf("if (Test-Path -LiteralPath '%s' -PathType Leaf) { Remove-Item -Force -LiteralPath '%s' }\n", path, path)
	}
	if _, err := ssh.Run(cleanupCtx, selected.SSHAlias, powerShellArguments(cleanupScript), nil); err != nil {
		return errors.Join(cause, fmt.Errorf("clean setup uploads: %w", err))
	}
	return cause
}

func readHostBinary(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("host binary must be a regular file without symlinks")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	contents, err := io.ReadAll(io.LimitReader(file, maxHostBinary+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > maxHostBinary || int64(len(contents)) != info.Size() {
		return nil, fmt.Errorf("host binary exceeds its limit or changed during read")
	}
	return contents, nil
}

func prepareSetupScript(selected target.Target) string {
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$root = '%s'
$daemonPath = '%s'
$blenderPath = '%s'
$interactiveUser = '%s'
if (-not (Test-Path -LiteralPath $daemonPath -PathType Leaf)) { throw 'Declared blendersessiond executable is missing.' }
if (-not (Test-Path -LiteralPath $blenderPath -PathType Leaf)) { throw 'Declared Blender executable is missing.' }
$interactiveSid = ([System.Security.Principal.NTAccount]::new($interactiveUser)).Translate([System.Security.Principal.SecurityIdentifier])
$controllerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$none = [System.Security.AccessControl.PropagationFlags]::None
$allow = [System.Security.AccessControl.AccessControlType]::Allow
$acl = [System.Security.AccessControl.DirectorySecurity]::new()
$acl.SetAccessRuleProtection($true, $false)
$acl.SetOwner($interactiveSid)
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, [System.Security.AccessControl.FileSystemRights]::Modify, $inherit, $none, $allow))
if ($controllerSid -ne $interactiveSid) { $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::Modify, $inherit, $none, $allow)) }
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
Set-Acl -LiteralPath $root -AclObject $acl`, selected.WorkRoot, selected.SessionBrokerExecutable, selected.BlenderExecutable, selected.InteractiveUser)
}

func setupScript(selected target.Target, plan SetupResult, stagedBinary string) string {
	taskArguments := fmt.Sprintf(`host run-request --state-root "%s"`, selected.WorkRoot)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
$root = '%s'
$hostPath = '%s'
$daemonPath = '%s'
$blenderPath = '%s'
$interactiveUser = '%s'
$taskName = '%s'
$expectedArguments = '%s'
$expectedSize = [int64]%d
$expectedHash = '%s'
$stagedBinary = '%s'
$temporary = $hostPath + '.setup-' + [Guid]::NewGuid().ToString('N')
$backup = $hostPath + '.setup-backup-' + [Guid]::NewGuid().ToString('N')
function New-BlenderBoxDirectoryAcl {
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($interactiveSid)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, [System.Security.AccessControl.FileSystemRights]::Modify, $inherit, $none, $allow))
    if ($controllerSid -ne $interactiveSid) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::Modify, $inherit, $none, $allow))
    }
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    return $acl
}
function New-BlenderBoxFileAcl {
    $noneInheritance = [System.Security.AccessControl.InheritanceFlags]::None
    $nonePropagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($interactiveSid)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $noneInheritance, $nonePropagation, $allow))
    if ($controllerSid -ne $interactiveSid) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $noneInheritance, $nonePropagation, $allow))
    }
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, $noneInheritance, $nonePropagation, $allow))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, $noneInheritance, $nonePropagation, $allow))
    return $acl
}
try {
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $hostDirectory = [System.IO.Path]::GetDirectoryName($hostPath)
    $daemonDirectory = [System.IO.Path]::GetDirectoryName($daemonPath)
    New-Item -ItemType Directory -Force -Path $hostDirectory | Out-Null
    if (-not (Test-Path -LiteralPath $daemonPath -PathType Leaf)) { throw 'Declared blendersessiond executable is missing.' }
    if (-not (Test-Path -LiteralPath $blenderPath -PathType Leaf)) { throw 'Declared Blender executable is missing.' }
    $interactiveSid = ([System.Security.Principal.NTAccount]::new($interactiveUser)).Translate([System.Security.Principal.SecurityIdentifier])
    $controllerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    Set-Acl -LiteralPath $root -AclObject (New-BlenderBoxDirectoryAcl)
    Set-Acl -LiteralPath $hostDirectory -AclObject (New-BlenderBoxDirectoryAcl)
    if ($daemonDirectory -ine $hostDirectory) { Set-Acl -LiteralPath $daemonDirectory -AclObject (New-BlenderBoxDirectoryAcl) }
    if ((Get-Item -LiteralPath $stagedBinary).Length -ne $expectedSize) { throw 'Host binary size changed in transfer.' }
    $inputStream = [System.IO.File]::Open($stagedBinary, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
    $outputStream = [System.IO.File]::Open($temporary, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $buffer = [byte[]]::new(65536)
        [int64]$total = 0
        while ($total -lt $expectedSize) {
            $requested = [int][Math]::Min($buffer.Length, $expectedSize - $total)
            $read = $inputStream.Read($buffer, 0, $requested)
            if ($read -le 0) { throw 'Host binary ended before its declared size.' }
            $total += $read
            $outputStream.Write($buffer, 0, $read)
        }
        $outputStream.Flush($true)
    } finally {
        $outputStream.Dispose()
        $inputStream.Dispose()
    }
    if ((Get-Item -LiteralPath $temporary).Length -ne $expectedSize) { throw 'Host binary size changed in transfer.' }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $fileStream = [System.IO.File]::OpenRead($temporary)
        try { $actualHash = [System.BitConverter]::ToString($sha.ComputeHash($fileStream)).Replace('-', '').ToLowerInvariant() }
        finally { $fileStream.Dispose() }
    } finally { $sha.Dispose() }
    if ($actualHash -cne $expectedHash) { throw 'Host binary SHA256 changed in transfer.' }
    if (Test-Path -LiteralPath $hostPath) {
        [System.IO.File]::Replace($temporary, $hostPath, $backup)
        Remove-Item -Force -LiteralPath $backup
    } else {
        [System.IO.File]::Move($temporary, $hostPath)
    }
    Set-Acl -LiteralPath $hostPath -AclObject (New-BlenderBoxFileAcl)
    Set-Acl -LiteralPath $daemonPath -AclObject (New-BlenderBoxFileAcl)
    $action = New-ScheduledTaskAction -Execute $hostPath -Argument $expectedArguments -WorkingDirectory ([System.IO.Path]::GetDirectoryName($hostPath))
    $principal = New-ScheduledTaskPrincipal -UserId $interactiveUser -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskPath '\' -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    $taskService = New-Object -ComObject 'Schedule.Service'
    $taskService.Connect()
    $registeredTask = $taskService.GetFolder('\').GetTask($taskName)
    $taskSddl = 'O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;' + $controllerSid.Value + ')'
    $registeredTask.SetSecurityDescriptor($taskSddl, 0)
    [ordered]@{schema_version=1; status='applied'; applied=$true; host_size=$expectedSize; host_sha256=$expectedHash} | ConvertTo-Json -Compress
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -Force -LiteralPath $temporary }
    if (Test-Path -LiteralPath $backup) { Remove-Item -Force -LiteralPath $backup }
    if (Test-Path -LiteralPath $stagedBinary) { Remove-Item -Force -LiteralPath $stagedBinary }
}
`, selected.WorkRoot, selected.HostExecutable, selected.SessionBrokerExecutable, selected.BlenderExecutable, selected.InteractiveUser, selected.TaskName, taskArguments, plan.HostSize, plan.HostSHA256, stagedBinary)
}
