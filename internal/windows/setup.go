package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/BramVR/blender-box/internal/target"
)

const (
	maxHostBinary = 64 << 20
	setupTimeout  = 5 * time.Minute
)

type SetupResult struct {
	SchemaVersion int    `json:"schema_version"`
	Status        string `json:"status"`
	Applied       bool   `json:"applied"`
	HostSize      int64  `json:"host_size"`
	HostSHA256    string `json:"host_sha256"`
}

func Setup(ctx context.Context, ssh SSH, selected target.Target, source string, apply bool) (SetupResult, error) {
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
	script := setupScript(selected, result)
	arguments := []string{
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-EncodedCommand",
		encodePowerShell(script),
	}
	output, err := ssh.Run(ctx, selected.SSHAlias, arguments, contents)
	if err != nil {
		return SetupResult{}, fmt.Errorf("apply Windows setup: %w", err)
	}
	if err := json.Unmarshal(output, &result); err != nil {
		return SetupResult{}, fmt.Errorf("decode Windows setup result: %w", err)
	}
	if result.SchemaVersion != 1 || result.Status != "applied" || !result.Applied || result.HostSize != int64(len(contents)) || result.HostSHA256 != hex.EncodeToString(hash[:]) {
		return SetupResult{}, fmt.Errorf("Windows setup returned an invalid contract")
	}
	return result, nil
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

func setupScript(selected target.Target, plan SetupResult) string {
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
$temporary = $hostPath + '.setup-' + [Guid]::NewGuid().ToString('N')
try {
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    New-Item -ItemType Directory -Force -Path ([System.IO.Path]::GetDirectoryName($hostPath)) | Out-Null
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
    if ($controllerSid -ne $interactiveSid) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::Modify, $inherit, $none, $allow))
    }
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    Set-Acl -LiteralPath $root -AclObject $acl
    $inputStream = [Console]::OpenStandardInput()
    $outputStream = [System.IO.File]::Open($temporary, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $buffer = [byte[]]::new(65536)
        [int64]$total = 0
        while (($read = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $total += $read
            if ($total -gt $expectedSize) { throw 'Host binary exceeds declared size.' }
            $outputStream.Write($buffer, 0, $read)
        }
        $outputStream.Flush($true)
    } finally {
        $outputStream.Dispose()
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
        [System.IO.File]::Replace($temporary, $hostPath, $null)
    } else {
        [System.IO.File]::Move($temporary, $hostPath)
    }
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
}
`, selected.WorkRoot, selected.HostExecutable, selected.SessionBrokerExecutable, selected.BlenderExecutable, selected.InteractiveUser, selected.TaskName, taskArguments, plan.HostSize, plan.HostSHA256)
}
