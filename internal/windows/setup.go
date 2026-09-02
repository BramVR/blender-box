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
	prepare := prepareSetupScript(selected)
	if len(prepare) == 0 || len(prepare) > maxSetupScript {
		return SetupResult{}, fmt.Errorf("setup guard script exceeds its limit")
	}
	if _, err := ssh.Run(ctx, selected.SSHAlias, powerShellInputArguments(), []byte(prepare)); err != nil {
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
	var applied SetupResult
	if err := json.Unmarshal(output, &applied); err != nil {
		return SetupResult{}, fmt.Errorf("decode Windows setup result: %w", err)
	}
	if applied.SchemaVersion != 1 || applied.Status != "applied" || !applied.Applied || applied.HostSize != int64(len(contents)) || applied.HostSHA256 != hex.EncodeToString(hash[:]) {
		return SetupResult{}, fmt.Errorf("Windows setup returned an invalid contract")
	}
	return applied, nil
}

func powerShellArguments(script string) []string {
	return []string{"powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(script)}
}

func powerShellInputArguments() []string {
	return powerShellArguments("[Console]::In.ReadToEnd() | Invoke-Expression")
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
$path = %s
try {
    $bytes = [IO.File]::ReadAllBytes($path)
    if ($bytes.Length -ne %d) { throw 'Setup script size changed in transfer.' }
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $actualHash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
    if ($actualHash -cne %s) { throw 'Setup script SHA256 changed in transfer.' }
    $script = [Text.Encoding]::UTF8.GetString($bytes)
    Remove-Item -Force -LiteralPath $path
    & ([ScriptBlock]::Create($script))
} finally {
    if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -Force -LiteralPath $path }
}`, powerShellLiteral(path), size, powerShellLiteral(expectedHash))
}

func cleanupSetupUploads(ctx context.Context, ssh SetupSSH, selected target.Target, paths []string, cause error) error {
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	cleanupScript := "$ErrorActionPreference = 'Stop'\n"
	for _, path := range paths {
		literal := powerShellLiteral(path)
		cleanupScript += fmt.Sprintf("if (Test-Path -LiteralPath %s -PathType Leaf) { Remove-Item -Force -LiteralPath %s }\n", literal, literal)
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
	if len(contents) == 0 {
		return nil, fmt.Errorf("host binary must not be empty")
	}
	if len(contents) > maxHostBinary || int64(len(contents)) != info.Size() {
		return nil, fmt.Errorf("host binary exceeds its limit or changed during read")
	}
	return contents, nil
}

const setupOperationFunctions = `function Assert-NoReparsePath([string]$Path) {
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $volumeRoot = [System.IO.Path]::GetPathRoot($fullPath)
    if ($volumeRoot -notmatch '^[A-Za-z]:\\$') { throw 'Setup paths must use a local drive.' }
    $volume = @(Get-Volume -DriveLetter $volumeRoot.Substring(0, 1) -ErrorAction Stop)
    if ($volume.Count -ne 1 -or [string]$volume[0].DriveType -ne 'Fixed') { throw 'Setup paths must use one fixed local volume.' }
    $current = $volumeRoot
    $relative = $fullPath.Substring($volumeRoot.Length)
    foreach ($segment in $relative.Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $current = [System.IO.Path]::Combine($current, $segment)
        if (-not (Test-Path -LiteralPath $current)) { break }
        $item = Get-Item -Force -LiteralPath $current -ErrorAction Stop
        if (([int64]$item.Attributes -band [int64][System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Setup path contains a reparse point.' }
    }
}
function Assert-RegularFileOrMissing([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return }
    $item = Get-Item -Force -LiteralPath $Path -ErrorAction Stop
    if ($item.PSIsContainer -or ([int64]$item.Attributes -band [int64][System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'Managed executable destination is not a regular file.'
    }
}
function Expand-BlenderBoxFileSystemMask([int64]$Mask) {
    [int64]$expanded = $Mask
    if (($Mask -band 2147483648) -ne 0) { $expanded = $expanded -bor 0x00120089 }
    if (($Mask -band 1073741824) -ne 0) { $expanded = $expanded -bor 0x00120116 }
    if (($Mask -band 536870912) -ne 0) { $expanded = $expanded -bor 0x001200A0 }
    if (($Mask -band 268435456) -ne 0) { $expanded = $expanded -bor 0x001F01FF }
    return $expanded
}
function Assert-TrustedAncestors([string]$Path, [System.Security.Principal.SecurityIdentifier]$ControllerSid) {
    $trusted = @($ControllerSid.Value, 'S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $current = [System.IO.Path]::GetDirectoryName($fullPath.TrimEnd([char[]]@('\')))
    $volumeRoot = [System.IO.Path]::GetPathRoot($fullPath)
    [int64]$authorityMask = [int64][System.Security.AccessControl.FileSystemRights]::Delete -bor [int64][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [int64][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [int64][System.Security.AccessControl.FileSystemRights]::TakeOwnership
    while ($null -ne $current) {
        $acl = Get-Acl -LiteralPath $current -ErrorAction Stop
        $ownerSid = ([System.Security.Principal.NTAccount]::new([string]$acl.Owner)).Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($trusted -notcontains $ownerSid) { throw 'Setup path has an untrusted ancestor owner.' }
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        foreach ($rule in $rules) {
            if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
            if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
            if ($trusted -contains $rule.IdentityReference.Value) { continue }
            $ruleMask = Expand-BlenderBoxFileSystemMask ([int64]$rule.FileSystemRights)
            if (($ruleMask -band $authorityMask) -ne 0) { throw 'Setup path has an untrusted writable ancestor.' }
        }
        if ($current -ieq $volumeRoot) { return }
        $next = [System.IO.Path]::GetDirectoryName($current)
        if ($null -eq $next -or $next -ieq $current) { throw 'Setup path ancestor traversal failed.' }
        $current = $next
    }
    throw 'Setup path ancestor traversal failed.'
}
function Enter-BlenderBoxOperation([string]$Path) {
    $operation = [System.IO.File]::Open($Path, [System.IO.FileMode]::OpenOrCreate, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::ReadWrite)
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    while ($true) {
        try {
            $operation.Lock(0, 1)
            return $operation
        } catch [System.IO.IOException] {
            if ([DateTime]::UtcNow -ge $deadline) {
                $operation.Dispose()
                throw 'Timed out waiting for the Blender Box host operation lock.'
            }
            Start-Sleep -Milliseconds 100
        }
    }
}
function Set-BlenderBoxDirectoryPath([string]$Root, [string]$Directory, [System.Security.AccessControl.DirectorySecurity]$Acl) {
    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd([char[]]@('\'))
    $directoryFull = [System.IO.Path]::GetFullPath($Directory).TrimEnd([char[]]@('\'))
    if ($directoryFull -ieq $rootFull) { return }
    $prefix = $rootFull + '\'
    if (-not $directoryFull.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) { throw 'Managed directory escaped the work root.' }
    $current = $rootFull
    $relative = $directoryFull.Substring($prefix.Length)
    foreach ($segment in $relative.Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries)) {
        $current = [System.IO.Path]::Combine($current, $segment)
        if (-not (Test-Path -LiteralPath $current)) { New-Item -ItemType Directory -Path $current | Out-Null }
        Assert-NoReparsePath $current
        Set-Acl -LiteralPath $current -AclObject $Acl
    }
}
`

func prepareSetupScript(selected target.Target) string {
	header := fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$root = %s
$daemonPath = %s
$blenderPath = %s
$hostPath = %s
$hostDirectory = [System.IO.Path]::GetDirectoryName($hostPath)
$daemonDirectory = [System.IO.Path]::GetDirectoryName($daemonPath)
$interactiveUser = %s
$expectedControllerUser = %s
$lockPath = [System.IO.Path]::Combine($root, 'host-lock.json')
$operationPath = [System.IO.Path]::Combine($root, '.operation.lock')
`, powerShellLiteral(selected.WorkRoot), powerShellLiteral(selected.SessionBrokerExecutable), powerShellLiteral(selected.BlenderExecutable), powerShellLiteral(selected.HostExecutable), powerShellLiteral(selected.InteractiveUser), powerShellLiteral(selected.SSHUser))
	return header + setupOperationFunctions + `if (-not (Test-Path -LiteralPath $root -PathType Container)) { throw 'Declared work root is missing; provision blendersessiond inside it first.' }
Assert-NoReparsePath $root
Assert-NoReparsePath $hostDirectory
Assert-NoReparsePath $hostPath
Assert-RegularFileOrMissing $hostPath
Assert-NoReparsePath $daemonDirectory
Assert-NoReparsePath $daemonPath
Assert-NoReparsePath $blenderPath
Assert-NoReparsePath $operationPath
$expectedControllerSid = ([System.Security.Principal.NTAccount]::new($expectedControllerUser)).Translate([System.Security.Principal.SecurityIdentifier])
$authenticatedControllerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
if ($authenticatedControllerSid -ne $expectedControllerSid) { throw 'Configured SSH user does not match the authenticated controller SID.' }
$operation = Enter-BlenderBoxOperation $operationPath
try {
    Assert-NoReparsePath $root
    Assert-NoReparsePath $hostDirectory
    Assert-NoReparsePath $hostPath
    Assert-RegularFileOrMissing $hostPath
    Assert-NoReparsePath $daemonDirectory
    Assert-NoReparsePath $daemonPath
    Assert-NoReparsePath $blenderPath
    Assert-NoReparsePath $operationPath
    if (Test-Path -LiteralPath $lockPath) { throw 'Cannot apply setup while a Host Lock exists.' }
    if (-not (Test-Path -LiteralPath $daemonPath -PathType Leaf)) { throw 'Declared blendersessiond executable is missing.' }
    if (-not (Test-Path -LiteralPath $blenderPath -PathType Leaf)) { throw 'Declared Blender executable is missing.' }
    $interactiveSid = ([System.Security.Principal.NTAccount]::new($interactiveUser)).Translate([System.Security.Principal.SecurityIdentifier])
    $controllerSid = $authenticatedControllerSid
    Assert-TrustedAncestors $root $controllerSid
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $objectInheritance = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $inheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $rootAcl = [System.Security.AccessControl.DirectorySecurity]::new()
    $rootAcl.SetAccessRuleProtection($true, $false)
    $rootAcl.SetOwner($controllerSid)
    $rootAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    if ($controllerSid -ne $interactiveSid) {
        $rootRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::WriteData
        $rootAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, $rootRights, [System.Security.AccessControl.InheritanceFlags]::None, $none, $allow))
        $rootAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, [System.Security.AccessControl.FileSystemRights]::Modify, $objectInheritance, $inheritOnly, $allow))
    }
    $rootAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    $rootAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    Set-Acl -LiteralPath $root -AclObject $rootAcl

    $executableDirectoryAcl = [System.Security.AccessControl.DirectorySecurity]::new()
    $executableDirectoryAcl.SetAccessRuleProtection($true, $false)
    $executableDirectoryAcl.SetOwner($controllerSid)
    $executableDirectoryAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    if ($controllerSid -ne $interactiveSid) { $executableDirectoryAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $inherit, $none, $allow)) }
    $executableDirectoryAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    $executableDirectoryAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    Set-BlenderBoxDirectoryPath $root $hostDirectory $executableDirectoryAcl
    Set-BlenderBoxDirectoryPath $root $daemonDirectory $executableDirectoryAcl

    $stateFileAcl = [System.Security.AccessControl.FileSecurity]::new()
    $stateFileAcl.SetAccessRuleProtection($true, $false)
    $stateFileAcl.SetOwner($controllerSid)
    $stateFileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::None, $none, $allow))
    if ($controllerSid -ne $interactiveSid) { $stateFileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, [System.Security.AccessControl.FileSystemRights]::Modify, [System.Security.AccessControl.InheritanceFlags]::None, $none, $allow)) }
    $stateFileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::None, $none, $allow))
    $stateFileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::None, $none, $allow))
    Set-Acl -LiteralPath $operationPath -AclObject $stateFileAcl

    $fileAcl = [System.Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetAccessRuleProtection($true, $false)
    $fileAcl.SetOwner($controllerSid)
    $fileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::None, $none, $allow))
    if ($controllerSid -ne $interactiveSid) { $fileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, [System.Security.AccessControl.InheritanceFlags]::None, $none, $allow)) }
    $fileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::None, $none, $allow))
    $fileAcl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]::None, $none, $allow))
    Set-Acl -LiteralPath $daemonPath -AclObject $fileAcl
    if (Test-Path -LiteralPath $hostPath -PathType Leaf) { Set-Acl -LiteralPath $hostPath -AclObject $fileAcl }
} finally {
    try { $operation.Unlock(0, 1) } finally { $operation.Dispose() }
}`
}

func setupScript(selected target.Target, plan SetupResult, stagedBinary string) string {
	taskArguments := fmt.Sprintf(`host run-request --state-root "%s"`, selected.WorkRoot)
	return fmt.Sprintf(`$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest
$root = %s
$hostPath = %s
$daemonPath = %s
$blenderPath = %s
$hostDirectory = [System.IO.Path]::GetDirectoryName($hostPath)
$daemonDirectory = [System.IO.Path]::GetDirectoryName($daemonPath)
$interactiveUser = %s
$expectedControllerUser = %s
$taskName = %s
$expectedArguments = %s
$expectedSize = [int64]%d
$expectedHash = %s
$stagedBinary = %s
$temporary = $hostPath + '.setup-' + [Guid]::NewGuid().ToString('N')
$backup = $hostPath + '.setup-backup-' + [Guid]::NewGuid().ToString('N')
$lockPath = [System.IO.Path]::Combine($root, 'host-lock.json')
$operationPath = [System.IO.Path]::Combine($root, '.operation.lock')
%s
function New-BlenderBoxRootAcl {
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $objectInheritance = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $inheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($controllerSid)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    if ($controllerSid -ne $interactiveSid) {
        $rootRights = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute -bor [System.Security.AccessControl.FileSystemRights]::WriteData
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, $rootRights, [System.Security.AccessControl.InheritanceFlags]::None, $none, $allow))
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, [System.Security.AccessControl.FileSystemRights]::Modify, $objectInheritance, $inheritOnly, $allow))
    }
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    return $acl
}
function New-BlenderBoxStateDirectoryAcl {
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($controllerSid)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    if ($controllerSid -ne $interactiveSid) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, [System.Security.AccessControl.FileSystemRights]::Modify, $inherit, $none, $allow))
    }
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    return $acl
}
function New-BlenderBoxExecutableDirectoryAcl {
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $none = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl = [System.Security.AccessControl.DirectorySecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($controllerSid)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    if ($controllerSid -ne $interactiveSid) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $inherit, $none, $allow))
    }
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, $none, $allow))
    return $acl
}
function New-BlenderBoxStateFileAcl {
    $noneInheritance = [System.Security.AccessControl.InheritanceFlags]::None
    $nonePropagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($controllerSid)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $noneInheritance, $nonePropagation, $allow))
    if ($controllerSid -ne $interactiveSid) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, [System.Security.AccessControl.FileSystemRights]::Modify, $noneInheritance, $nonePropagation, $allow))
    }
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, $noneInheritance, $nonePropagation, $allow))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, $noneInheritance, $nonePropagation, $allow))
    return $acl
}
function Set-BlenderBoxStateTree([string]$path) {
    if (-not (Test-Path -LiteralPath $path)) { return }
    $rootItem = Get-Item -Force -LiteralPath $path
    if (-not $rootItem.PSIsContainer) { throw 'Managed state path is not a directory.' }
    $pending = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
    $pending.Push($rootItem)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        if (([int64]$directory.Attributes -band [int64][System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Managed state contains a reparse point.' }
        Set-Acl -LiteralPath $directory.FullName -AclObject (New-BlenderBoxStateDirectoryAcl)
        foreach ($child in $directory.EnumerateFileSystemInfos()) {
            if (([int64]$child.Attributes -band [int64][System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Managed state contains a reparse point.' }
            if (($child.Attributes -band [System.IO.FileAttributes]::Directory) -ne 0) { $pending.Push($child) }
            else { Set-Acl -LiteralPath $child.FullName -AclObject (New-BlenderBoxStateFileAcl) }
        }
    }
}
function New-BlenderBoxFileAcl {
    $noneInheritance = [System.Security.AccessControl.InheritanceFlags]::None
    $nonePropagation = [System.Security.AccessControl.PropagationFlags]::None
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($controllerSid)
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($controllerSid, [System.Security.AccessControl.FileSystemRights]::FullControl, $noneInheritance, $nonePropagation, $allow))
    if ($controllerSid -ne $interactiveSid) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($interactiveSid, [System.Security.AccessControl.FileSystemRights]::ReadAndExecute, $noneInheritance, $nonePropagation, $allow))
    }
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'), [System.Security.AccessControl.FileSystemRights]::FullControl, $noneInheritance, $nonePropagation, $allow))
    $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new([System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'), [System.Security.AccessControl.FileSystemRights]::FullControl, $noneInheritance, $nonePropagation, $allow))
    return $acl
}
$expectedControllerSid = ([System.Security.Principal.NTAccount]::new($expectedControllerUser)).Translate([System.Security.Principal.SecurityIdentifier])
$authenticatedControllerSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
if ($authenticatedControllerSid -ne $expectedControllerSid) { throw 'Configured SSH user does not match the authenticated controller SID.' }
$operation = $null
try {
    Assert-NoReparsePath $root
    Assert-NoReparsePath $hostDirectory
    Assert-NoReparsePath $hostPath
    Assert-RegularFileOrMissing $hostPath
    Assert-NoReparsePath $daemonDirectory
    Assert-NoReparsePath $daemonPath
    Assert-NoReparsePath $blenderPath
    Assert-NoReparsePath $stagedBinary
    Assert-NoReparsePath $operationPath
    $operation = Enter-BlenderBoxOperation $operationPath
    Assert-NoReparsePath $root
    Assert-NoReparsePath $hostDirectory
    Assert-NoReparsePath $hostPath
    Assert-RegularFileOrMissing $hostPath
    Assert-NoReparsePath $daemonDirectory
    Assert-NoReparsePath $daemonPath
    Assert-NoReparsePath $blenderPath
    Assert-NoReparsePath $stagedBinary
    Assert-NoReparsePath $operationPath
    if (Test-Path -LiteralPath $lockPath) { throw 'Cannot apply setup while a Host Lock exists.' }
    if (-not (Test-Path -LiteralPath $daemonPath -PathType Leaf)) { throw 'Declared blendersessiond executable is missing.' }
    if (-not (Test-Path -LiteralPath $blenderPath -PathType Leaf)) { throw 'Declared Blender executable is missing.' }
    $interactiveSid = ([System.Security.Principal.NTAccount]::new($interactiveUser)).Translate([System.Security.Principal.SecurityIdentifier])
    $controllerSid = $authenticatedControllerSid
    Assert-TrustedAncestors $root $controllerSid
    Set-Acl -LiteralPath $root -AclObject (New-BlenderBoxRootAcl)
    $runsPath = [System.IO.Path]::Combine($root, 'runs')
    $receiptsPath = [System.IO.Path]::Combine($root, 'receipts')
    Set-BlenderBoxDirectoryPath $root $runsPath (New-BlenderBoxStateDirectoryAcl)
    Set-BlenderBoxDirectoryPath $root $receiptsPath (New-BlenderBoxStateDirectoryAcl)
    Set-BlenderBoxStateTree $runsPath
    Set-BlenderBoxStateTree $receiptsPath
    Set-Acl -LiteralPath $operationPath -AclObject (New-BlenderBoxStateFileAcl)
    Set-BlenderBoxDirectoryPath $root $hostDirectory (New-BlenderBoxExecutableDirectoryAcl)
    Set-BlenderBoxDirectoryPath $root $daemonDirectory (New-BlenderBoxExecutableDirectoryAcl)
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
    $taskSddl = 'O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;GA;;;' + $controllerSid.Value + ')'
    $registeredTask.SetSecurityDescriptor($taskSddl, 0)
    [ordered]@{schema_version=1; status='applied'; applied=$true; host_size=$expectedSize; host_sha256=$expectedHash} | ConvertTo-Json -Compress
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -Force -LiteralPath $temporary }
    if (Test-Path -LiteralPath $backup) { Remove-Item -Force -LiteralPath $backup }
    if (Test-Path -LiteralPath $stagedBinary) { Remove-Item -Force -LiteralPath $stagedBinary }
    if ($null -ne $operation) { try { $operation.Unlock(0, 1) } finally { $operation.Dispose() } }
}
`, powerShellLiteral(selected.WorkRoot), powerShellLiteral(selected.HostExecutable), powerShellLiteral(selected.SessionBrokerExecutable), powerShellLiteral(selected.BlenderExecutable), powerShellLiteral(selected.InteractiveUser), powerShellLiteral(selected.SSHUser), powerShellLiteral(selected.TaskName), powerShellLiteral(taskArguments), plan.HostSize, powerShellLiteral(plan.HostSHA256), powerShellLiteral(stagedBinary), setupOperationFunctions)
}
