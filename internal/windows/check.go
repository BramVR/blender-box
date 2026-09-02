package windows

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf16"

	"github.com/BramVR/blender-box/internal/target"
)

const checkTimeout = 2 * time.Minute

const checkScript = `$config = $configText | ConvertFrom-Json
$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check([string]$Id, [bool]$Passed, [bool]$Required, $Actual, $Expected, [string]$Message) {
    $checks.Add([ordered]@{id=$Id; passed=$Passed; required=$Required; actual=$Actual; expected=$Expected; message=$Message})
}
function Resolve-Sid([string]$Identity) {
    if ([string]::IsNullOrWhiteSpace($Identity)) { return $null }
    try {
        return ([System.Security.Principal.NTAccount]::new($Identity)).Translate([System.Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
}
function Normalize-Path([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try { return [System.IO.Path]::GetFullPath($Path) } catch { return $null }
}
function Expand-FileSystemMask([int64]$Mask) {
    [int64]$genericRead = 2147483648
    [int64]$genericWrite = 1073741824
    [int64]$genericExecute = 536870912
    [int64]$genericAll = 268435456
    [int64]$expanded = $Mask
    if (($Mask -band $genericRead) -ne 0) { $expanded = $expanded -bor 0x00120089 }
    if (($Mask -band $genericWrite) -ne 0) { $expanded = $expanded -bor 0x00120116 }
    if (($Mask -band $genericExecute) -ne 0) { $expanded = $expanded -bor 0x001200A0 }
    if (($Mask -band $genericAll) -ne 0) { $expanded = $expanded -bor 0x001F01FF }
    return $expanded
}
function Test-ConservativePathAccess([string]$Path, [string]$PrincipalSid, [System.Security.AccessControl.FileSystemRights]$RequiredRights, [bool]$RequireDirectAllow) {
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return $false }
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    } catch {
        return $false
    }
    $allowedSids = if ($RequireDirectAllow) { @($PrincipalSid) } else { @($PrincipalSid, 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545') }
    [int64]$allowMask = 0
    [int64]$denyMask = 0
    $requiredMask = [int64]$RequiredRights
    foreach ($rule in $rules) {
		if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        $ruleMask = Expand-FileSystemMask ([int64]$rule.FileSystemRights)
        # This process does not own the interactive task token. Treat every deny as applicable so inspection can fail closed instead of guessing group membership.
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and ($ruleMask -band $requiredMask) -ne 0) { $denyMask = $denyMask -bor $ruleMask }
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and $allowedSids -contains $rule.IdentityReference.Value) { $allowMask = $allowMask -bor $ruleMask }
    }
    return ($denyMask -band $requiredMask) -eq 0 -and ($allowMask -band $requiredMask) -eq $requiredMask
}
function Test-TrustedWriters([string]$Path, [string]$PrincipalSid, [string]$ControllerSid, [bool]$ProtectChildren, [bool]$AllowControllerOwner) {
    if (-not (Test-Path -LiteralPath $Path -ErrorAction SilentlyContinue)) { return $false }
    $trustedOwners = @(
        $PrincipalSid,
        'S-1-5-18',
        'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )
    if ($AllowControllerOwner) { $trustedOwners += $ControllerSid }
    $trustedWriters = @($trustedOwners) + @($ControllerSid)
    if ($ProtectChildren) { $trustedWriters += 'S-1-3-0' }
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return $false }
    $ownerSid = Resolve-Sid ([string]$acl.Owner)
    if ($trustedOwners -notcontains $ownerSid) { return $false }
    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $writeMask = [int64][System.Security.AccessControl.FileSystemRights]::Write -bor [int64][System.Security.AccessControl.FileSystemRights]::Delete -bor [int64][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [int64][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [int64][System.Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $rules) {
        $inheritOnly = ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0
        if ($inheritOnly -and -not $ProtectChildren) { continue }
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($trustedWriters -contains $rule.IdentityReference.Value) { continue }
        $ruleMask = Expand-FileSystemMask ([int64]$rule.FileSystemRights)
        if (($ruleMask -band $writeMask) -ne 0) { return $false }
    }
    return $true
}
function Test-TrustedAncestor([string]$Path, [string]$PrincipalSid, [string]$ControllerSid) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container -ErrorAction SilentlyContinue)) { return $false }
    $trustedWriters = @(
        $PrincipalSid,
        'S-1-5-18',
        'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464',
        $ControllerSid
    )
    try { $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop } catch { return $false }
    $ownerSid = Resolve-Sid ([string]$acl.Owner)
    if ($trustedWriters -notcontains $ownerSid) { return $false }
    $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $deleteChild = [int64][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
    $authorityMask = [int64][System.Security.AccessControl.FileSystemRights]::Delete -bor $deleteChild -bor [int64][System.Security.AccessControl.FileSystemRights]::ChangePermissions -bor [int64][System.Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $rules) {
        if (($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) { continue }
        if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if ($trustedWriters -contains $rule.IdentityReference.Value) { continue }
        $ruleMask = Expand-FileSystemMask ([int64]$rule.FileSystemRights)
        if (($ruleMask -band $authorityMask) -ne 0) { return $false }
    }
    return $true
}
function Test-TrustedTaskAuthorities([string]$Sddl, [string]$ControllerSid) {
    if ([string]::IsNullOrWhiteSpace($Sddl)) { return $false }
    try {
        $descriptor = [System.Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
    } catch {
        return $false
    }
    $trustedManagers = @(
        'S-1-5-18',
        'S-1-5-32-544',
        'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'
    )
    if ($null -eq $descriptor.Owner -or $trustedManagers -notcontains $descriptor.Owner.Value -or $null -eq $descriptor.DiscretionaryAcl) { return $false }
    [int64]$genericAll = 0x10000000
    [int64]$genericWrite = 0x40000000
    [int64]$genericExecute = 0x20000000
    [int64]$taskWrite = 0x00000116
    [int64]$taskExecute = 0x00000020
    [int64]$taskWriteMask = $genericAll -bor $genericWrite -bor 0x00010000 -bor 0x00040000 -bor 0x00080000 -bor $taskWrite
    [int64]$taskExecuteMask = $genericAll -bor $genericExecute -bor $taskExecute
    $controllerCanExecute = $false
    $controllerCanManage = $false
    foreach ($ace in $descriptor.DiscretionaryAcl) {
        if (([int]$ace.AceFlags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0) { continue }
        if ($null -eq $ace.SecurityIdentifier) { continue }
        $aceMask = [int64]$ace.AccessMask
        $authorityMask = $taskWriteMask -bor $taskExecuteMask
        if (($aceMask -band $authorityMask) -ne 0 -and ($ace -isnot [System.Security.AccessControl.CommonAce] -or $ace.IsCallback)) { return $false }
        if ($ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessDenied -and ($aceMask -band $taskExecuteMask) -ne 0) { return $false }
        if ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
        if ($trustedManagers -contains $ace.SecurityIdentifier.Value) { continue }
        if ($ace.SecurityIdentifier.Value -eq $ControllerSid) {
            if (($aceMask -band $genericAll) -eq $genericAll) { $controllerCanManage = $true }
            if (($aceMask -band $taskExecuteMask) -ne 0) { $controllerCanExecute = $true }
            continue
        }
        if (($aceMask -band ($taskWriteMask -bor $taskExecuteMask)) -ne 0) { return $false }
    }
    return $controllerCanExecute -and $controllerCanManage
}
function Test-LocalVolumeRoot([string]$Root) {
    if ($Root -notmatch '^[A-Za-z]:\\$') { return $false }
    try {
        $volumes = @(Get-Volume -DriveLetter $Root.Substring(0, 1) -ErrorAction Stop)
    } catch {
        return $false
    }
    return $volumes.Count -eq 1 -and [string]$volumes[0].DriveType -eq 'Fixed'
}
function Test-NoReparsePoints([string]$Path) {
    $current = Normalize-Path $Path
    if ($null -eq $current) { return $false }
    $root = [System.IO.Path]::GetPathRoot($current)
    if (-not (Test-LocalVolumeRoot $root)) { return $false }
    while ($null -ne $current) {
        try { $item = Get-Item -Force -LiteralPath $current -ErrorAction Stop } catch { return $false }
        if (([int64]$item.Attributes -band [int64][System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        if ($current -ieq $root) { return $true }
        $next = [System.IO.Path]::GetDirectoryName($current)
        if ($null -eq $next -or $next -ieq $current) { return $false }
        $current = $next
    }
    return $false
}
function Test-SafePath([string]$Path, [string]$PrincipalSid, [string]$ControllerSid, [System.Security.AccessControl.FileSystemRights]$RequiredRights, [bool]$RequireDirectAllow, [bool]$RequireSealedParent, [bool]$ProtectChildren, [bool]$AllowControllerOwner) {
    if (-not (Test-NoReparsePoints $Path)) { return $false }
    if (-not (Test-ConservativePathAccess $Path $PrincipalSid $RequiredRights $RequireDirectAllow)) { return $false }
    if (-not (Test-TrustedWriters $Path $PrincipalSid $ControllerSid $ProtectChildren $AllowControllerOwner)) { return $false }
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    if ($null -eq $parent) { return $false }
    if ($RequireSealedParent) {
        if (-not (Test-TrustedWriters $parent $PrincipalSid $ControllerSid $true $AllowControllerOwner)) { return $false }
    } elseif (-not (Test-TrustedAncestor $parent $PrincipalSid $ControllerSid)) {
        return $false
    }
    $root = [System.IO.Path]::GetPathRoot($Path)
    if ($parent -ieq $root) { return $true }
    $ancestor = [System.IO.Path]::GetDirectoryName($parent)
    while ($null -ne $ancestor) {
        if (-not (Test-TrustedAncestor $ancestor $PrincipalSid $ControllerSid)) { return $false }
        if ($ancestor -ieq $root) { break }
        $next = [System.IO.Path]::GetDirectoryName($ancestor)
        if ($null -eq $next -or $next -ieq $ancestor) { return $false }
        $ancestor = $next
    }
    return $null -ne $ancestor -and $ancestor -ieq $root
}
function Test-SafeStateTree([string]$Path, [string]$PrincipalSid, [string]$ControllerSid) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { return $false }
    try { $rootItem = Get-Item -Force -LiteralPath $Path -ErrorAction Stop } catch { return $false }
    if (-not $rootItem.PSIsContainer) { return $false }
    $pending = [System.Collections.Generic.Stack[System.IO.DirectoryInfo]]::new()
    $pending.Push($rootItem)
    $modify = [System.Security.AccessControl.FileSystemRights]::Modify
    $fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        $isRoot = $directory.FullName -ieq $rootItem.FullName
        if (([int64]$directory.Attributes -band [int64][System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
        if (-not (Test-SafePath $directory.FullName $PrincipalSid $ControllerSid $modify $false $true $true $true)) { return $false }
        if (-not (Test-ConservativePathAccess $directory.FullName $ControllerSid $fullControl $isRoot)) { return $false }
        try { $children = @($directory.EnumerateFileSystemInfos()) } catch { return $false }
        foreach ($child in $children) {
            if (([int64]$child.Attributes -band [int64][System.IO.FileAttributes]::ReparsePoint) -ne 0) { return $false }
            $isDirectory = ([int64]$child.Attributes -band [int64][System.IO.FileAttributes]::Directory) -ne 0
            if ($isDirectory) {
                $pending.Push($child)
            } elseif (-not (Test-SafePath $child.FullName $PrincipalSid $ControllerSid $modify $false $true $false $true)) {
                return $false
            } elseif (-not (Test-ConservativePathAccess $child.FullName $ControllerSid $fullControl $false)) {
                return $false
            }
        }
    }
    return $true
}
function Test-RootStateFileInheritance([string]$Path, [string]$PrincipalSid, [string]$ControllerSid) {
    try {
        $acl = Get-Acl -LiteralPath $Path -ErrorAction Stop
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    } catch {
        return $false
    }
    $objectInheritance = [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $inheritOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly
    $modify = [int64][System.Security.AccessControl.FileSystemRights]::Modify
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -ne $PrincipalSid -or $rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }
        if (($rule.InheritanceFlags -band $objectInheritance) -eq 0) { continue }
        if ($PrincipalSid -ne $ControllerSid -and ($rule.PropagationFlags -band $inheritOnly) -eq 0) { continue }
        $ruleMask = Expand-FileSystemMask ([int64]$rule.FileSystemRights)
        if (($ruleMask -band $modify) -eq $modify) { return $true }
    }
    return $false
}
$os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
Add-Check 'host.windows' ($null -ne $os) $true $os.Caption 'Windows' 'Windows host detected.'
$computer = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
$consoleUser = [string]$computer.UserName
$expectedUser = [string]$config.interactive_user
$expectedSid = Resolve-Sid $expectedUser
$consoleSid = Resolve-Sid $consoleUser
Add-Check 'host.console-user' ($null -ne $expectedSid -and $consoleSid -eq $expectedSid) $true ([ordered]@{identity=$consoleUser; sid=$consoleSid}) ([ordered]@{identity=$expectedUser; sid=$expectedSid}) 'Configured interactive user SID must own the console session.'
$sshIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$sshUser = [string]$sshIdentity.Name
$sshSid = [string]$sshIdentity.User.Value
$expectedSSHUser = [string]$config.ssh_user
$expectedSSHSid = Resolve-Sid $expectedSSHUser
Add-Check 'host.ssh-user' ($null -ne $expectedSSHSid -and $sshSid -eq $expectedSSHSid) $true ([ordered]@{identity=$sshUser; sid=$sshSid}) ([ordered]@{identity=$expectedSSHUser; sid=$expectedSSHSid}) 'The SSH process SID must match the declared controller identity.'
$enableLUA = Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -ErrorAction SilentlyContinue
$builtInAdministrator = $null -ne $expectedSid -and $expectedSid -match '-500$'
Add-Check 'host.limited-token-policy' ([int]$enableLUA -eq 1 -and -not $builtInAdministrator) $true ([ordered]@{enable_lua=[int]$enableLUA; built_in_administrator=$builtInAdministrator}) ([ordered]@{enable_lua=1; built_in_administrator=$false}) 'UAC filtering must be enabled and the task principal must not be a RID-500 Administrator account.'
$blenderPath = [string]$config.blender_executable
$daemonPath = [string]$config.session_broker_executable
$hostPath = [string]$config.host_executable
$readExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
$modify = [System.Security.AccessControl.FileSystemRights]::Modify
$fullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
$rootAccess = $readExecute -bor [System.Security.AccessControl.FileSystemRights]::WriteData
$blenderOK = Test-Path -LiteralPath $blenderPath -PathType Leaf -ErrorAction SilentlyContinue
$daemonOK = Test-Path -LiteralPath $daemonPath -PathType Leaf -ErrorAction SilentlyContinue
$hostOK = Test-Path -LiteralPath $hostPath -PathType Leaf -ErrorAction SilentlyContinue
Add-Check 'blender.executable' ($blenderOK -and (Test-SafePath $blenderPath $expectedSid $sshSid $readExecute $false $true $false $false)) $true $blenderPath 'existing executable with safe readers, owner, and writers' 'The configured Blender executable and parent must reject untrusted writers.'
Add-Check 'daemon.executable' ($daemonOK -and (Test-SafePath $daemonPath $expectedSid $sshSid $readExecute $true $true $false $true) -and (Test-ConservativePathAccess $daemonPath $sshSid $fullControl $true) -and (Test-ConservativePathAccess ([System.IO.Path]::GetDirectoryName($daemonPath)) $sshSid $fullControl $true)) $true $daemonPath 'existing executable with task execution and controller update authority' 'The staged session broker and parent must carry the setup ACL.'
Add-Check 'host.executable' ($hostOK -and (Test-SafePath $hostPath $expectedSid $sshSid $readExecute $true $true $false $true) -and (Test-ConservativePathAccess $hostPath $sshSid $fullControl $true) -and (Test-ConservativePathAccess ([System.IO.Path]::GetDirectoryName($hostPath)) $sshSid $fullControl $true)) $true $hostPath 'existing executable with task execution and controller update authority' 'The staged Blender Box host binary and parent must carry the setup ACL.'
$rootExists = Test-Path -LiteralPath ([string]$config.work_root) -PathType Container -ErrorAction SilentlyContinue
Add-Check 'work-root.access' ($rootExists -and (Test-SafePath ([string]$config.work_root) $expectedSid $sshSid $rootAccess $true $false $true $true) -and (Test-ConservativePathAccess ([string]$config.work_root) $sshSid $fullControl $true) -and (Test-RootStateFileInheritance ([string]$config.work_root) $expectedSid $sshSid)) $true ([string]$config.work_root) 'controller-owned root with controller update authority and inherited task state-file access' 'The operator-managed work root must separate task file creation from executable-directory replacement authority.'
$stateTreeOK = $rootExists -and (Test-SafeStateTree ([System.IO.Path]::Combine([string]$config.work_root, 'runs')) $expectedSid $sshSid) -and (Test-SafeStateTree ([System.IO.Path]::Combine([string]$config.work_root, 'receipts')) $expectedSid $sshSid)
Add-Check 'work-root.state-tree' $stateTreeOK $true $stateTreeOK $true 'Existing Run and receipt trees must contain no reparse points and only declared writers.'
$task = Get-ScheduledTask -TaskPath '\' -TaskName ([string]$config.task_name) -ErrorAction SilentlyContinue
$taskActual = $null
$taskOK = $false
if ($null -ne $task) {
    $actions = @($task.Actions)
    $triggers = @($task.Triggers | Where-Object { $_ })
    $taskSid = Resolve-Sid ([string]$task.Principal.UserId)
    $requiredPrivileges = @($task.Principal.RequiredPrivilege | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    $taskActual = [ordered]@{
        user = [string]$task.Principal.UserId
        sid = $taskSid
        logon_type = [string]$task.Principal.LogonType
        run_level = [string]$task.Principal.RunLevel
        required_privileges = $requiredPrivileges
        action_count = $actions.Count
        trigger_count = $triggers.Count
        multiple_instances = [string]$task.Settings.MultipleInstances
        execution_time_limit = [string]$task.Settings.ExecutionTimeLimit
        allow_demand_start = [bool]$task.Settings.AllowDemandStart
        allow_hard_terminate = [bool]$task.Settings.AllowHardTerminate
        disallow_start_if_on_batteries = [bool]$task.Settings.DisallowStartIfOnBatteries
        stop_if_going_on_batteries = [bool]$task.Settings.StopIfGoingOnBatteries
        run_only_if_idle = [bool]$task.Settings.RunOnlyIfIdle
        run_only_if_network_available = [bool]$task.Settings.RunOnlyIfNetworkAvailable
        restart_count = [int]$task.Settings.RestartCount
        restart_interval = [string]$task.Settings.RestartInterval
        volatile = [bool]$task.Settings.Volatile
        enabled = [bool]$task.Settings.Enabled
        execute = $(if ($actions.Count -eq 1) {[string]$actions[0].Execute} else {$null})
        arguments = $(if ($actions.Count -eq 1) {[string]$actions[0].Arguments} else {$null})
        working_directory = $(if ($actions.Count -eq 1) {[string]$actions[0].WorkingDirectory} else {$null})
    }
    $expectedWorkingDirectory = [System.IO.Path]::GetDirectoryName($hostPath)
    $actualExecute = $(if ($actions.Count -eq 1) {Normalize-Path ([string]$actions[0].Execute)} else {$null})
    $actualWorkingDirectory = $(if ($actions.Count -eq 1) {Normalize-Path ([string]$actions[0].WorkingDirectory)} else {$null})
    $expectedExecute = Normalize-Path $hostPath
    $expectedWorkingDirectory = Normalize-Path $expectedWorkingDirectory
    $taskSddl = $null
    try {
        $taskService = New-Object -ComObject 'Schedule.Service'
        $taskService.Connect()
        $registeredTask = $taskService.GetFolder('\').GetTask([string]$config.task_name)
        $taskSddl = [string]$registeredTask.GetSecurityDescriptor(7)
    } catch {
        $taskSddl = $null
    }
    $taskAclOK = Test-TrustedTaskAuthorities $taskSddl $expectedSSHSid
    $taskActual['task_acl_trusted'] = $taskAclOK
    $taskSettingsOK = [string]$task.Settings.MultipleInstances -eq 'IgnoreNew' -and [string]$task.Settings.ExecutionTimeLimit -in @('PT0S', '00:00:00', '0') -and [bool]$task.Settings.AllowDemandStart -and [bool]$task.Settings.AllowHardTerminate -and -not ([bool]$task.Settings.DisallowStartIfOnBatteries) -and -not ([bool]$task.Settings.StopIfGoingOnBatteries) -and -not ([bool]$task.Settings.RunOnlyIfIdle) -and -not ([bool]$task.Settings.RunOnlyIfNetworkAvailable) -and [int]$task.Settings.RestartCount -eq 0 -and -not ([bool]$task.Settings.Volatile) -and [bool]$task.Settings.Enabled
    $taskOK = $null -ne $expectedSid -and $taskSid -eq $expectedSid -and [string]$task.Principal.LogonType -eq 'Interactive' -and [string]$task.Principal.RunLevel -eq 'Limited' -and $requiredPrivileges.Count -eq 0 -and $actions.Count -eq 1 -and $triggers.Count -eq 0 -and $taskSettingsOK -and $null -ne $actualExecute -and $actualExecute -ieq $expectedExecute -and [string]$actions[0].Arguments -ceq [string]$config.expected_task_arguments -and $null -ne $actualWorkingDirectory -and $actualWorkingDirectory -ieq $expectedWorkingDirectory -and $taskAclOK
}
Add-Check 'task.interactive' $taskOK $true $taskActual ([ordered]@{user=$expectedUser; sid=$expectedSid; controller_sid=$expectedSSHSid; execute=$hostPath; arguments=[string]$config.expected_task_arguments; working_directory=[System.IO.Path]::GetDirectoryName($hostPath); logon_type='Interactive'; run_level='Limited'; required_privileges=@(); triggers=0; multiple_instances='IgnoreNew'; execution_time_limit='PT0S'; allow_demand_start=$true; allow_hard_terminate=$true; disallow_start_if_on_batteries=$false; stop_if_going_on_batteries=$false; run_only_if_idle=$false; run_only_if_network_available=$false; restart_count=0; volatile=$false}) 'The static task must match the complete Blender Box action, principal, and controller contract.'
$requiredFailed = @($checks | Where-Object { $_.required -and -not $_.passed }).Count
[ordered]@{schema_version=1; status=$(if ($requiredFailed -eq 0) {'pass'} else {'fail'}); checks=$checks} | ConvertTo-Json -Compress -Depth 8
`

type SSH interface {
	Run(context.Context, string, []string, []byte) ([]byte, error)
}

type SetupSSH interface {
	SSH
	Upload(context.Context, string, string, string) error
}

type CheckResult struct {
	SchemaVersion int             `json:"schema_version"`
	Status        string          `json:"status"`
	Checks        []CheckEvidence `json:"checks"`
}

type CheckEvidence struct {
	ID       string          `json:"id"`
	Passed   bool            `json:"passed"`
	Required bool            `json:"required"`
	Actual   json.RawMessage `json:"actual,omitempty"`
	Expected json.RawMessage `json:"expected,omitempty"`
	Message  string          `json:"message,omitempty"`
}

func Check(ctx context.Context, ssh SSH, selected target.Target) (CheckResult, error) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()

	input, err := json.Marshal(struct {
		target.Target
		ExpectedTaskArguments string `json:"expected_task_arguments"`
	}{
		Target:                selected,
		ExpectedTaskArguments: fmt.Sprintf(`host run-request --state-root "%s"`, selected.WorkRoot),
	})
	if err != nil {
		return CheckResult{}, fmt.Errorf("encode target check input: %w", err)
	}
	scriptInput := fmt.Sprintf(
		"$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n$configText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%s'))\n%s",
		base64.StdEncoding.EncodeToString(input),
		checkScript,
	)
	arguments := []string{
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-EncodedCommand",
		encodePowerShell("[Console]::In.ReadToEnd() | Invoke-Expression"),
	}
	output, err := ssh.Run(ctx, selected.SSHAlias, arguments, []byte(scriptInput))
	if err != nil {
		return CheckResult{}, fmt.Errorf("inspect Windows host: %w", err)
	}
	var wire struct {
		SchemaVersion int             `json:"schema_version"`
		Status        string          `json:"status"`
		Checks        json.RawMessage `json:"checks"`
	}
	if err := json.Unmarshal(output, &wire); err != nil {
		return CheckResult{}, fmt.Errorf("parse Windows check result: %w", err)
	}
	var checks []CheckEvidence
	if err := json.Unmarshal(wire.Checks, &checks); err != nil {
		return CheckResult{}, fmt.Errorf("Windows check returned an invalid contract: checks must be an array")
	}
	result := CheckResult{SchemaVersion: wire.SchemaVersion, Status: wire.Status, Checks: checks}
	if !validCheckResult(result) {
		return CheckResult{}, fmt.Errorf("Windows check returned an invalid contract")
	}
	return result, nil
}

func validCheckResult(result CheckResult) bool {
	requiredIDs := map[string]bool{
		"host.windows":              false,
		"host.console-user":         false,
		"host.ssh-user":             false,
		"host.limited-token-policy": false,
		"blender.executable":        false,
		"daemon.executable":         false,
		"host.executable":           false,
		"work-root.access":          false,
		"work-root.state-tree":      false,
		"task.interactive":          false,
	}
	if result.SchemaVersion != 1 || (result.Status != "pass" && result.Status != "fail") || len(result.Checks) == 0 {
		return false
	}
	seen := make(map[string]struct{}, len(result.Checks))
	requiredFailed := false
	for _, check := range result.Checks {
		if check.ID == "" {
			return false
		}
		if _, duplicate := seen[check.ID]; duplicate {
			return false
		}
		seen[check.ID] = struct{}{}
		if _, required := requiredIDs[check.ID]; required {
			if !check.Required {
				return false
			}
			requiredIDs[check.ID] = true
		}
		if check.Required && !check.Passed {
			requiredFailed = true
		}
	}
	for _, present := range requiredIDs {
		if !present {
			return false
		}
	}
	return (result.Status == "fail") == requiredFailed
}

func encodePowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	bytes := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(bytes[index*2:], unit)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}
