package windows

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"unicode/utf16"

	"github.com/BramVR/blender-box/internal/target"
)

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
function Test-ConservativePathAccess([string]$Path, [string]$PrincipalSid, [System.Security.AccessControl.FileSystemRights]$RequiredRights, [bool]$RequireDirectAllow) {
    if (-not (Test-Path -LiteralPath $Path)) { return $false }
    $rules = (Get-Acl -LiteralPath $Path).GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $allowedSids = if ($RequireDirectAllow) { @($PrincipalSid) } else { @($PrincipalSid, 'S-1-1-0', 'S-1-5-11', 'S-1-5-32-545') }
    [int64]$allowMask = 0
    [int64]$denyMask = 0
    $requiredMask = [int64]$RequiredRights
    foreach ($rule in $rules) {
        $ruleMask = [int64]$rule.FileSystemRights
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and ($ruleMask -band $requiredMask) -ne 0) { $denyMask = $denyMask -bor $ruleMask }
        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and $allowedSids -contains $rule.IdentityReference.Value) { $allowMask = $allowMask -bor $ruleMask }
    }
    return ($denyMask -band $requiredMask) -eq 0 -and ($allowMask -band $requiredMask) -eq $requiredMask
}
$os = Get-CimInstance -ClassName Win32_OperatingSystem
Add-Check 'host.windows' ($null -ne $os) $true $os.Caption 'Windows' 'Windows host detected.'
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$consoleUser = [string]$computer.UserName
$expectedUser = [string]$config.interactive_user
$expectedSid = Resolve-Sid $expectedUser
$consoleSid = Resolve-Sid $consoleUser
Add-Check 'host.console-user' ($null -ne $expectedSid -and $consoleSid -eq $expectedSid) $true ([ordered]@{identity=$consoleUser; sid=$consoleSid}) ([ordered]@{identity=$expectedUser; sid=$expectedSid}) 'Configured interactive user SID must own the console session.'
$blenderPath = [string]$config.blender_executable
$daemonPath = [string]$config.session_broker_executable
$hostPath = [string]$config.host_executable
$readExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
$modify = [System.Security.AccessControl.FileSystemRights]::Modify
$blenderOK = Test-Path -LiteralPath $blenderPath -PathType Leaf
$daemonOK = Test-Path -LiteralPath $daemonPath -PathType Leaf
$hostOK = Test-Path -LiteralPath $hostPath -PathType Leaf
Add-Check 'blender.executable' ($blenderOK -and (Test-ConservativePathAccess $blenderPath $expectedSid $readExecute $false)) $true $blenderPath 'existing file with unambiguous ReadAndExecute access' 'The configured Blender executable must be readable by the task principal without an overlapping deny ACE.'
Add-Check 'daemon.executable' ($daemonOK -and (Test-ConservativePathAccess $daemonPath $expectedSid $readExecute $true)) $true $daemonPath 'existing file with explicit task-principal ReadAndExecute access' 'The staged session broker must carry the setup ACL without an overlapping deny ACE.'
Add-Check 'host.executable' ($hostOK -and (Test-ConservativePathAccess $hostPath $expectedSid $readExecute $true)) $true $hostPath 'existing file with explicit task-principal ReadAndExecute access' 'The staged Blender Box host binary must carry the setup ACL without an overlapping deny ACE.'
$rootExists = Test-Path -LiteralPath ([string]$config.work_root) -PathType Container
Add-Check 'work-root.access' ($rootExists -and (Test-ConservativePathAccess ([string]$config.work_root) $expectedSid $modify $true)) $true ([string]$config.work_root) 'existing directory with explicit task-principal Modify access' 'The operator-managed work root must carry the setup ACL without an overlapping deny ACE.'
$task = Get-ScheduledTask -TaskName ([string]$config.task_name) -ErrorAction SilentlyContinue
$taskActual = $null
$taskOK = $false
if ($null -ne $task) {
    $actions = @($task.Actions)
    $triggers = @($task.Triggers | Where-Object { $_ })
    $taskSid = Resolve-Sid ([string]$task.Principal.UserId)
    $taskActual = [ordered]@{
        user = [string]$task.Principal.UserId
        sid = $taskSid
        logon_type = [string]$task.Principal.LogonType
        run_level = [string]$task.Principal.RunLevel
        action_count = $actions.Count
        trigger_count = $triggers.Count
        multiple_instances = [string]$task.Settings.MultipleInstances
        execution_time_limit = [string]$task.Settings.ExecutionTimeLimit
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
    $taskOK = $null -ne $expectedSid -and $taskSid -eq $expectedSid -and [string]$task.Principal.LogonType -eq 'Interactive' -and [string]$task.Principal.RunLevel -eq 'Limited' -and $actions.Count -eq 1 -and $triggers.Count -eq 0 -and [string]$task.Settings.MultipleInstances -eq 'IgnoreNew' -and [string]$task.Settings.ExecutionTimeLimit -in @('PT0S', '00:00:00', '0') -and [bool]$task.Settings.Enabled -and $null -ne $actualExecute -and $actualExecute -ieq $expectedExecute -and [string]$actions[0].Arguments -ceq [string]$config.expected_task_arguments -and $null -ne $actualWorkingDirectory -and $actualWorkingDirectory -ieq $expectedWorkingDirectory
}
Add-Check 'task.interactive' $taskOK $true $taskActual ([ordered]@{user=$expectedUser; sid=$expectedSid; execute=$hostPath; arguments=[string]$config.expected_task_arguments; working_directory=[System.IO.Path]::GetDirectoryName($hostPath); logon_type='Interactive'; run_level='Limited'; triggers=0; multiple_instances='IgnoreNew'; execution_time_limit='PT0S'}) 'The static task must match the complete Blender Box action and principal contract.'
$requiredFailed = @($checks | Where-Object { $_.required -and -not $_.passed }).Count
[ordered]@{schema_version=1; status=$(if ($requiredFailed -eq 0) {'pass'} else {'fail'}); checks=$checks} | ConvertTo-Json -Compress -Depth 8
`

type SSH interface {
	Run(context.Context, string, []string, []byte) ([]byte, error)
}

type CheckResult struct {
	SchemaVersion int             `json:"schema_version"`
	Status        string          `json:"status"`
	Checks        json.RawMessage `json:"checks"`
}

func Check(ctx context.Context, ssh SSH, selected target.Target) (CheckResult, error) {
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
		"$ErrorActionPreference = 'Stop'\n$ProgressPreference = 'SilentlyContinue'\n$configText = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('%s'))\n%s",
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
	var result CheckResult
	if err := json.Unmarshal(output, &result); err != nil {
		return CheckResult{}, fmt.Errorf("parse Windows check result: %w", err)
	}
	if result.SchemaVersion != 1 || (result.Status != "pass" && result.Status != "fail") || len(result.Checks) == 0 {
		return CheckResult{}, fmt.Errorf("Windows check returned an invalid contract")
	}
	return result, nil
}

func encodePowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	bytes := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(bytes[index*2:], unit)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}
