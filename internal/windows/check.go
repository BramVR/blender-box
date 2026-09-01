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

const checkScript = `$ErrorActionPreference = 'Stop'
$configText = [Console]::In.ReadToEnd()
$config = $configText | ConvertFrom-Json
$checks = [System.Collections.Generic.List[object]]::new()
function Add-Check([string]$Id, [bool]$Passed, [bool]$Required, $Actual, $Expected, [string]$Message) {
    $checks.Add([ordered]@{id=$Id; passed=$Passed; required=$Required; actual=$Actual; expected=$Expected; message=$Message})
}
$os = Get-CimInstance -ClassName Win32_OperatingSystem
Add-Check 'host.windows' ($null -ne $os) $true $os.Caption 'Windows' 'Windows host detected.'
$computer = Get-CimInstance -ClassName Win32_ComputerSystem
$consoleUser = [string]$computer.UserName
$expectedUser = [string]$config.interactive_user
$shortExpected = ($expectedUser -split '\\')[-1]
$shortActual = ($consoleUser -split '\\')[-1]
Add-Check 'host.console-user' ($shortActual -ieq $shortExpected) $true $consoleUser $expectedUser 'Configured interactive user must be logged in.'
$blender = Get-Command blender.exe -ErrorAction SilentlyContinue
Add-Check 'blender.command' ($null -ne $blender) $true ([string]$blender.Source) 'blender.exe on PATH' 'Blender must be discoverable.'
$daemon = Get-Command blendersessiond.exe -ErrorAction SilentlyContinue
if ($null -eq $daemon) { $daemon = Get-Command blendersessiond -ErrorAction SilentlyContinue }
Add-Check 'daemon.command' ($null -ne $daemon) $true ([string]$daemon.Source) 'blendersessiond on PATH' 'blendersessiond must be discoverable.'
$rootExists = Test-Path -LiteralPath ([string]$config.work_root) -PathType Container
Add-Check 'work-root.exists' $rootExists $true ([string]$config.work_root) 'existing directory' 'The operator-managed work root must exist.'
$task = Get-ScheduledTask -TaskName ([string]$config.task_name) -ErrorAction SilentlyContinue
$taskActual = $null
$taskOK = $false
if ($null -ne $task) {
    $actions = @($task.Actions)
    $triggers = @($task.Triggers | Where-Object { $_ })
    $taskActual = [ordered]@{
        user = [string]$task.Principal.UserId
        logon_type = [string]$task.Principal.LogonType
        run_level = [string]$task.Principal.RunLevel
        action_count = $actions.Count
        trigger_count = $triggers.Count
        multiple_instances = [string]$task.Settings.MultipleInstances
        execution_time_limit = [string]$task.Settings.ExecutionTimeLimit
        enabled = [bool]$task.Settings.Enabled
    }
    $taskUser = ([string]$task.Principal.UserId -split '\\')[-1]
    $taskOK = $taskUser -ieq $shortExpected -and [string]$task.Principal.LogonType -eq 'Interactive' -and [string]$task.Principal.RunLevel -eq 'Limited' -and $actions.Count -eq 1 -and $triggers.Count -eq 0 -and [string]$task.Settings.MultipleInstances -eq 'IgnoreNew' -and [string]$task.Settings.ExecutionTimeLimit -in @('PT0S', '00:00:00', '0') -and [bool]$task.Settings.Enabled
}
Add-Check 'task.interactive' $taskOK $true $taskActual 'Interactive, Limited, no trigger, IgnoreNew, no time limit' 'The static task must match the Blender Box safety contract.'
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
	input, err := json.Marshal(selected)
	if err != nil {
		return CheckResult{}, fmt.Errorf("encode target check input: %w", err)
	}
	arguments := []string{
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-EncodedCommand",
		encodePowerShell(checkScript),
	}
	output, err := ssh.Run(ctx, selected.SSHAlias, arguments, input)
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
