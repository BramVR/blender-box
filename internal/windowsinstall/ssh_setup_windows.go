//go:build windows

package windowsinstall

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/strictjson"
)

type nativeSSHMachine struct{ nativeSSHD }

// firewallObservation is what Windows reports for one named rule after inspect, create or delete.
type firewallObservation struct {
	Exists        bool     `json:"exists"`
	Direction     string   `json:"direction"`
	Action        string   `json:"action"`
	Enabled       string   `json:"enabled"`
	Protocol      string   `json:"protocol"`
	LocalPort     []string `json:"local_port"`
	Program       string   `json:"program"`
	Profile       string   `json:"profile"`
	RemoteAddress []string `json:"remote_address"`
}

func (nativeSSHMachine) setService(ctx context.Context, startType string, start bool) error {
	if startType != "" && !slices.Contains([]string{"Automatic", "Manual", "Disabled"}, startType) {
		return fmt.Errorf("unsupported service start type %q", startType)
	}
	_, err := powerShell(ctx, `if ($r.start_type) { Set-Service -Name sshd -StartupType $r.start_type }
if ($r.start) { Start-Service -Name sshd }
'{}'`, map[string]any{"start_type": startType, "start": start})
	return err
}

func (nativeSSHMachine) rule(ctx context.Context, operation string, rule FirewallRule) (bool, bool, error) {
	if !slices.Contains([]string{"inspect", "create", "delete"}, operation) {
		return false, false, fmt.Errorf("unknown firewall operation %q", operation)
	}
	output, err := powerShellWithTimeout(ctx, `$rules=@(Get-NetFirewallRule -Name $r.rule.name -ErrorAction SilentlyContinue)
if ($rules.Count -gt 1) { throw "ambiguous firewall rule $($r.rule.name)" }
if ($r.operation -eq 'create' -and $rules.Count -eq 0) {
 $rules=@(New-NetFirewallRule -Name $r.rule.name -DisplayName $r.rule.name -Description 'Blender Box owned inbound rule for OpenSSH pairing' -Direction Inbound -Action Allow -Enabled True -Protocol TCP -LocalPort ([string]$r.rule.port) -Program $r.rule.program -Profile ([string[]]$r.rule.profiles) -RemoteAddress ([string[]]$r.rule.remote_addresses))
}
if ($r.operation -eq 'delete' -and $rules.Count -eq 1) { Remove-NetFirewallRule -Name $r.rule.name; $rules=@() }
if ($rules.Count -eq 0) { '{"exists":false}' } else {
 $rule=$rules[0]
 $port=$rule | Get-NetFirewallPortFilter
 $app=$rule | Get-NetFirewallApplicationFilter
 $addr=$rule | Get-NetFirewallAddressFilter
 [ordered]@{exists=$true;direction=[string]$rule.Direction;action=[string]$rule.Action;enabled=[string]$rule.Enabled;protocol=[string]$port.Protocol;local_port=@([string[]]$port.LocalPort);program=[string]$app.Program;profile=[string]$rule.Profile;remote_address=@([string[]]$addr.RemoteAddress)} | ConvertTo-Json -Compress
}`, map[string]any{"operation": operation, "rule": rule}, 60*time.Second)
	if err != nil {
		return false, false, err
	}
	var observed firewallObservation
	if err := strictjson.Decode(output, &observed); err != nil {
		return false, false, err
	}
	return observed.Exists, rule.matches(observed), nil
}

func (rule FirewallRule) matches(observed firewallObservation) bool {
	return observed.Exists && observed.Direction == "Inbound" && observed.Action == "Allow" && observed.Enabled == "True" && observed.Protocol == "TCP" &&
		slices.Equal(observed.LocalPort, []string{strconv.Itoa(int(rule.Port))}) && strings.EqualFold(observed.Program, rule.Program) &&
		sameFold(profileSet(observed.Profile), rule.Profiles) && sameFold(observed.RemoteAddress, rule.RemoteAddresses)
}

// profileSet expands the flags string Windows reports ("Any" or "Domain, Private").
func profileSet(profile string) []string {
	if strings.EqualFold(strings.TrimSpace(profile), "Any") {
		return firewallProfiles
	}
	var set []string
	for _, item := range strings.Split(profile, ",") {
		if item = strings.TrimSpace(item); item != "" {
			set = append(set, item)
		}
	}
	return set
}

func sameFold(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for _, item := range a {
		if !slices.ContainsFunc(b, func(other string) bool { return strings.EqualFold(item, other) }) {
			return false
		}
	}
	return true
}

func (nativeSSHMachine) admittingRule(ctx context.Context, port uint16) (string, error) {
	output, err := powerShellWithTimeout(ctx, `$rules=@(Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -ErrorAction SilentlyContinue)
$filters=@(Get-NetFirewallPortFilter -All)
if ($rules.Count -gt 4096 -or $filters.Count -gt 4096) { throw 'firewall enumeration exceeds bound' }
$ports=@{}
foreach ($f in $filters) { if ($f.Protocol -eq 'TCP') { $lp=@([string[]]$f.LocalPort); if ($lp -contains 'Any' -or $lp -contains [string]$r.port) { $ports[$f.InstanceID]=$true } } }
$programs=@{}
foreach ($a in @(Get-NetFirewallApplicationFilter -All)) { $programs[$a.InstanceID]=[string]$a.Program }
$sshd=[Environment]::ExpandEnvironmentVariables($r.program)
$names=[System.Collections.Generic.List[string]]::new()
foreach ($rule in $rules) {
 if (-not $ports.ContainsKey($rule.Name)) { continue }
 $p=$programs[$rule.Name]
 if (-not $p -or $p -eq 'Any' -or [Environment]::ExpandEnvironmentVariables($p) -ieq $sshd) { $names.Add($rule.Name) }
}
ConvertTo-Json -InputObject @($names | Sort-Object -Unique) -Compress`, map[string]any{"port": port, "program": sshdProgram}, 60*time.Second)
	if err != nil {
		return "", err
	}
	var names []string
	if err := strictjson.Decode(output, &names); err != nil {
		return "", err
	}
	if slices.Contains(names, "OpenSSH-Server-In-TCP") {
		return "OpenSSH-Server-In-TCP", nil
	}
	if len(names) == 0 {
		return "", nil
	}
	return names[0], nil
}
