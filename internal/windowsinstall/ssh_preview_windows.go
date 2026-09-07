//go:build windows

package windowsinstall

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/BramVR/blender-box/internal/windowstarget"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
)

var sshGetSecurityInfo = syscall.NewLazyDLL("advapi32.dll").NewProc("GetSecurityInfo")
var sshLocalFree = syscall.NewLazyDLL("kernel32.dll").NewProc("LocalFree")

type sshWindowsFacts struct {
	AuthenticatedSID string              `json:"authenticated_sid"`
	InteractiveSID   string              `json:"interactive_sid"`
	Accounts         []sshWindowsAccount `json:"accounts"`
	ProgramData      string              `json:"program_data"`
	ConfigPath       string              `json:"config_path"`
	BinaryPath       string              `json:"binary_path"`
	KeygenPath       string              `json:"keygen_path"`
	Service          SSHServiceState     `json:"service"`
	Firewall         []SSHFirewallRule   `json:"firewall"`
}
type sshWindowsAccount struct {
	Name          string   `json:"name"`
	SID           string   `json:"sid"`
	Administrator bool     `json:"administrator"`
	Groups        []string `json:"groups"`
}

func (s *sshNativeReader) inspectSSH(ctx context.Context, r SSHPreparationRequest) (sshNativeObservation, error) {
	var observed sshNativeObservation
	if !windowstarget.ValidateWindowsPath(r.StateRoot) {
		return observed, fmt.Errorf("native Windows state root required")
	}
	installed, parent, err := loadSSHInstallation(ctx, r, sshReadMachine{reader: s}, s.files())
	if err != nil {
		return observed, err
	}
	var receipt installationReceipt
	receipt, err = sshReceipt(r, installed.Receipt)
	if err != nil {
		return observed, err
	}
	system, err := systemDirectory()
	if err != nil {
		return observed, err
	}
	var discovered struct {
		ProgramData string `json:"program_data"`
	}
	output, err := s.powerShell(ctx, `[ordered]@{program_data=[Environment]::GetFolderPath('CommonApplicationData')} | ConvertTo-Json -Compress`, nil)
	if err != nil {
		return observed, err
	}
	if err := decodeSSHObservation(output, &discovered); err != nil {
		return observed, err
	}
	configPath := filepath.Join(discovered.ProgramData, "ssh", "sshd_config")
	binaryPath := filepath.Join(system, "OpenSSH", "sshd.exe")
	keygenPath := filepath.Join(system, "OpenSSH", "ssh-keygen.exe")
	for _, path := range []string{discovered.ProgramData, configPath, binaryPath, keygenPath} {
		if !windowstarget.ValidateWindowsPath(path) {
			return observed, fmt.Errorf("invalid native OpenSSH path")
		}
		if err := s.trusted(path, receipt.Intent.OwnerSID); err != nil {
			return observed, err
		}
	}
	binaryProbe, err := s.commandPath(binaryPath)
	if err != nil {
		return observed, err
	}
	input := map[string]any{}
	requestData, _ := json.Marshal(r)
	if err := json.Unmarshal(requestData, &input); err != nil {
		return observed, err
	}
	input["program_data"] = discovered.ProgramData
	input["binary_path"] = binaryPath
	input["keygen_path"] = keygenPath
	input["config_path"] = configPath
	input["binary_probe"] = binaryProbe
	readFacts := func() (sshWindowsFacts, error) {
		var facts sshWindowsFacts
		output, err := s.powerShell(ctx, sshFactsScript, input)
		if err != nil {
			return facts, err
		}
		if err := decodeSSHObservation(output, &facts); err != nil {
			return facts, err
		}
		if len(facts.Accounts) != len(r.ControlAccounts)+1 || len(facts.Firewall) == 0 || len(facts.Firewall) > 256 {
			return facts, fmt.Errorf("incomplete or excessive native facts")
		}
		return facts, nil
	}
	facts, err := readFacts()
	if err != nil {
		return observed, err
	}
	if facts.AuthenticatedSID != receipt.Intent.OwnerSID || facts.InteractiveSID != facts.AuthenticatedSID || facts.Accounts[0].SID != facts.AuthenticatedSID {
		return observed, fmt.Errorf("authenticated, interactive and installed account SIDs differ")
	}
	installed.AccountSID = facts.Accounts[0].SID
	installed.AuthenticatedSID = facts.AuthenticatedSID
	installed.InteractiveSID = facts.InteractiveSID
	observed = sshNativeObservation{Installed: installed, Parent: parent, Service: facts.Service, Firewall: facts.Firewall, Policies: []sshPolicyObservation{}, HostKeys: []SSHHostKeyPin{}}
	observed.Configuration, err = s.image(facts.ConfigPath, maxSSHConfig)
	if err != nil {
		return observed, err
	}
	keys, err := sshConfig(observed.Configuration.Bytes)
	if err != nil {
		return observed, err
	}
	if len(keys) != 1 {
		return observed, fmt.Errorf("one explicit Ed25519 HostKey required")
	}
	binary, err := s.image(facts.BinaryPath, 64<<20)
	if err != nil {
		return observed, err
	}
	keygen, err := s.image(facts.KeygenPath, 64<<20)
	if err != nil {
		return observed, err
	}
	observed.Service.Binary = binary.Pin
	observed.Keygen = keygen.Pin
	if observed.Service.CommandLine != `"`+facts.BinaryPath+`"` || !strings.HasPrefix(observed.Service.BinaryVersion, "9.5.") {
		return observed, fmt.Errorf("unsupported installed sshd service command or version")
	}
	environment, err := s.commandEnvironment()
	if err != nil {
		return observed, err
	}
	if !windowstarget.ValidateWindowsPath(facts.ProgramData) || facts.ConfigPath != filepath.Join(facts.ProgramData, "ssh", "sshd_config") {
		return observed, fmt.Errorf("invalid native ProgramData directory")
	}
	physicalProgramData, err := s.commandPath(facts.ProgramData)
	if err != nil {
		return observed, err
	}
	environment = append(environment, "ProgramData="+physicalProgramData)
	keyPath := keys[0]
	if !windowstarget.ValidateWindowsPath(keyPath) {
		return observed, fmt.Errorf("configured HostKey must use canonical absolute path")
	}
	private, err := s.open(keyPath)
	if err != nil {
		return observed, err
	}

	privatePin, err := private.pin(keyPath)
	if err != nil {
		return observed, err
	}
	if err := s.trusted(keyPath, receipt.Intent.OwnerSID); err != nil {
		return observed, err
	}
	trustedPrivate, err := s.pin(keyPath, false)
	if err != nil || trustedPrivate != privatePin {
		return observed, fmt.Errorf("private source changed during trust inspection")
	}
	public, err := s.image(keyPath+".pub", 16<<10)
	if err != nil {
		return observed, err
	}
	keygenHandle, err := s.open(facts.KeygenPath)
	if err != nil {
		return observed, err
	}

	keygenPin, err := keygenHandle.pin(facts.KeygenPath)
	if err != nil || keygenPin != observed.Keygen.Path {
		return observed, fmt.Errorf("ssh-keygen changed before execution")
	}
	physicalKeygen, err := s.commandPath(facts.KeygenPath)
	if err != nil {
		return observed, err
	}
	physicalKey, err := s.commandPath(keyPath)
	if err != nil {
		return observed, err
	}
	output, err = runNative(ctx, physicalKeygen, []string{"-y", "-f", physicalKey}, nil, environment)
	if err != nil {
		return observed, fmt.Errorf("configured host-key derivation failed: %w", err)
	}
	derived, err := sshPublic(output)
	if err != nil {
		return observed, err
	}
	companion, err := sshPublic(public.Bytes)
	if err != nil || derived != companion {
		return observed, fmt.Errorf("configured host key and companion public file differ")
	}
	currentPrivate, err := s.pin(keyPath, false)
	if err != nil || privatePin != currentPrivate {
		return observed, fmt.Errorf("configured private-source metadata changed")
	}
	observed.HostKeys = append(observed.HostKeys, SSHHostKeyPin{PrivateSource: privatePin, PublicSource: public, PublicKey: derived, PublicSHA: digest([]byte(derived)), Provenance: "configured-private-key-derived-by-pinned-ssh-keygen; listener-unverified"})
	sshdHandle, err := s.open(facts.BinaryPath)
	if err != nil {
		return observed, err
	}

	sshdPin, err := sshdHandle.pin(facts.BinaryPath)
	if err != nil || sshdPin != observed.Service.Binary.Path {
		return observed, fmt.Errorf("sshd changed before execution")
	}
	for index, account := range facts.Accounts {
		expected := r.Account
		if index > 0 {
			expected = r.ControlAccounts[index-1]
		}
		if account.Name != expected || len(account.Groups) > 64 || !sortedUnique(account.Groups) {
			return observed, fmt.Errorf("unsupported local account/group shape")
		}
		connection := "user=" + account.Name + ",host=" + r.Connection.Hostname + ",addr=" + strings.Split(r.Connection.RemotePrefixes[0], "/")[0] + ",laddr=" + r.Connection.LocalAddresses[0] + ",lport=" + fmt.Sprint(r.Connection.Port)
		physicalConfig, err := s.commandPath(facts.ConfigPath)
		if err != nil {
			return observed, err
		}
		physicalBinary, err := s.commandPath(facts.BinaryPath)
		if err != nil {
			return observed, err
		}
		output, err := runNative(ctx, physicalBinary, []string{"-G", "-T", "-f", physicalConfig, "-C", connection}, nil, environment)
		if err != nil {
			return observed, fmt.Errorf("current native sshd policy failed: %w", err)
		}
		if _, _, err := sshPolicy(output); err != nil {
			return observed, err
		}
		observed.Policies = append(observed.Policies, sshPolicyObservation{Account: account.Name, SID: account.SID, Administrator: account.Administrator, Groups: account.Groups, Text: output})
	}
	after, err := readFacts()
	if err != nil || !reflect.DeepEqual(facts, after) {
		return observed, fmt.Errorf("native account, service or firewall changed")
	}
	for _, expected := range []SSHByteImage{observed.Configuration, binary, keygen, public} {
		current, err := s.image(expected.Pin.Path.Path, int(expected.Pin.Size))
		if err != nil || !reflect.DeepEqual(expected, current) {
			return observed, fmt.Errorf("native file changed after commands")
		}
	}
	currentPrivate, err = s.pin(keyPath, false)
	if err != nil || currentPrivate != privatePin {
		return observed, fmt.Errorf("configured private source changed after commands")
	}
	installedAfter, parentAfter, err := loadSSHInstallation(ctx, r, sshReadMachine{reader: s}, s.files())
	if err != nil {
		return observed, err
	}
	installedAfter.AccountSID = installed.AccountSID
	installedAfter.AuthenticatedSID = installed.AuthenticatedSID
	installedAfter.InteractiveSID = installed.InteractiveSID
	if !reflect.DeepEqual(installed, installedAfter) || parent != parentAfter {
		return observed, fmt.Errorf("installed scope changed")
	}
	slices.SortFunc(observed.Firewall, func(a, b SSHFirewallRule) int { return strings.Compare(a.ID, b.ID) })
	return observed, nil
}

const sshFactsScript = `
$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$sid=$identity.User.Value
if(-not ([Security.Principal.WindowsPrincipal]::new($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'SSH preview requires elevation as the installed interactive account'}
$interactive=(Get-CimInstance Win32_ComputerSystem).UserName
if(-not $interactive){throw 'No interactive account'}
$interactiveSid=([Security.Principal.NTAccount]::new($interactive)).Translate([Security.Principal.SecurityIdentifier]).Value
$accounts=@()
$groups=@(Get-LocalGroup)
if($groups.Count -gt 64){throw 'Excessive local groups'}
$members=@{}
foreach($group in $groups){$members[$group.SID.Value]=@(Get-LocalGroupMember -SID $group.SID -ErrorAction Stop | ForEach-Object {$_.SID.Value})}
foreach($name in (@($r.account)+@($r.control_accounts))){
 $user=Get-LocalUser -Name $name -ErrorAction Stop
 if(-not $user.Enabled -or $user.PrincipalSource -ne 'Local' -or $user.Name.ToLowerInvariant() -cne $name){throw 'Unsupported local account'}
 $membership=@($groups | Where-Object {$members[$_.SID.Value] -contains $user.SID.Value} | ForEach-Object {$_.SID.Value} | Sort-Object)
 $accounts+=,[ordered]@{name=$name;sid=$user.SID.Value;administrator=($membership -contains 'S-1-5-32-544');groups=$membership}
}
if($accounts[0].sid -ne $sid -or $interactiveSid -ne $sid){throw 'Selected, authenticated and interactive SIDs differ'}
$binary=$r.binary_path
$keygen=$r.keygen_path
$programData=$r.program_data
$config=$r.config_path
$svc=Get-CimInstance Win32_Service -Filter "Name='sshd'"
if(-not $svc -or $svc.State -ne 'Running' -or $svc.StartName -ne 'LocalSystem' -or $svc.StartMode -ne 'Auto' -or $svc.PathName -cne ('"'+$binary+'"')){throw 'Unsupported existing sshd service'}
$security=Invoke-CimMethod -InputObject $svc -MethodName GetSecurityDescriptor
if($security.ReturnValue -ne 0){throw 'Cannot read service security'}
$sddl=Invoke-CimMethod -ClassName Win32_SecurityDescriptorHelper -MethodName Win32SDToSDDL -Arguments @{Descriptor=$security.Descriptor}
if($sddl.ReturnValue -ne 0 -or -not $sddl.SDDL){throw 'Cannot encode service security'}
$profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore)
if($profiles.Count -ne 3){throw 'Incomplete effective firewall profiles'}
foreach($profile in $profiles){if($profile.Enabled -ne 'True' -or $profile.DefaultInboundAction -ne 'Block' -or $profile.AllowInboundRules -ne 'True' -or $profile.AllowLocalFirewallRules -ne 'True' -or @($profile.DisabledInterfaceAliases).Count -ne 0){throw 'Unsupported effective firewall profile'}}
$rules=@(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound)
if($rules.Count -gt 4096){throw 'Excessive firewall rule inventory'}
$firewall=@()
foreach($rule in $rules){
 $port=Get-NetFirewallPortFilter -AssociatedNetFirewallRule $rule
 if(@($port).Count -ne 1){throw 'Ambiguous firewall port filter'}
 if($port.Protocol -ne 'TCP' -and $port.Protocol -ne '6' -and $port.Protocol -ne 'Any' -and $port.Protocol -ne '256'){continue}
 $relevant=$false
 foreach($token in @($port.LocalPort)){
  if($token -eq 'Any'){$relevant=$true}
  elseif($token -match '^\d+$'){if([int]$token -eq [int]$r.connection.port){$relevant=$true}}
  elseif($token -match '^(\d+)-(\d+)$'){if([int]$r.connection.port -ge [int]$Matches[1] -and [int]$r.connection.port -le [int]$Matches[2]){$relevant=$true}}
  else{throw 'Unknown firewall port token'}
 }
 if(-not $relevant){continue}
 $address=Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule
 $app=Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rule
 $service=Get-NetFirewallServiceFilter -AssociatedNetFirewallRule $rule
 $interface=Get-NetFirewallInterfaceTypeFilter -AssociatedNetFirewallRule $rule
 $interfaces=Get-NetFirewallInterfaceFilter -AssociatedNetFirewallRule $rule
 $security=Get-NetFirewallSecurityFilter -AssociatedNetFirewallRule $rule
 if(@($address).Count -ne 1 -or @($app).Count -ne 1 -or @($service).Count -ne 1 -or @($interface).Count -ne 1 -or @($interfaces).Count -ne 1 -or @($security).Count -ne 1 -or @($interfaces.InterfaceAlias).Count -ne 1 -or $interfaces.InterfaceAlias -ne 'Any' -or $security.Authentication -ne 'NotRequired' -or $security.Encryption -ne 'NotRequired' -or $security.OverrideBlockRules -ne $false -or $security.LocalUser -ne 'Any' -or $security.RemoteUser -ne 'Any' -or $security.RemoteMachine -ne 'Any' -or $app.Package -ne 'Any'){throw 'Unsupported firewall filters'}
 if($rule.PrimaryStatus -ne 'OK' -or $rule.LooseSourceMapping -ne $false -or $rule.LocalOnlyMapping -ne $false -or @($rule.Platform).Count -ne 0 -or $rule.Owner){throw 'Unsupported firewall rule restrictions'}
 if($rule.PolicyStoreSourceType -ne 'Local' -or $rule.PolicyStoreSource -ne 'PersistentStore'){throw 'Unsupported firewall provenance'}
 $ruleProfiles=@($rule.Profile.ToString().Split(',') | ForEach-Object {$_.Trim().ToLowerInvariant()} | Sort-Object)
 $protocol=$port.Protocol.ToString();if($protocol -eq '6'){$protocol='TCP'}
 $firewall+=,[ordered]@{policy_store='PersistentStore';id=$rule.Name;enabled=$true;direction=$rule.Direction.ToString();action=$rule.Action.ToString();profiles=$ruleProfiles;protocol=$protocol;local_addresses=@($address.LocalAddress | Sort-Object);local_ports=@($port.LocalPort | Sort-Object);remote_addresses=@($address.RemoteAddress | Sort-Object);remote_ports=@($port.RemotePort | Sort-Object);program=$app.Program;service=$service.Service;interface_types=@($interface.InterfaceType | ForEach-Object {$_.ToString()} | Sort-Object);edge_traversal=$rule.EdgeTraversalPolicy.ToString()}
 if($firewall.Count -gt 256){throw 'Excessive relevant firewall rules'}
}
[ordered]@{authenticated_sid=$sid;interactive_sid=$interactiveSid;accounts=$accounts;program_data=$programData;config_path=$config;binary_path=$binary;keygen_path=$keygen;service=[ordered]@{installation_provenance='system-directory-openssh-binaries-and-existing-service; capability-inventory-unobserved';os_build=[Environment]::OSVersion.Version.ToString();name=$svc.Name;binary_version=(Get-Item -LiteralPath $r.binary_probe).VersionInfo.FileVersion;command_line=$svc.PathName;account=$svc.StartName;start_type=$svc.StartMode;state=$svc.State;service_sddl=$sddl.SDDL;activation='';required_privilege=''};firewall=@($firewall | Sort-Object id)} | ConvertTo-Json -Depth 12 -Compress
`
