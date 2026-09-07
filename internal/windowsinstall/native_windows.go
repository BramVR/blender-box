//go:build windows

package windowsinstall

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/target"
	"github.com/BramVR/blender-box/internal/windowstarget"
)

type nativeMachine struct {
	pythonCommand func(context.Context, string, []string, []byte, []string) ([]byte, error)
}

func cleanEnvironment() ([]string, error) {
	directory, err := systemDirectory()
	if err != nil {
		return nil, err
	}
	return pythonEnvironment(os.Environ(), directory), nil
}
func runNative(ctx context.Context, executable string, args []string, input []byte, environment []string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return runNativeJob(ctx, executable, args, input, environment)
}
func powerShell(ctx context.Context, action string, input any) ([]byte, error) {
	return powerShellWithTimeout(ctx, action, input, 15*time.Second)
}
func powerShellWithTimeout(ctx context.Context, action string, input any, timeout time.Duration) ([]byte, error) {
	data, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	script := "$ErrorActionPreference='Stop'\n$env:PSModulePath=[IO.Path]::Combine($PSHOME,'Modules')\n[Console]::InputEncoding=[Text.UTF8Encoding]::new($false)\n[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false)\n$OutputEncoding=[Console]::OutputEncoding\n$r=ConvertFrom-Json ([Console]::In.ReadToEnd())\n" + nativeFunctions + "\n" + action
	units := utf16.Encode([]rune(script))
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:], unit)
	}
	directory, err := systemDirectory()
	if err != nil {
		return nil, err
	}
	executable := filepath.Join(directory, "WindowsPowerShell", "v1.0", "powershell.exe")
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return runNativeJobWithIntent(ctx, nativeTrustedPowerShell, executable, []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(encoded)}, data, powerShellEnvironment(os.Environ(), directory), nil)
}
func (m nativeMachine) inspect(ctx context.Context, r Request) (Inspection, error) {
	inspection := Inspection{BlenderCandidates: []Candidate{}}
	if !windowstarget.ValidateWindowsPath(r.StateRoot) {
		return inspection, fmt.Errorf("unsafe Windows state root")
	}
	var identity struct {
		SID string `json:"sid"`
	}
	output, err := powerShell(ctx, `$sid=[System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$account=(Get-CimInstance Win32_ComputerSystem).UserName
if (-not $account) { throw 'No logged-in interactive user' }
$console=([System.Security.Principal.NTAccount]::new($account)).Translate([System.Security.Principal.SecurityIdentifier]).Value
if ($sid -ne $console) { throw 'Authenticated and interactive SID must match' }
if ($r.windows_user) { $selected=([System.Security.Principal.NTAccount]::new($r.windows_user)).Translate([System.Security.Principal.SecurityIdentifier]).Value; if ($selected -ne $sid) { throw 'Selected account differs' } }
if ($sid -match '-500$' -or (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA -ne 1) { throw 'Limited interactive task requires enabled UAC and a non-RID-500 account' }
[ordered]@{sid=$sid} | ConvertTo-Json -Compress`, map[string]string{"windows_user": r.WindowsUser})
	if err != nil {
		return inspection, err
	}
	if err = strictjson.Decode(output, &identity); err != nil {
		return inspection, err
	}
	inspection.OwnerSID = identity.SID
	if err = m.securePath(ctx, r.StateRoot, identity.SID, true); err != nil {
		return inspection, err
	}
	if _, err = os.Lstat(r.StateRoot); err == nil {
		inspection.RootIdentity, err = fileIdentity(r.StateRoot)
		if err != nil {
			return inspection, err
		}
	}
	if r.Operation == "remove" || r.Operation == "status" {
		return inspection, nil
	}
	if r.BlenderPath != "" {
		candidate, err := m.candidate(ctx, r.BlenderPath, identity.SID, true)
		if err != nil {
			return inspection, err
		}
		inspection.BlenderCandidates = append(inspection.BlenderCandidates, candidate)
	} else {
		output, err = powerShell(ctx, `$paths=[System.Collections.Generic.List[string]]::new()
foreach($key in @('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*')) {
 $items=@(Get-ItemProperty $key -ErrorAction SilentlyContinue); if($items.Count -gt 4096){throw 'Uninstall registry exceeds discovery bound'}
 foreach($item in $items){ if($item.DisplayName -like 'Blender*' -and $item.InstallLocation){$paths.Add((Join-Path $item.InstallLocation 'blender.exe'))} }
}
$base=Join-Path $env:ProgramFiles 'Blender Foundation'
if(Test-Path -LiteralPath $base){$children=@(Get-ChildItem -LiteralPath $base -Directory);if($children.Count -gt 128){throw 'Blender discovery exceeds bound'};foreach($child in $children){$paths.Add((Join-Path $child.FullName 'blender.exe'))}}
$found=@($paths | Sort-Object -Unique | Where-Object {Test-Path -LiteralPath $_ -PathType Leaf});ConvertTo-Json -InputObject $found -Compress`, struct{}{})
		if err != nil {
			return inspection, err
		}
		var paths []string
		if err = json.Unmarshal(output, &paths); err != nil {
			return inspection, err
		}
		if len(paths) > 128 {
			return inspection, fmt.Errorf("excessive Blender candidates")
		}
		for _, path := range paths {
			candidate, err := m.candidate(ctx, path, identity.SID, true)
			if err != nil {
				return inspection, err
			}
			inspection.BlenderCandidates = append(inspection.BlenderCandidates, candidate)
		}
	}
	if r.PythonPath != "" {
		python, err := m.python(ctx, r.PythonPath, identity.SID)
		if err != nil {
			return inspection, err
		}
		inspection.Python = &python
	}
	return inspection, nil
}
func (m nativeMachine) candidate(ctx context.Context, path, sid string, executable bool) (Candidate, error) {
	if !windowstarget.ValidateWindowsPath(path) {
		return Candidate{}, fmt.Errorf("unsafe prerequisite path")
	}
	if _, err := powerShell(ctx, `Assert-Path $r.path $r.sid $false; Assert-Access $r.path $r.sid $false`, map[string]string{"path": path, "sid": sid}); err != nil {
		return Candidate{}, err
	}
	hash, identity, err := hashPrerequisite(path, executable)
	if err != nil {
		return Candidate{}, err
	}
	version := ""
	if executable {
		data, err := powerShell(ctx, `$v=[Diagnostics.FileVersionInfo]::GetVersionInfo($r.path);[ordered]@{version=[string]$v.FileVersion}|ConvertTo-Json -Compress`, map[string]string{"path": path})
		if err != nil {
			return Candidate{}, err
		}
		var info struct {
			Version string `json:"version"`
		}
		if err := strictjson.Decode(data, &info); err != nil {
			return Candidate{}, err
		}
		version = info.Version
	}
	afterIdentity, err := fileIdentity(path)
	if err != nil || afterIdentity != identity {
		return Candidate{}, fmt.Errorf("prerequisite changed during version inspection")
	}
	return Candidate{Path: path, Version: version, SHA256: hash, Identity: identity}, nil
}
func (m nativeMachine) python(ctx context.Context, path, sid string) (PythonPrerequisite, error) {
	result := PythonPrerequisite{}
	candidate, err := m.candidate(ctx, path, sid, true)
	if err != nil {
		return result, err
	}
	dllPath, err := pythonRuntimeDLL(candidate)
	if err != nil {
		return result, err
	}
	dll, err := m.candidate(ctx, dllPath, sid, false)
	if err != nil {
		return result, err
	}
	if err = auditPython(ctx, filepath.Dir(path), sid); err != nil {
		return result, err
	}
	code := `import json,sys,sysconfig,platform,os,venv,ctypes
assert sys.implementation.name == 'cpython' and sys.platform == 'win32' and sys.version_info[:2] >= (3,11) and sys.version_info[:2] <= (3,14)
assert sys.prefix == sys.base_prefix and platform.machine().lower() in ('amd64','x86_64')
assert not sysconfig.is_python_build() and not sysconfig.get_config_var('Py_GIL_DISABLED') and not hasattr(sys,'gettotalrefcount')
assert os.path.basename(sys.executable).lower() == 'python.exe'
home=os.path.dirname(sys.executable)
template=os.path.join(os.path.dirname(venv.__file__),'scripts','nt','venvlauncher.exe' if sys.version_info[:2] >= (3,13) else 'python.exe')
buffer=ctypes.create_unicode_buffer(4096)
assert ctypes.windll.kernel32.GetModuleFileNameW(ctypes.c_void_p(sys.dllhandle),buffer,4096) in range(1,4096)
print(json.dumps(dict(version=platform.python_version(),home=home,template=template,dll=buffer.value,venv_source=venv.__file__)))`
	command := m.pythonCommand
	if command == nil {
		command = runNative
	}
	environment, err := cleanEnvironment()
	if err != nil {
		return result, err
	}
	data, err := command(ctx, path, []string{"-I", "-B", "-S", "-c", code}, nil, environment)
	if err != nil {
		return result, fmt.Errorf("unsupported CPython Windows venv recipe: %w", err)
	}
	var facts struct {
		Version    string `json:"version"`
		Home       string `json:"home"`
		Template   string `json:"template"`
		DLL        string `json:"dll"`
		VenvSource string `json:"venv_source"`
	}
	if err = strictjson.Decode(data, &facts); err != nil {
		return result, err
	}
	if !strings.EqualFold(facts.Home, filepath.Dir(path)) {
		return result, fmt.Errorf("Python executable redirected to another installation")
	}
	if !strings.EqualFold(facts.DLL, dll.Path) {
		return result, fmt.Errorf("Python loaded another runtime DLL")
	}
	candidate.Version = facts.Version
	result.Candidate = candidate
	result.Home = facts.Home
	result.Template, err = m.candidate(ctx, facts.Template, sid, true)
	if err != nil {
		return result, fmt.Errorf("unsupported CPython redirector layout: %w", err)
	}
	result.DLL, err = m.candidate(ctx, dll.Path, sid, false)
	if err != nil || result.DLL.SHA256 != dll.SHA256 || result.DLL.Identity != dll.Identity {
		return result, fmt.Errorf("Python runtime DLL changed during inspection")
	}
	result.VenvSource, err = m.candidate(ctx, facts.VenvSource, sid, false)
	if err != nil {
		return result, err
	}
	again, err := m.candidate(ctx, path, sid, true)
	if err != nil || again.SHA256 != candidate.SHA256 || again.Identity != candidate.Identity {
		return result, fmt.Errorf("Python changed during inspection")
	}
	return result, nil
}
func (nativeMachine) securePath(ctx context.Context, path, sid string, missing bool) error {
	_, err := powerShell(ctx, `Assert-Path $r.path $r.sid $r.missing; if(Test-Path -LiteralPath $r.path){Assert-Access $r.path $r.sid $true}`, map[string]any{"path": path, "sid": sid, "missing": missing})
	return err
}
func (nativeMachine) createDirectory(ctx context.Context, path, sid string) error {
	_, err := powerShell(ctx, `Assert-Path $r.path $r.sid $true
if(Test-Path -LiteralPath $r.path){throw 'Directory collision'}
if(-not (Test-Path -LiteralPath ([IO.Path]::GetDirectoryName($r.path)) -PathType Container)){throw 'Managed directory requires an existing trusted parent'}
$security=[System.Security.AccessControl.DirectorySecurity]::new()
$security.SetSecurityDescriptorSddlForm(('O:'+$r.sid+'G:'+$r.sid+'D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;'+$r.sid+')'))
[void]([System.IO.Directory]::CreateDirectory($r.path,$security))
Assert-Path $r.path $r.sid $false`, map[string]string{"path": path, "sid": sid})
	return err
}
func (nativeMachine) task(ctx context.Context, operation string, spec taskSpec) (taskObservation, error) {
	data, err := powerShell(ctx, taskScript, map[string]any{"operation": operation, "spec": spec})
	if err != nil {
		return taskObservation{}, err
	}
	var result taskObservation
	if err = strictjson.Decode(data, &result); err != nil {
		return result, err
	}
	return result, nil
}
func (nativeMachine) probe(ctx context.Context, path, state string) error {
	if _, err := os.Lstat(state); !os.IsNotExist(err) {
		return fmt.Errorf("unexpected setup probe Session state")
	}
	clean, err := cleanEnvironment()
	if err != nil {
		return err
	}
	environment := []string{}
	for _, value := range clean {
		if !strings.HasPrefix(strings.ToUpper(value), "BLENDERSESSIOND_STATE_DIR=") {
			environment = append(environment, value)
		}
	}
	environment = append(environment, "BLENDERSESSIOND_STATE_DIR="+state)
	_, err = runNative(ctx, path, []string{"capabilities", "--require", "blender-box-v1", "--require-capability", "typed-call-error-reason"}, nil, environment)
	if err != nil {
		return err
	}
	statusBytes, statusErr := runNative(ctx, path, []string{"status", "--json"}, nil, environment)
	if errors.Is(statusErr, errNativeExecutionFailed) {
		return statusErr
	}
	var sessions struct {
		SchemaVersion int               `json:"schema_version"`
		Status        string            `json:"status"`
		Message       string            `json:"message"`
		Sessions      []json.RawMessage `json:"sessions"`
	}
	var statusExit *exec.ExitError
	if err := strictjson.Decode(statusBytes, &sessions); err != nil || !errors.As(statusErr, &statusExit) || statusExit.ExitCode() != 1 || sessions.SchemaVersion != 1 || sessions.Status != "unhealthy" || sessions.Sessions == nil || len(sessions.Sessions) != 0 {
		return errors.Join(fmt.Errorf("daemon Session inactivity is unknown"), statusErr)
	}
	python := filepath.Join(filepath.Dir(path), "python", "Scripts", "python.exe")
	code := `import json,sys,site,subprocess,os,blendersessiond
assert sys.prefix != sys.base_prefix and site.ENABLE_USER_SITE is False
assert all('site-packages' not in p.lower() or os.path.normcase(os.path.abspath(p)).startswith(os.path.normcase(sys.prefix)+os.sep) for p in sys.path)
child=subprocess.run([sys.executable,'-m','blendersessiond.windows_job','--help'],capture_output=True,timeout=5)
assert child.returncode == 2 and not child.stdout and not child.stderr,child.stderr.decode()
child=subprocess.run([sys.executable,'-m','blendersessiond','capabilities','--require','blender-box-v1'],capture_output=True,timeout=5)
assert child.returncode == 0,child.stderr.decode()
print(json.dumps({'isolated':True}))`
	_, err = runNative(ctx, python, []string{"-I", "-B", "-c", code}, nil, environment)
	return err
}

const nativeFunctions = `function Assert-TrustedItem([string]$Path,[string]$Sid,[int64]$AuthorityMask=0x000d0156) {
 $item=Get-Item -Force -LiteralPath $Path -ErrorAction Stop
 if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0){throw 'Reparse path refused'}
 if($item -isnot [IO.FileInfo] -and $item -isnot [IO.DirectoryInfo]){throw 'Non-filesystem path refused'}
 $trusted=@($Sid,'S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
 $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop;$owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value;if($trusted -notcontains $owner){throw 'Untrusted path owner'}
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  if(($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0){continue}
  $mask=[int64]$rule.FileSystemRights
  if(($mask -band 0x10000000) -ne 0){$mask=$mask -bor 0x001f01ff};if(($mask -band 0x40000000) -ne 0){$mask=$mask -bor 0x00000116}
  if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and ($mask -band $AuthorityMask) -ne 0 -and $trusted -notcontains $rule.IdentityReference.Value){throw 'Untrusted path writer'}
 }
 return $item
}
function Assert-Path([string]$Path,[string]$Sid,[bool]$Missing) {
 if(-not [IO.Path]::IsPathRooted($Path) -or $Path.StartsWith('\\')){throw 'Path must use a fixed local drive'}
 $drive=[IO.DriveInfo]::new([IO.Path]::GetPathRoot($Path));if($drive.DriveType -ne [IO.DriveType]::Fixed){throw 'Path requires fixed local volume'}
 $current=$Path
 while($current){
  if(Test-Path -LiteralPath $current){
   $authorityMask=0x000d0040;if($current -ceq $Path){$authorityMask=0x000d0156}
   $null=Assert-TrustedItem $current $Sid $authorityMask
  } elseif(-not $Missing){throw 'Required path missing'}
  $parent=[IO.Directory]::GetParent($current);if($null -eq $parent){break};$current=$parent.FullName
 }
}
function Assert-Access([string]$Path,[string]$Sid,[bool]$Managed){
 $acl=Get-Acl -LiteralPath $Path
 $allowed=@($Sid);$required=0x001f01ff;if(-not $Managed){$allowed+=@('S-1-1-0','S-1-5-11','S-1-5-32-545');$required=0x001200a9}
 $allow=0;$deny=0;$inherit=$false
 foreach($rule in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
  $mask=[int64]$rule.FileSystemRights
  if(($mask -band 0x10000000) -ne 0){$mask=$mask -bor 0x001f01ff};if(($mask -band 0x80000000L) -ne 0){$mask=$mask -bor 0x00120089};if(($mask -band 0x40000000) -ne 0){$mask=$mask -bor 0x00120116};if(($mask -band 0x20000000) -ne 0){$mask=$mask -bor 0x001200a0}
  if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $rule.IdentityReference.Value -eq $Sid -and ($mask -band 0x001f01ff) -eq 0x001f01ff -and ($rule.InheritanceFlags -band 3) -eq 3){$inherit=$true}
  if(($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0){continue}
  if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny){$deny=$deny -bor $mask}
  if($rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and $allowed -contains $rule.IdentityReference.Value){$allow=$allow -bor $mask}
 }
 if(($deny -band $required) -ne 0 -or ($allow -band $required) -ne $required){throw 'Configured limited account lacks required path rights'}
 if($Managed -and (Test-Path -LiteralPath $Path -PathType Container) -and -not $inherit){throw 'Managed directory lacks direct account inheritance for files and directories'}
}
function Task-Definition($service,$s){
 $d=$service.NewTask(0);$d.RegistrationInfo.Description='Blender Box installation '+$s.installation_id;$d.RegistrationInfo.Source=$s.installation_id;$d.RegistrationInfo.Author=$s.owner_sid;$d.RegistrationInfo.URI='\'+$s.name
 $d.Principal.UserId=$s.owner_sid;$d.Principal.LogonType=3;$d.Principal.RunLevel=0
 $d.Settings.Enabled=$true;$d.Settings.MultipleInstances=2;$d.Settings.ExecutionTimeLimit='PT0S';$d.Settings.DisallowStartIfOnBatteries=$false;$d.Settings.StopIfGoingOnBatteries=$false;$d.Settings.AllowDemandStart=$true
 $a=$d.Actions.Create(0);$a.Path=$s.executable;$a.Arguments=$s.arguments;$a.WorkingDirectory=$s.directory
 return $d
}
function Task-Security($s){return ('O:'+$s.owner_sid+'G:'+$s.owner_sid+'D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;'+$s.owner_sid+')')}
function Canonical-XML($xml){
 $doc=[xml]$xml
 $lines=[System.Collections.Generic.List[string]]::new()
 function Visit-Node($node,[string]$path){
  $path=$path+'/'+$node.LocalName
  foreach($attribute in $node.Attributes){if($attribute.Name -ne 'xmlns'){$lines.Add($path+'/@'+$attribute.LocalName+'='+$attribute.Value)}}
  $children=@($node.ChildNodes | Where-Object {$_.NodeType -eq [Xml.XmlNodeType]::Element})
  if($children.Count -eq 0){$lines.Add($path+'='+$node.InnerText.Trim())}
  foreach($child in $children){Visit-Node $child $path}
 }
 Visit-Node $doc.DocumentElement ''
 return (($lines | Sort-Object) -join [char]10)
}
function Canonical-Security([string]$sddl){
 $sd=[Security.AccessControl.RawSecurityDescriptor]::new($sddl)
 if($null -eq $sd.Owner -or $null -eq $sd.Group -or $null -eq $sd.DiscretionaryAcl){throw 'Task security incomplete'}
 $aces=[System.Collections.Generic.List[string]]::new()
 foreach($ace in $sd.DiscretionaryAcl){
  if($ace -isnot [Security.AccessControl.CommonAce] -or $ace.IsCallback){throw 'Unknown task security ACE'}
  $mask=[int64]$ace.AccessMask;if(($mask -band 0x10000000) -ne 0){$mask=($mask -band (-bnot 0x10000000)) -bor 0x001f01ff}
  $aces.Add(([string][int]$ace.AceQualifier)+'/'+([int]$ace.AceFlags)+'/'+$mask+'/'+$ace.SecurityIdentifier.Value)
 }
 return ($sd.Owner.Value+'/'+$sd.Group.Value+'/'+([int]$sd.ControlFlags -band 0x1000)+'/'+(($aces|Sort-Object)-join ','))
}
function Hash-Text([string]$text){$sha=[Security.Cryptography.SHA256]::Create();try{return (($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($text))|ForEach-Object{$_.ToString('x2')}) -join '')}finally{$sha.Dispose()}}
`
const taskScript = `$s=$r.spec;$service=New-Object -ComObject 'Schedule.Service';$service.Connect();$folder=$service.GetFolder('\');$task=$null
try{$task=$folder.GetTask($s.name)}catch{if($_.Exception.HResult -ne -2147024894){throw}}
$expected=Task-Definition $service $s
$security=Task-Security $s
function Observe($task){
 if($null -eq $task){return [ordered]@{exists=$false;running=$false;matches=$false}}
 $actual=$task.Definition
 $actualXML=Canonical-XML $actual.XmlText;$expectedXML=Canonical-XML $expected.XmlText
 $actualSecurity=Canonical-Security $task.GetSecurityDescriptor(7)
 $expectedSecurity=Canonical-Security $security
 $matches=$actualXML -ceq $expectedXML -and $actualSecurity -ceq $expectedSecurity
 return [ordered]@{exists=$true;running=($task.GetInstances(0).Count -gt 0);matches=$matches;fingerprint=(Hash-Text ($actualXML+[char]10+$actualSecurity))}
}
$observed=Observe $task
if($r.operation -eq 'create'){
 if($observed.exists){throw 'Task collision'}
 $task=$folder.RegisterTaskDefinition($s.name,$expected,2,$s.owner_sid,$null,3,$security)
 $observed=Observe $task
}elseif($r.operation -eq 'delete'){
 if(-not $observed.exists -or -not $observed.matches -or $observed.running){throw 'Task deletion authority mismatch'}
 $folder.DeleteTask($s.name,0);$task=$null
 try{$task=$folder.GetTask($s.name)}catch{if($_.Exception.HResult -ne -2147024894){throw}}
 $observed=Observe $task
}elseif($r.operation -ne 'inspect'){throw 'Unknown task operation'}
$observed | ConvertTo-Json -Compress`

func (nativeMachine) target(intent installIntent) (target.Target, error) {
	for _, file := range intent.Files {
		path := filepath.Join(filepath.Dir(filepath.Dir(intent.Task.Executable)), filepath.FromSlash(file.Path))
		if !windowstarget.ValidateWindowsPath(path) {
			return target.Target{}, fmt.Errorf("planned runtime path exceeds supported Windows grammar")
		}
	}
	return target.NewWindows(intent.SSHAlias, windowstarget.Config{SSHUser: intent.WindowsUser, InteractiveUser: intent.WindowsUser, WorkRoot: intent.Root, TaskName: intent.Task.Name, BlenderExecutable: intent.Blender.Path, SessionBrokerExecutable: filepath.Join(filepath.Dir(intent.Task.Executable), "blendersessiond.exe"), HostExecutable: intent.Task.Executable})
}
