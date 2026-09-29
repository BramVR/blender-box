//go:build windows

package windowsinstall

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BramVR/blender-box/internal/pairing"
	"github.com/BramVR/blender-box/internal/privatefile"
	"github.com/BramVR/blender-box/internal/sshkey"
	"github.com/BramVR/blender-box/internal/strictjson"
	"github.com/BramVR/blender-box/internal/windowstarget"
)

type nativeSSHD struct{}
type nativeKeys struct{}

func adminKeysFile() string {
	if programData := os.Getenv("ProgramData"); windowstarget.ValidateWindowsPath(programData) {
		return filepath.Join(programData, "ssh", "administrators_authorized_keys")
	}
	return defaultAdminKeysFile
}

// facts gathers raw sshd facts in one elevated PowerShell process and leaves every decision to Go.
// An unelevated caller gets Elevated false and nothing else, because sshd -T cannot read the host
// keys without elevation.
func (nativeSSHD) facts(ctx context.Context, account, host, addr string) (sshdFacts, error) {
	for _, value := range []string{account, host, addr} {
		if value == "" || strings.ContainsAny(value, ",=\"' \t\r\n") {
			return sshdFacts{}, fmt.Errorf("invalid sshd connection spec")
		}
	}
	output, err := powerShellWithTimeout(ctx, sshdFactsScript, map[string]string{"user": account, "host": host, "addr": addr}, 60*time.Second)
	if err != nil {
		return sshdFacts{}, err
	}
	var raw struct {
		Elevated    bool   `json:"elevated"`
		Status      string `json:"status"`
		StartType   string `json:"start_type"`
		Config      string `json:"sshd_t"`
		Profile     string `json:"profile"`
		ProgramData string `json:"program_data"`
	}
	if err := strictjson.Decode(output, &raw); err != nil {
		return sshdFacts{}, err
	}
	if !raw.Elevated {
		return sshdFacts{}, nil
	}
	config, err := parseSSHDT(raw.Config)
	if err != nil {
		return sshdFacts{}, err
	}
	if raw.Profile == "" {
		return sshdFacts{}, fmt.Errorf("account %s has no local profile; sign in to the desktop once", account)
	}
	keysFile, err := expandAuthorizedKeys(config.AuthorizedKeysFile, account, raw.Profile, raw.ProgramData)
	if err != nil {
		return sshdFacts{}, err
	}
	hostKey, err := expandAuthorizedKeys(config.HostKey, account, raw.Profile, raw.ProgramData)
	if err != nil {
		return sshdFacts{}, fmt.Errorf("sshd ed25519 host key path: %w", err)
	}
	public, err := privatefile.ReadSource(hostKey+".pub", 16<<10)
	if err != nil {
		return sshdFacts{}, fmt.Errorf("sshd ed25519 host public key: %w", err)
	}
	fields := strings.Fields(strings.SplitN(string(public), "\n", 2)[0])
	if len(fields) < 2 {
		return sshdFacts{}, fmt.Errorf("sshd ed25519 host public key is malformed")
	}
	canonical, err := sshkey.CanonicalPublicKey(fields[0] + " " + fields[1])
	if err != nil {
		return sshdFacts{}, fmt.Errorf("sshd ed25519 host public key: %w", err)
	}
	return sshdFacts{ServiceStatus: raw.Status, StartType: raw.StartType, Port: config.Port, PubkeyAuthentication: config.PubkeyAuthentication, AuthorizedKeysFile: keysFile, HostKeyEd25519: canonical, Elevated: true}, nil
}

const sshdFactsScript = `$identity=[Security.Principal.WindowsIdentity]::GetCurrent()
$elevated=[Security.Principal.WindowsPrincipal]::new($identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if(-not $elevated){[ordered]@{elevated=$false}|ConvertTo-Json -Compress;exit 0}
$service=Get-Service -Name sshd -ErrorAction Stop
$command=[string](Get-CimInstance -ClassName Win32_Service -Filter "Name='sshd'").PathName
$sshd=$command.Trim()
if($sshd.StartsWith('"')){$sshd=$sshd.Substring(1,$sshd.IndexOf('"',1)-1)}
if(-not (Test-Path -LiteralPath $sshd -PathType Leaf)){throw ('sshd executable missing: '+$sshd)}
$start=[Diagnostics.ProcessStartInfo]::new($sshd)
$start.Arguments='-T -C user='+$r.user+',host='+$r.host+',addr='+$r.addr
$start.UseShellExecute=$false;$start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true;$start.CreateNoWindow=$true
$process=[Diagnostics.Process]::Start($start)
$stderr=$process.StandardError.ReadToEndAsync()
$config=$process.StandardOutput.ReadToEnd()
$process.WaitForExit()
if($process.ExitCode -ne 0){throw ('sshd -T failed: '+$stderr.Result.Trim())}
$sid=([Security.Principal.NTAccount]::new($r.user)).Translate([Security.Principal.SecurityIdentifier]).Value
$localPath=[string](Get-CimInstance -ClassName Win32_UserProfile -Filter ("SID='"+$sid+"'")).LocalPath
[ordered]@{elevated=$true;status=[string]$service.Status;start_type=[string]$service.StartType;sshd_t=$config;profile=$localPath;program_data=$env:ProgramData}|ConvertTo-Json -Compress`

func (nativeKeys) read(ctx context.Context, path string) (keysObservation, error) {
	if !windowstarget.ValidateWindowsPath(path) {
		return keysObservation{}, fmt.Errorf("unsafe authorized keys path")
	}
	output, err := powerShell(ctx, keysFunctions+`if(-not (Test-Path -LiteralPath $r.path)){[ordered]@{exists=$false}|ConvertTo-Json -Compress;exit 0}
(Observe-Keys $r.path $r.limit)|ConvertTo-Json -Compress`, map[string]any{"path": path, "limit": pairing.MaxKeysFile})
	if err != nil {
		return keysObservation{}, err
	}
	var observed keysObservation
	if err := strictjson.Decode(output, &observed); err != nil {
		return keysObservation{}, err
	}
	if observed.Exists && observed.Regular && !observed.Reparse && observed.Size <= pairing.MaxKeysFile {
		if observed.Bytes, err = privatefile.ReadSource(path, pairing.MaxKeysFile); err != nil {
			return keysObservation{}, err
		}
	}
	return observed, nil
}

// replace checks, writes and verifies in one PowerShell process. The temp file is created with
// its final descriptor, then swapped in with ReplaceFile, which also carries the replaced file's
// DACL onto the replacement. ReplaceFile gets a backup name because without one a failed rename
// can leave no file at the path, and a retry would then create an admin file holding only the
// pairing line; with a backup the original is moved back. A compare failure is reported through
// the KEYS_CHANGED marker.
func (nativeKeys) replace(ctx context.Context, r keysReplacement) (keysObservation, error) {
	if !windowstarget.ValidateWindowsPath(r.Path) {
		return keysObservation{}, fmt.Errorf("unsafe authorized keys path")
	}
	if r.Contents == nil {
		r.Contents = []byte{}
	}
	output, err := powerShellWithTimeout(ctx, keysFunctions+keysReplaceScript, r, 60*time.Second)
	if err != nil {
		if strings.Contains(err.Error(), "KEYS_CHANGED:") {
			return keysObservation{}, fmt.Errorf("%w: %v", pairing.ErrKeysChanged, err)
		}
		return keysObservation{}, err
	}
	var observed keysObservation
	if err := strictjson.Decode(output, &observed); err != nil {
		return keysObservation{}, err
	}
	return observed, nil
}

const keysFunctions = `function Hash-Bytes([byte[]]$bytes){if($null -eq $bytes){$bytes=[byte[]]::new(0)};$sha=[Security.Cryptography.SHA256]::Create();try{return (($sha.ComputeHash($bytes)|ForEach-Object{$_.ToString('x2')}) -join '')}finally{$sha.Dispose()}}
function Observe-Keys([string]$Path,[int64]$Limit){
 $item=Get-Item -Force -LiteralPath $Path -ErrorAction Stop
 $out=[ordered]@{exists=$true;reparse=(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0);regular=($item -is [IO.FileInfo]);size=0;sha='';sddl='';canonical='';owner=''}
 if($out.reparse -or -not $out.regular){return $out}
 $acl=Get-Acl -LiteralPath $Path -ErrorAction Stop
 $out.size=$item.Length;$out.sddl=$acl.Sddl;$out.canonical=Canonical-Security $acl.Sddl;$out.owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
 if($item.Length -le $Limit){$out.sha=Hash-Bytes ([IO.File]::ReadAllBytes($Path))}
 return $out
}
`
const keysReplaceScript = `$path=$r.path
$exists=Test-Path -LiteralPath $path
if($exists -ne [bool]$r.exists){throw 'KEYS_CHANGED: keys file presence changed'}
$security=[Security.AccessControl.FileSecurity]::new()
if($exists){
 $before=Observe-Keys $path ([int64]::MaxValue)
 if($before.reparse -or -not $before.regular){throw 'keys path is not a regular file'}
 if($before.canonical -cne $r.expected_security){throw 'KEYS_CHANGED: keys file security changed'}
 if($before.sha -cne $r.expected_sha){throw 'KEYS_CHANGED: keys file bytes changed'}
 $security.SetSecurityDescriptorSddlForm($before.sddl)
}else{
 $left=@(Get-ChildItem -Force -LiteralPath ([IO.Path]::GetDirectoryName($path)) -Filter '.blender-box-*.bak' -ErrorAction Stop)
 if($left.Count -gt 0){throw ('an interrupted keys-file replace left '+$left[0].FullName+'; restore it as '+$path+' before pairing')}
 $security.SetSecurityDescriptorSddlForm($r.new_security)
}
$bytes=[Convert]::FromBase64String($r.contents_b64)
$name='.blender-box-'+[guid]::NewGuid().ToString('N')
$tmp=Join-Path ([IO.Path]::GetDirectoryName($path)) ($name+'.tmp')
$bak=Join-Path ([IO.Path]::GetDirectoryName($path)) ($name+'.bak')
try{
 $stream=[IO.FileStream]::new($tmp,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::FullControl,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough,$security)
 try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
 if($exists){
  try{[IO.File]::Replace($tmp,$path,$bak)}catch{
   if(-not (Test-Path -LiteralPath $path) -and (Test-Path -LiteralPath $bak)){[IO.File]::Move($bak,$path)}
   throw ('keys-file replace failed; original kept at '+$path+' or '+$bak+': '+$_.Exception.Message)
  }
  Remove-Item -LiteralPath $bak -Force
 }else{[IO.File]::Move($tmp,$path)}
}finally{if(Test-Path -LiteralPath $tmp){Remove-Item -LiteralPath $tmp -Force}}
(Observe-Keys $path ([int64]::MaxValue))|ConvertTo-Json -Compress`
