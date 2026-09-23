//go:build windows

package windowsinstall

import (
	"context"
	"fmt"
	"time"
)

func auditPython(ctx context.Context, home, sid string) error {
	_, err := powerShellWithTimeout(ctx, pythonTrustFunctions+`Assert-PythonTree $r.home $r.sid`, map[string]string{"home": home, "sid": sid}, 45*time.Second)
	if err != nil {
		return fmt.Errorf("Python runtime trust audit: %w", err)
	}
	return nil
}

const pythonTrustFunctions = `function Assert-AbsentPythonMarker([string]$Path,[string]$Sid) {
 if(Test-Path -LiteralPath $Path -ErrorAction Stop){throw 'Python startup redirector or build marker refused'}
 $parent=[IO.Path]::GetDirectoryName($Path)
 while(-not (Test-Path -LiteralPath $parent -ErrorAction Stop)){
  $next=[IO.Path]::GetDirectoryName($parent);if(-not $next -or $next -eq $parent){throw 'Python marker parent missing'};$parent=$next
 }
 Assert-Path $parent $Sid $false
}
function Assert-PythonTree([string]$PythonHome,[string]$Sid,[int]$MaxEntries=32768,[int]$MaxDepth=64,[int]$TimeoutMilliseconds=40000) {
 $watch=[Diagnostics.Stopwatch]::StartNew()
 Assert-Path $PythonHome $Sid $false
 foreach($marker in @('pyvenv.cfg','..\pyvenv.cfg','pybuilddir.txt','..\..\Modules\Setup.local','..\..\..\Modules\Setup.local')){
  Assert-AbsentPythonMarker ([IO.Path]::GetFullPath((Join-Path $PythonHome $marker))) $Sid
 }
 $lib=Join-Path $PythonHome 'Lib';$dlls=Join-Path $PythonHome 'DLLs';$os=Join-Path $lib 'os.py'
 if(-not (Test-Path -LiteralPath $lib -PathType Container) -or -not (Test-Path -LiteralPath $dlls -PathType Container) -or -not (Test-Path -LiteralPath $os -PathType Leaf)){throw 'Unsupported Python standard library layout'}
 $excluded=Join-Path $lib 'site-packages'
 $stack=[Collections.Generic.Stack[object]]::new()
 $count=1
 try{
  $stack.Push([Tuple[Collections.IEnumerator,int]]::new([IO.Directory]::EnumerateFileSystemEntries($PythonHome).GetEnumerator(),0))
  while($stack.Count -gt 0){
   if($watch.ElapsedMilliseconds -ge $TimeoutMilliseconds){throw 'Python trust audit deadline exceeded'}
   $frame=$stack.Peek()
   if(-not $frame.Item1.MoveNext()){([IDisposable]$frame.Item1).Dispose();$null=$stack.Pop();continue}
   $count++;if($count -gt $MaxEntries){throw 'Python trust audit entry bound exceeded'}
   $path=[string]$frame.Item1.Current
   $item=Assert-TrustedItem $path $Sid
   if($frame.Item2 -eq 0 -and $item.Name.EndsWith('._pth',[StringComparison]::OrdinalIgnoreCase)){throw 'Python startup redirector refused'}
   if($item -is [IO.DirectoryInfo]){
    if([string]::Equals($path,$excluded,[StringComparison]::OrdinalIgnoreCase)){continue}
    $depth=$frame.Item2+1;if($depth -gt $MaxDepth){throw 'Python trust audit depth bound exceeded'}
    $stack.Push([Tuple[Collections.IEnumerator,int]]::new([IO.Directory]::EnumerateFileSystemEntries($path).GetEnumerator(),$depth))
   }
  }
 }finally{while($stack.Count -gt 0){$frame=$stack.Pop();([IDisposable]$frame.Item1).Dispose()}}
}
`
