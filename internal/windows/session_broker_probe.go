package windows

const sessionBrokerProbeFunctions = `function Stop-SessionBrokerProbe([System.Diagnostics.Process]$Process) {
    try {
        if (-not $Process.HasExited) { $Process.Kill() }
    } catch {}
    try { [void]$Process.WaitForExit(1000) } catch {}
}
function Invoke-SessionBrokerProbe([string]$Path, [string[]]$Arguments) {
    $process = $null
    try {
        $process = Start-Process -FilePath $Path -ArgumentList $Arguments -RedirectStandardOutput 'NUL' -RedirectStandardError '\\.\NUL' -NoNewWindow -PassThru
        $null = $process.Handle
        if (-not $process.WaitForExit(10000)) {
            Stop-SessionBrokerProbe $process
            return $null
        }
        return [int]$process.ExitCode
    } catch {
        if ($null -ne $process) { Stop-SessionBrokerProbe $process }
        return $null
    } finally {
        if ($null -ne $process) { $process.Dispose() }
    }
}
`
