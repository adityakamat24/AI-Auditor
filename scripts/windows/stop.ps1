#requires -Version 5.1
# Stop the detached auditor started by demo.ps1.
$ErrorActionPreference = "SilentlyContinue"
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $root
$pidFile = ".run\auditor.pid"
if (Test-Path $pidFile) {
    $auditorPid = (Get-Content $pidFile | Select-Object -First 1)
    if ($auditorPid) {
        Stop-Process -Id ([int]$auditorPid) -Force -ErrorAction SilentlyContinue
        Write-Host "stopped auditor (PID $auditorPid)"
    }
    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
}
else {
    Write-Host "no auditor pid file (.run\auditor.pid)"
}
