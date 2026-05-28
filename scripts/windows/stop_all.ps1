#requires -Version 5.1
# Stop both the auditor and the UI dev server started by start_all.ps1.
$ErrorActionPreference = "Continue"
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $root

function Stop-Pid([string]$label, [string]$pidFile) {
    if (-not (Test-Path $pidFile)) { Write-Host "$label : no pid file (skipped)"; return }
    $procId = (Get-Content $pidFile -Raw).Trim()  # $pid is a PowerShell automatic var — don't reuse it
    if (-not $procId) { Remove-Item $pidFile -Force; return }
    try {
        # Kill the whole process tree (npm spawns node + esbuild children; uvicorn may spawn workers).
        taskkill /F /T /PID $procId 2>$null | Out-Null
        Write-Host "$label : stopped (PID $procId)" -ForegroundColor Green
    } catch {
        Write-Host "$label : already gone (PID $procId)" -ForegroundColor Gray
    }
    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
}

Stop-Pid "auditor" ".run\auditor.pid"
Stop-Pid "ui"      ".run\ui.pid"
