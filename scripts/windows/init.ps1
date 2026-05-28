#requires -Version 5.1
# Wait for Postgres, run migrations, seed demo data.
$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $root
$py = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { Write-Error "venv missing - run: .\make.ps1 bootstrap"; exit 1 }
if (-not (Test-Path ".env")) { Copy-Item .env.example .env }

Write-Host "==> waiting for postgres to be healthy"
$pgid = (docker compose ps -q postgres)
if (-not $pgid) { Write-Error "postgres not running - run: .\make.ps1 up"; exit 1 }
for ($i = 0; $i -lt 60; $i++) {
    if ((docker inspect -f '{{.State.Health.Status}}' $pgid 2>$null) -eq "healthy") { break }
    Start-Sleep -Seconds 1
}

Write-Host "==> alembic upgrade head"
& $py -m alembic upgrade head

Write-Host "==> seed demo data"
& $py scripts\seed_demo.py

Write-Host "init complete. Next: .\make.ps1 demo"
