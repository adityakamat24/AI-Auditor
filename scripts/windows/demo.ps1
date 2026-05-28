#requires -Version 5.1
# End-to-end Phase 2 demo: services -> migrate/seed -> CA -> auditor (mTLS) -> /health
#   -> harness scripted run (ALLOW kb_search + create_ticket, DENY exec_shell over mTLS)
#   -> adversarial runner --demo (ASI02 loop DENY, ASI05 exec_shell DENY).
$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $root
$py = ".\.venv\Scripts\python.exe"
if (-not (Test-Path $py)) { Write-Error "venv missing - run: .\make.ps1 bootstrap"; exit 1 }
if (-not (Test-Path ".env")) { Copy-Item .env.example .env }

Write-Host "==> ensuring Docker backing services"
docker info *> $null
if ($LASTEXITCODE -ne 0) { Write-Error "Docker daemon not running. Start Docker Desktop."; exit 1 }
docker compose up -d postgres redis minio opa | Out-Null
$pgid = (docker compose ps -q postgres)
for ($i = 0; $i -lt 60; $i++) {
    if ((docker inspect -f '{{.State.Health.Status}}' $pgid 2>$null) -eq "healthy") { break }
    Start-Sleep -Seconds 1
}

Write-Host "==> migrate + seed"
& $py -m alembic upgrade head
& $py scripts\seed_demo.py

Write-Host "==> mTLS CA"
& $py -m auditor.auth.init_ca
$env:IPC_MTLS_ENABLED = "true"   # auditor + harness child processes inherit this
$env:GATE_TIMEOUT_MS = "500"     # tolerate the cold first OPA call over Docker-Desktop on Windows

& "$PSScriptRoot\stop.ps1" | Out-Null
New-Item -ItemType Directory -Force .run | Out-Null
Write-Host "==> starting auditor (native, mTLS, detached)"
$auditorArgs = @("-m", "uvicorn", "auditor.main:app", "--host", "127.0.0.1", "--port", "8000")
$proc = Start-Process -FilePath $py -ArgumentList $auditorArgs -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput ".run\auditor.out.log" -RedirectStandardError ".run\auditor.err.log"
$proc.Id | Out-File -Encoding ascii ".run\auditor.pid"

Write-Host "==> waiting for /health"
$ok = $false
for ($i = 0; $i -lt 60; $i++) {
    Start-Sleep -Seconds 1
    if ((& curl.exe -s -o NUL -w "%{http_code}" http://127.0.0.1:8000/health) -eq "200") { $ok = $true; break }
}
if ($ok) { Write-Host "   /health GREEN" -ForegroundColor Green } else { Write-Warning "/health not green - see .run\auditor.err.log" }

Write-Host "==> minting harness mTLS cert"
foreach ($line in (& $py scripts\mint_harness_cert.py)) {
    if ($line -match '^(HARNESS_\w+)=(.+)$') { Set-Item -Path "env:$($matches[1])" -Value $matches[2] }
}

Write-Host "==> harness scripted run (gated tool calls over mTLS)"
& $py -m harness.main
Write-Host "   harness exit: $LASTEXITCODE"

Write-Host "==> adversarial attacks (expect DENY)"
& $py -m adversarial.runner --demo

Write-Host "==> async pipeline: attack -> CRITICAL flag -> incident -> audit-log review (headless)"
& $py scripts\demo_review_flow.py

Write-Host ""
Write-Host "Auditor running at http://localhost:8000  (PID $($proc.Id))  [mTLS IPC on :8787]"
Write-Host "   HITL UI: cd hitl_ui\frontend; npm install; npm run dev  (review the flag/incident above)"
Write-Host "   endpoints: /health  /healthz/live  /metrics"
Write-Host "Stop with: .\make.ps1 stop"
