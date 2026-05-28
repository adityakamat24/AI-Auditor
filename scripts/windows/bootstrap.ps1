#requires -Version 5.1
# One-time setup: Python venv + deps + Docker backing services.
$ErrorActionPreference = "Stop"
$root = (Resolve-Path "$PSScriptRoot\..\..").Path
Set-Location $root

Write-Host "==> [1/4] Python venv (3.12)"
if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    if (Get-Command py -ErrorAction SilentlyContinue) { py -3.12 -m venv .venv } else { python -m venv .venv }
}
$py = ".\.venv\Scripts\python.exe"

Write-Host "==> [2/5] install deps (editable + extras: dev, gate, harness, embeddings-local)"
& $py -m pip install --upgrade pip | Out-Null
& $py -m pip install -e ".[dev,gate,harness,embeddings-local]"

Write-Host "==> [3/5] spaCy model for Presidio NER (en_core_web_sm)"
& $py -m spacy download en_core_web_sm

Write-Host "==> [4/5] .env"
if (-not (Test-Path ".env")) { Copy-Item .env.example .env; Write-Host "   created .env from .env.example" }

Write-Host "==> [5/5] Docker backing services"
docker info *> $null
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Docker daemon not running. Start Docker Desktop, then re-run: .\make.ps1 bootstrap"
    exit 1
}
docker compose up -d postgres redis minio opa

Write-Host "bootstrap complete. Next: .\make.ps1 init"
