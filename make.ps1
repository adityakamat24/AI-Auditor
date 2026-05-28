#!/usr/bin/env pwsh
# AI Auditor task runner for Windows (mirrors the Makefile). Usage:  .\make.ps1 <target>
param([Parameter(Position = 0)][string]$Target = "help")
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = ".\.venv\Scripts\python.exe"

function Require-Venv {
    if (-not (Test-Path $py)) { Write-Error "venv missing - run: .\make.ps1 bootstrap"; exit 1 }
}

switch ($Target) {
    "bootstrap" { & "$PSScriptRoot\scripts\windows\bootstrap.ps1" }
    "init" { & "$PSScriptRoot\scripts\windows\init.ps1" }
    "demo" { & "$PSScriptRoot\scripts\windows\demo.ps1" }
    "stop" { & "$PSScriptRoot\scripts\windows\stop.ps1" }
    "up" { docker compose up -d postgres redis minio opa }
    "down" { docker compose down }
    "clean" { & "$PSScriptRoot\scripts\windows\stop.ps1"; docker compose down -v }
    "migrate" { Require-Venv; & $py -m alembic upgrade head }
    "seed" { Require-Venv; & $py scripts\seed_demo.py }
    "proto" { Require-Venv; & $py scripts\gen_proto.py }
    "test" { Require-Venv; & $py -m pytest tests/unit -q }
    "lint" { Require-Venv; & $py -m ruff check auditor harness tests scripts }
    "fmt" { Require-Venv; & $py -m ruff check --fix auditor harness tests scripts }
    default {
        @"
AI Auditor - make.ps1 targets
  bootstrap   create venv, install deps, start Docker services
  init        wait for DB, run migrations, seed demo data
  demo        end-to-end: services + migrate + seed + auditor + harness
  stop        stop the detached auditor
  up / down   start / stop Docker backing services
  migrate     alembic upgrade head
  seed        seed demo tenant + admin
  proto       regenerate protobuf bindings
  test        run unit tests
  lint / fmt  ruff check / --fix
  clean       stop auditor + docker compose down -v
"@
    }
}
