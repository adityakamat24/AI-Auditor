#!/usr/bin/env bash
# End-to-end Phase 2 demo: services -> migrate/seed -> CA -> auditor (mTLS) -> /health
#   -> harness scripted run (ALLOW kb_search + create_ticket, DENY exec_shell over mTLS)
#   -> adversarial runner --demo (ASI02 loop DENY, ASI05 exec_shell DENY).
set -euo pipefail
cd "$(dirname "$0")/../.."
[ -f .env ] || cp .env.example .env
PY=.venv/bin/python

echo "==> ensuring Docker backing services"
docker info >/dev/null 2>&1 || { echo "Docker daemon not running."; exit 1; }
docker compose up -d postgres redis minio opa >/dev/null
pgid=$(docker compose ps -q postgres)
for _ in $(seq 1 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$pgid" 2>/dev/null || true)" = "healthy" ] && break
  sleep 1
done

echo "==> migrate + seed"
"$PY" -m alembic upgrade head
"$PY" scripts/seed_demo.py

echo "==> mTLS CA"
"$PY" -m auditor.auth.init_ca
export IPC_MTLS_ENABLED=true
export GATE_TIMEOUT_MS=500

mkdir -p .run
[ -f .run/auditor.pid ] && kill "$(cat .run/auditor.pid)" 2>/dev/null || true

echo "==> starting auditor (native, mTLS, detached)"
"$PY" -m uvicorn auditor.main:app --host 127.0.0.1 --port 8000 \
  >.run/auditor.out.log 2>.run/auditor.err.log &
echo $! >.run/auditor.pid

echo "==> waiting for /health"
ok=false
for _ in $(seq 1 60); do
  sleep 1
  [ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/health || true)" = "200" ] && { ok=true; break; }
done
$ok && echo "   /health GREEN" || echo "   /health not green - see .run/auditor.err.log"

echo "==> minting harness mTLS cert"
while IFS= read -r line; do export "${line?}"; done < <("$PY" scripts/mint_harness_cert.py)

echo "==> harness scripted run (gated tool calls over mTLS)"
"$PY" -m harness.main || true

echo "==> adversarial attacks (expect DENY)"
"$PY" -m adversarial.runner --demo || true

echo "==> async pipeline: attack -> CRITICAL flag -> incident -> audit-log review (headless)"
"$PY" scripts/demo_review_flow.py || true

echo ""
echo "Auditor running at http://localhost:8000 (PID $(cat .run/auditor.pid))  [mTLS IPC on :8787]"
echo "   HITL UI: cd hitl_ui/frontend && npm install && npm run dev  (review the flag/incident above)"
echo "Stop with: make stop"
