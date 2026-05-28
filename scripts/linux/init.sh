#!/usr/bin/env bash
# Wait for Postgres, run migrations, seed demo data.
set -euo pipefail
cd "$(dirname "$0")/../.."
[ -f .env ] || cp .env.example .env

echo "==> waiting for postgres to be healthy"
pgid=$(docker compose ps -q postgres)
[ -n "$pgid" ] || { echo "postgres not running - run: make up"; exit 1; }
for _ in $(seq 1 60); do
  st=$(docker inspect -f '{{.State.Health.Status}}' "$pgid" 2>/dev/null || true)
  [ "$st" = "healthy" ] && break
  sleep 1
done

echo "==> alembic upgrade head"
.venv/bin/python -m alembic upgrade head

echo "==> seed demo data"
.venv/bin/python scripts/seed_demo.py

echo "init complete. Next: make demo"
