#!/usr/bin/env bash
# One-time setup: Python venv + deps + Docker backing services.
set -euo pipefail
cd "$(dirname "$0")/../.."

echo "==> [1/4] Python venv (3.12)"
if [ ! -x .venv/bin/python ]; then
  if command -v python3.12 >/dev/null 2>&1; then python3.12 -m venv .venv; else python3 -m venv .venv; fi
fi

echo "==> [2/5] install deps (editable + extras: dev, gate, harness, embeddings-local)"
.venv/bin/python -m pip install --upgrade pip >/dev/null
.venv/bin/python -m pip install -e ".[dev,gate,harness,embeddings-local]"

echo "==> [3/5] spaCy model for Presidio NER (en_core_web_sm)"
.venv/bin/python -m spacy download en_core_web_sm

echo "==> [4/5] .env"
[ -f .env ] || { cp .env.example .env; echo "   created .env from .env.example"; }

echo "==> [5/5] Docker backing services"
docker info >/dev/null 2>&1 || { echo "Docker daemon not running. Start it, then re-run."; exit 1; }
docker compose up -d postgres redis minio opa

echo "bootstrap complete. Next: make init"
