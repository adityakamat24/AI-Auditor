# AI Auditor task runner (Linux/macOS). On Windows use:  .\make.ps1 <target>
PY := .venv/bin/python
.DEFAULT_GOAL := help

.PHONY: help bootstrap init demo stop up down migrate seed proto test lint fmt clean

help:
	@echo "targets: bootstrap init demo stop up down migrate seed proto test lint fmt clean"

bootstrap:
	@bash scripts/linux/bootstrap.sh

init:
	@bash scripts/linux/init.sh

demo:
	@bash scripts/linux/demo.sh

stop:
	@if [ -f .run/auditor.pid ]; then kill `cat .run/auditor.pid` 2>/dev/null || true; rm -f .run/auditor.pid; echo "stopped auditor"; else echo "no auditor pid file"; fi

up:
	docker compose up -d postgres redis minio opa

down:
	docker compose down

migrate:
	$(PY) -m alembic upgrade head

seed:
	$(PY) scripts/seed_demo.py

proto:
	$(PY) scripts/gen_proto.py

test:
	$(PY) -m pytest tests/unit -q

lint:
	$(PY) -m ruff check auditor harness tests scripts

fmt:
	$(PY) -m ruff check --fix auditor harness tests scripts

clean: stop
	docker compose down -v
