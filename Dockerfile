# syntax=docker/dockerfile:1.7
#
# AI Auditor - single-image container for cloud demo deployments (Fly.io, Render, etc.).
# Bundles the auditor + UI + OPA + an in-container Redis so only one external service
# (Postgres) is needed. Build the UI in a small Node stage and copy the artefact into the
# runtime stage so the runtime image doesn't carry Node.

# -------- stage 1: build the React UI ----------------------------------------
FROM node:20-alpine AS ui-build
WORKDIR /ui

# Copy manifest first so npm install is cached when source changes but deps don't.
COPY hitl_ui/frontend/package.json ./
COPY hitl_ui/frontend/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --no-audit --no-fund; else npm install --no-audit --no-fund; fi

COPY hitl_ui/frontend/ ./
# Production build - emits hitl_ui/frontend/dist/
RUN npm run build

# -------- stage 2: runtime ---------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

# Native deps:
#   - ca-certificates / curl: fetch the OPA binary
#   - build-essential: builds wheels that don't ship pre-built for slim
#   - redis-server: single-container Redis (sampler + tool-budget; no persistence needed)
#   - tini: PID 1 reaping for the multi-process entrypoint
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
         ca-certificates curl build-essential redis-server tini \
    && rm -rf /var/lib/apt/lists/*

# OPA static binary
ARG OPA_VERSION=v1.14.0
RUN curl -fsSL "https://openpolicyagent.org/downloads/${OPA_VERSION}/opa_linux_amd64_static" \
        -o /usr/local/bin/opa \
    && chmod +x /usr/local/bin/opa

# Source has to land before `pip install -e .` because editable mode needs to introspect the
# package layout (auditor/, harness/, etc.). This means any code change invalidates the pip layer,
# which is fine for a low-frequency demo build.
WORKDIR /app

COPY pyproject.toml alembic.ini README.md ./
COPY auditor ./auditor
COPY harness ./harness
COPY adversarial ./adversarial
COPY proto ./proto
COPY opa ./opa
COPY scripts ./scripts

# Editable install picks up the package plus the [gate, harness, embeddings-local] extras
RUN pip install -e ".[gate,harness,embeddings-local]"

# spaCy English model needed by Presidio's NER recognizer
RUN python -m spacy download en_core_web_sm

# Demo sandbox files (data/) are intentionally NOT copied here - they are gitignored on the host
# and the entrypoint writes them fresh on every container boot so the demo prompts stay
# reproducible across deploys.

# Pre-built UI from the Node stage. The auditor mounts this directory as static at "/".
COPY --from=ui-build /ui/dist ./hitl_ui/frontend/dist

# Cloud entrypoint - starts redis + opa, waits for Postgres, migrates + seeds, exec-s uvicorn.
COPY scripts/cloud/start.sh /start.sh
RUN chmod +x /start.sh

# Cloud-safe defaults; override via env vars / Fly secrets.
ENV API_HOST=0.0.0.0 \
    API_PORT=8000 \
    OPA_URL=http://127.0.0.1:8181 \
    REDIS_URL=redis://127.0.0.1:6379/0 \
    IPC_MTLS_ENABLED=false \
    GATE_TIMEOUT_MS=500 \
    LOG_LEVEL=INFO

EXPOSE 8000

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/start.sh"]
