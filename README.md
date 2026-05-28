# AI Auditor for Agent Sandbox

A runtime security auditor for autonomous AI agents. The auditor runs as a separate OS process alongside a low-trust agent harness on the same machine, using **dual-channel telemetry** - voluntary SDK events from the harness combined with involuntary kernel-level observation (Sysmon on Windows, eBPF on Linux) - to detect attacks the harness itself might try to hide.

**What it does:**
- Gates every tool call inline (OPA policy engine + Presidio PII scanner + Redis tool-budget + channel-divergence check), targeting p99 < 5 ms.
- Samples runs with stratified + adaptive policy and fans the trace through ten ASI-category detectors concurrently, each backed by a calibrated LLM judge (Claude Haiku via LiteLLM, with a deterministic offline stub when no API key is present).
- Routes flags by severity through a Human-in-the-Loop system: critical flags pause the harness process and queue for review; high flags queue without pausing; medium flags aggregate to a digest.
- Maintains a hash-chained audit log (tamper-evident via sha256 linking), multi-tenant row-level security, and a nightly calibration job that auto-disables a detector's blocking authority if its precision drops below 0.85.

Coverage maps to the **OWASP ASI Top 10 (2026)**. All ten categories have at least one production detector.

**Status:** all eight build phases complete and verified on Windows (Python 3.12).

---

## Architecture (brief)

```
Harness process                    Auditor process
   Telemetry SDK ──VOL──►  Event Receiver  ──►  Async Pipeline
   (tool calls,             (correlates          (Sampler → 10 ASI Detectors
    LLM calls,               VOL + INVOL)         → LLM Judge → Aggregator)
    memory ops)                   │                      │
                                  ▼                      ▼
Kernel / Sysmon ──INVOL──►  Inline Gate ◄──   HITL Router + Audit Log
   (openat, connect,         (OPA + Presidio    (severity-tiered review,
    execve, DnsQuery)         + budget +         hash chain, MinIO blobs)
                              divergence)
```

Two independent channels observe the harness. When the voluntary report diverges from what the kernel actually saw, that divergence is itself the highest-confidence security signal.

---

## Prerequisites

| Requirement | Notes |
|---|---|
| Python 3.12 | Exactly 3.12 - `requires-python = ">=3.12,<3.13"` |
| Docker Desktop | Running. Provides Postgres, Redis, MinIO, OPA. |
| Node 20+ | For the HITL React UI (`hitl_ui/frontend`). `start.bat` runs `npm install` on first launch. |
| Git | Standard |
| Sysmon (Windows, optional) | One-time admin install for the involuntary telemetry channel. Not required to run the demo. |
| `ANTHROPIC_API_KEY` (optional) | For the live LLM judge. Without it the system uses a deterministic offline stub. |

---

## Quick Start

### Windows (native - primary dev target)

**First time on this machine** - one command does everything (venv + deps + Docker services + migrations + seed):

```bat
.\setup.bat
```

**Every other launch** - opens the auditor (port 8000) and the React UI (port 5173) in two console windows and opens your browser:

```bat
.\start.bat
```

Close those two windows or run `.\stop.bat` to shut everything down. Run `.\reset.bat` (or click "Reset session data" in `/settings`) to wipe per-run flags / incidents / runs without restarting.

#### Manual / advanced

`setup.bat` is `make.ps1 bootstrap` + `make.ps1 init` chained - if you want to run the steps individually:

```powershell
.\make.ps1 bootstrap   # venv + Python/Node deps + Docker backing services
.\make.ps1 init        # wait for Postgres, alembic upgrade head, seed demo data
.\make.ps1 demo        # headless: auditor + harness + adversarial runner (no UI)
.\make.ps1 stop        # stop the detached auditor
```

### Linux / macOS (native)

```bash
make bootstrap && make init && make demo
```

The HITL UI:

```bash
cd hitl_ui/frontend && npm install && npm run dev
```

### Docker (backing services only - auditor and harness always run natively)

The auditor and harness run natively on the host; only the stateful services run in Docker. This is the only supported topology.

```bash
# Start backing services
docker compose up -d postgres redis minio opa

# Optional: LLM judge (needs ANTHROPIC_API_KEY in .env)
docker compose --profile judge up -d litellm

# Optional: observability stack (Prometheus + Grafana + OTel collector)
docker compose --profile observability up -d
```

Grafana is at `http://localhost:3000` (admin / admin). Prometheus at `http://localhost:9090`.

---

## Cloud demo (Fly.io)

For a public live demo where a stakeholder can click around the UI themselves, the repo ships a single-image Fly.io deployment. One Docker container bundles the auditor + UI + OPA + an in-container Redis; an external Fly Postgres holds state. UI is served same-origin from the auditor on `:8000` so there is no CORS coordination and no separate static host.

**Prerequisites**

- Fly.io account, [`fly` CLI](https://fly.io/docs/flyctl/install/) installed and authenticated (`fly auth login`).
- Docker installed locally (Fly's remote builder is also fine - it builds in the cloud).

**One-time setup**

```bash
# 1. Provision the app (accept the existing fly.toml; do NOT auto-deploy yet)
fly launch --copy-config --no-deploy --name ai-auditor

# 2. Managed Postgres + attach it (fly populates DATABASE_URL on the app)
fly postgres create --name ai-auditor-db --region ord --vm-size shared-cpu-1x --volume-size 1
fly postgres attach ai-auditor-db --app ai-auditor

# 3. Convert DATABASE_URL to the asyncpg DSN the auditor expects, and set a JWT secret
fly ssh console -a ai-auditor -C "printenv DATABASE_URL"   # copy the value
# Replace `postgres://` with `postgresql+asyncpg://` and set as POSTGRES_DSN:
fly secrets set -a ai-auditor POSTGRES_DSN="postgresql+asyncpg://<...>"
fly secrets set -a ai-auditor JWT_SECRET="$(openssl rand -hex 32)"

# 4. (Optional) live LLM judge - omit to use the deterministic offline stub
fly secrets set -a ai-auditor ANTHROPIC_API_KEY="sk-ant-..."

# 5. Deploy
fly deploy --remote-only
```

The first deploy takes ~5 minutes (image build + Postgres provisioning). Subsequent deploys are ~60 seconds because the layer cache holds. `fly open` opens the public HTTPS URL. Sign in with `admin@demo.local` / any password.

**Things to know**

- `auto_stop_machines = "stop"` in `fly.toml` puts the machine to sleep when idle and wakes on the first request. Cold-start is ~3-4 seconds. Comment it out if you want the demo persistently warm (and pay for it).
- The container has no Sysmon/eBPF backend, so the involuntary-divergence detector is silent on Fly. The other ten detectors + the judge still fire. The voluntary telemetry channel and the inline gate behave identically to the local demo.
- Demo sandbox files (`notes.txt`, `secrets.txt`, `kb_article.txt`) are written on every container boot by `scripts/cloud/start.sh` so the canned attack prompts in the SYSTEM_OVERVIEW demo flow stay reproducible across deploys.
- To reset between demos: click **Settings -> Reset session data** in the UI, or `fly ssh console -a ai-auditor -C "python scripts/wipe_run_data.py"`.

**Cost expectation:** ~$5/mo at the listed VM size with `auto_stop_machines` on; ~$15/mo persistently warm. Fly Postgres on `shared-cpu-1x` + 1GB volume is ~$2/mo extra.

---

## Running Tests

```powershell
# Windows
.\make.ps1 test
# or directly:
.\.venv\Scripts\python.exe -m pytest tests/unit -q

# Linux
make test
# or:
.venv/bin/python -m pytest tests/unit -q
```

To exclude integration tests (which need live services):

```bash
pytest -m "not integration" tests/ -q
```

Test count as of Phase 8: **545 tests pass** (non-integration). `ruff` is clean tree-wide.

---

## Key Targets (`make.ps1` / `Makefile`)

| Target | What it does |
|---|---|
| `bootstrap` | Create venv, `pip install -e ".[dev,gate,harness,embeddings-local]"`, start Docker services |
| `init` | Wait for Postgres health, `alembic upgrade head`, seed demo data |
| `demo` | Full end-to-end: services + migrate + seed + auditor + harness + adversarial runner |
| `stop` | Stop the detached auditor process |
| `up` / `down` | Start / stop Docker backing services only |
| `migrate` | `alembic upgrade head` |
| `seed` | `python scripts/seed_demo.py` |
| `test` | `pytest tests/unit -q` |
| `lint` / `fmt` | `ruff check` / `ruff check --fix` |
| `clean` | Stop auditor + `docker compose down -v` |

---

## Useful CLIs

```bash
# Verify the audit-log hash chain for a tenant
python -m auditor.audit_log.verifier --tenant <tenant-uuid>

# Run nightly calibration (judge vs ground truth corpus)
python -m auditor.calibration.nightly

# Manually label a trace for the calibration corpus
python -m auditor.calibration.label --add --run-id <uuid> --category ASI06 --label VIOLATION

# Run the adversarial red-team runner
python -m adversarial.runner --demo        # curated demo subset
python -m adversarial.runner --all         # all registered categories
python -m adversarial.runner --category ASI02
```

---

## Key Endpoints

| Endpoint | Description |
|---|---|
| `GET /health` | DB + Redis + MinIO + OPA probes |
| `GET /healthz/live` | Liveness (always 200 if process is up) |
| `GET /metrics` | Prometheus metrics |
| `GET /hitl/flags` | List flags (filterable by status, severity, tenant) |
| `GET /hitl/flags/{id}` | Flag detail with trace |
| `POST /hitl/flags/{id}/decisions` | Submit reviewer decision (continue / abort / quarantine) |
| `WS /hitl/ws/flags` | Live flag updates (WebSocket) |
| `GET /incidents` | List incidents |
| `POST /incidents/{id}/transition` | Move incident through lifecycle |
| `POST /audit/search` | Query DSL over events/verdicts/flags/audit_log |
| `GET /admin/calibration/latest` | Latest calibration report |
| `POST /admin/calibration/run` | Trigger calibration run (admin only) |
| `POST /auth/login` | Obtain session token |
| `GET /auth/me` | Current user info |

---

## Configuration

Copy `.env.example` to `.env` and edit as needed. Key variables:

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | `postgresql+asyncpg://auditor:auditor@localhost:5432/auditor` | |
| `REDIS_URL` | `redis://localhost:6379/0` | |
| `MINIO_ENDPOINT` | `localhost:9000` | |
| `OPA_URL` | `http://localhost:8181` | |
| `ANTHROPIC_API_KEY` | (unset) | Required for live judge; offline stub used without it |
| `IPC_MTLS_ENABLED` | `false` | Set to `true` to enable mTLS over IPC (demo.ps1 sets this) |
| `GATE_TIMEOUT_MS` | `500` | Inline gate timeout; raise on slow Docker-Desktop links |

**Important:** keep `.env` comments on their own lines (not inline). python-dotenv folds inline comments into values.

---

## Project layout

```
auditor/          FastAPI app, async detector pipeline, IPC server, DB models
harness/          Agent harness (AG2 ConversableAgent) + telemetry SDK + tool packs
hitl_ui/frontend/ React + TypeScript operator console
adversarial/      Per-category attack scenarios used by the red-team runner
involuntary/      Windows Sysmon + Linux eBPF telemetry backends
scripts/          Bootstrap / init / demo entrypoints for Windows + Linux
opa/              Default Rego policies loaded into OPA
litellm/          LiteLLM proxy config for the live judge
docker-compose.yml   Postgres, Redis, MinIO, OPA, optional LiteLLM
```
