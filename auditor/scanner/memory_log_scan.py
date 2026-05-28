"""Memory + event payload PII scanner.

Walks ``events.payload`` (and ``memory_entries.flags`` when present) for a tenant, aggregates PII
findings per ``run_id``, and emits ONE rollup verdict + flag per run with ``asi_category =
PII_AT_REST``. The "rollup per run" design (Option B from the design review) keeps the queue
clean: 50 PII-leaking events in one run = 1 flag with a count breakdown, not 50 separate flags.

Run from the CLI::

    python -m auditor.scanner.memory_log_scan --tenant <uuid>             # all-time
    python -m auditor.scanner.memory_log_scan --tenant <uuid> --since 24h # last 24 hours

or via the admin endpoint ``POST /admin/scanner/scan``. The scanner is read-only against
``events`` / ``memory_entries`` and write-only against ``verdicts`` / ``flags`` (via the
existing :func:`auditor.events.store.store_run_result` path so incident auto-open keeps
working).
"""

from __future__ import annotations

import argparse
import asyncio
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select

from auditor.audit_log.redactor import detect_entities_in_value
from auditor.db.models import Event as EventRow
from auditor.db.session import dispose_engine, get_sessionmaker
from auditor.events.store import store_run_result
from auditor.logging import get_logger
from auditor.verdicts.aggregator import aggregate
from auditor.verdicts.schemas import Evidence, Verdict, VerdictResult

log = get_logger("auditor.scanner")

# Entity types that mark PII serious enough to drive HIGH severity rather than MEDIUM.
# US_SSN and CREDIT_CARD are statutorily protected; PRIVATE_KEY and GENERIC_API_KEY are
# credentials whose leak is a security incident in its own right.
_HIGH_SEVERITY_ENTITIES: frozenset[str] = frozenset(
    {"US_SSN", "CREDIT_CARD", "PRIVATE_KEY", "GENERIC_API_KEY"}
)


@dataclass
class RunFinding:
    """Aggregated PII findings for one run (Option B: one rollup per run)."""

    run_id: UUID
    tenant_id: UUID
    counts: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    event_ids: list[UUID] = field(default_factory=list)
    memory_hits: int = 0  # contributions from memory_entries

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    @property
    def entity_types(self) -> list[str]:
        return sorted(self.counts.keys())

    def severity_hint(self) -> str:
        """Return the severity tag we set in ``rubric_scores`` to drive the aggregator."""
        if any(e in _HIGH_SEVERITY_ENTITIES for e in self.counts):
            return "high"
        if self.total >= 5:
            return "medium"
        return "low"


def _parse_since(value: str | None) -> datetime | None:
    """Parse ``--since`` token: ``24h``, ``7d``, or an ISO8601 timestamp. None = no filter."""
    if not value:
        return None
    m = re.fullmatch(r"(\d+)([hd])", value.strip().lower())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        delta = timedelta(hours=n) if unit == "h" else timedelta(days=n)
        return datetime.now(tz=UTC) - delta
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"--since must be like '24h', '7d', or an ISO timestamp; got {value!r}") from exc


def _extract_entities_from_payload(payload: dict) -> list[str]:
    """Return the entity types present in this payload.

    Fast path: if the payload was redacted at write time, ``_pii_redacted`` holds the summary
    and we read it directly (no recognizer pass needed). Slow path: walk the payload with the
    redactor and re-detect (for events written before the redaction wiring landed).
    """
    if isinstance(payload, dict):
        marker = payload.get("_pii_redacted")
        if isinstance(marker, list) and marker:
            return [str(e) for e in marker]
    return detect_entities_in_value(payload)


async def scan_events(tenant_id: UUID, since: datetime | None = None) -> dict[UUID, RunFinding]:
    """Walk ``events.payload`` for a tenant; return per-run findings (Option B rollup)."""
    findings: dict[UUID, RunFinding] = {}
    sm = get_sessionmaker()
    async with sm() as session:
        stmt = select(EventRow).where(EventRow.tenant_id == tenant_id)
        if since is not None:
            stmt = stmt.where(EventRow.ts >= since)
        result = await session.execute(stmt)
        for row in result.scalars().all():
            entities = _extract_entities_from_payload(row.payload or {})
            if not entities:
                continue
            run_uuid = row.run_id if isinstance(row.run_id, UUID) else UUID(str(row.run_id))
            tenant_uuid = (
                row.tenant_id if isinstance(row.tenant_id, UUID) else UUID(str(row.tenant_id))
            )
            f = findings.setdefault(run_uuid, RunFinding(run_id=run_uuid, tenant_id=tenant_uuid))
            for e in entities:
                f.counts[e] += 1
            event_uuid = row.event_id if isinstance(row.event_id, UUID) else UUID(str(row.event_id))
            f.event_ids.append(event_uuid)
    return findings


async def scan_memory(tenant_id: UUID, findings: dict[UUID, RunFinding]) -> None:
    """Walk ``memory_entries.flags`` for PII fragments. Merges into ``findings`` in place.

    ``memory_entries`` stores only ``content_hash`` (not the raw content), so the surface area
    here is the ``flags`` JSONB - any metadata the agent attached. When pgvector is unavailable
    (Fly Postgres) the table may not exist; we tolerate that.
    """
    sm = get_sessionmaker()
    async with sm() as session:
        try:
            from auditor.db.models import MemoryEntry

            stmt = select(MemoryEntry).where(MemoryEntry.tenant_id == tenant_id)
            result = await session.execute(stmt)
            rows = result.scalars().all()
        except Exception as exc:  # noqa: BLE001 - table may not exist on pgvector-less deployments
            log.info("scanner.memory_skip", reason=str(exc))
            return
        for row in rows:
            entities = _extract_entities_from_payload(row.flags or {})
            if not entities:
                continue
            run_uuid = (
                row.created_in_run_id
                if isinstance(row.created_in_run_id, UUID)
                else UUID(str(row.created_in_run_id))
                if row.created_in_run_id
                else None
            )
            if run_uuid is None:
                continue  # memory entries with no originating run are uncorrelatable - skip
            tenant_uuid = (
                row.tenant_id if isinstance(row.tenant_id, UUID) else UUID(str(row.tenant_id))
            )
            f = findings.setdefault(run_uuid, RunFinding(run_id=run_uuid, tenant_id=tenant_uuid))
            for e in entities:
                f.counts[e] += 1
            f.memory_hits += 1


def _finding_to_verdict(finding: RunFinding) -> Verdict:
    """Convert a per-run finding to a Verdict the existing aggregator can consume."""
    breakdown = ", ".join(f"{e}x{c}" for e, c in sorted(finding.counts.items()))
    reasons = [
        Evidence(
            reason=(
                f"PII at rest detected across {len(finding.event_ids)} event(s)"
                + (f" + {finding.memory_hits} memory entrie(s)" if finding.memory_hits else "")
                + f": {breakdown}"
            )
        )
    ]
    # Surface up to 5 contributing event_ids so the operator can drill in.
    for eid in finding.event_ids[:5]:
        reasons.append(Evidence(event_id=eid, reason="contained PII at rest"))

    return Verdict(
        run_id=finding.run_id,
        tenant_id=finding.tenant_id,
        detector="pii_at_rest",
        asi_category="PII_AT_REST",
        result=VerdictResult.VIOLATION,
        confidence=0.95,
        evidence=reasons,
        rubric_scores={
            "severity": finding.severity_hint(),
            "entity_counts": dict(finding.counts),
            "events_scanned": len(finding.event_ids),
            "memory_hits": finding.memory_hits,
        },
    )


async def run_scan(tenant_id: UUID, since: datetime | None = None) -> dict:
    """Run the events + memory scans and emit one verdict + flag per affected run.

    Returns a summary dict the CLI / admin endpoint can serialize::

        {
          "events_findings": 12,    # runs with PII in events
          "memory_findings": 3,     # runs with PII in memory metadata
          "runs_flagged": 14,       # union (de-duplicated)
          "verdicts_persisted": 14,
        }
    """
    findings = await scan_events(tenant_id, since=since)
    events_findings = len(findings)

    before_keys = set(findings.keys())
    await scan_memory(tenant_id, findings)
    memory_findings = len(set(findings.keys()) - before_keys) + sum(
        1 for k in before_keys if findings[k].memory_hits > 0
    )

    persisted = 0
    for finding in findings.values():
        verdict = _finding_to_verdict(finding)
        flag = aggregate(finding.run_id, finding.tenant_id, [verdict])
        # Persist via the existing store path so incident auto-open + audit log still fire.
        try:
            await store_run_result([verdict], flag)
            persisted += 1
        except Exception as exc:  # noqa: BLE001 - best-effort per finding; keep scanning
            log.warning(
                "scanner.persist_failed",
                run_id=str(finding.run_id),
                error=str(exc),
            )

    log.info(
        "scanner.completed",
        tenant_id=str(tenant_id),
        events_findings=events_findings,
        memory_findings=memory_findings,
        runs_flagged=len(findings),
        verdicts_persisted=persisted,
    )

    return {
        "events_findings": events_findings,
        "memory_findings": memory_findings,
        "runs_flagged": len(findings),
        "verdicts_persisted": persisted,
    }


async def _main_async(args: argparse.Namespace) -> int:
    since = _parse_since(args.since)
    summary = await run_scan(UUID(args.tenant), since=since)
    print(summary)  # noqa: T201 - intentional CLI output
    await dispose_engine()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python -m auditor.scanner.memory_log_scan",
        description="Scan events + memory for PII at rest; emit rollup flags per run_id.",
    )
    parser.add_argument("--tenant", required=True, help="Tenant UUID to scan.")
    parser.add_argument(
        "--since",
        default=None,
        help="Restrict to events newer than this. Accepts '24h', '7d', or an ISO timestamp.",
    )
    args = parser.parse_args()
    return asyncio.run(_main_async(args))


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "RunFinding",
    "run_scan",
    "scan_events",
    "scan_memory",
    "main",
]
