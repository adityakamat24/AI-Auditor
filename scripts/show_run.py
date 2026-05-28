"""Show the auditor's verdict on one run, grouped under the four operator checks.

Usage:  python scripts/show_run.py <run_id>

Prints the sampler decision, the aggregated flag, the per-check findings (Instruction Following /
Unauthorized Access / Data Exfiltration / Sensitive-Data Hygiene), and any opened incident.
"""

from __future__ import annotations

import asyncio
import contextlib
import sys
from uuid import UUID

from auditor.db.models import Flag, Incident, Run, SamplerDecision, Verdict
from auditor.db.session import dispose_engine, get_sessionmaker
from auditor.verdicts.checks import CHECK_TITLES, Check, check_for_detector
from sqlalchemy import select


async def show(run_id: UUID) -> None:
    sm = get_sessionmaker()
    async with sm() as session:
        run = await session.get(Run, run_id)
        sampler = (await session.execute(
            select(SamplerDecision).where(SamplerDecision.run_id == run_id))).scalars().first()
        flag = (await session.execute(select(Flag).where(Flag.run_id == run_id))).scalars().first()
        verdicts = (await session.execute(select(Verdict).where(Verdict.run_id == run_id))).scalars().all()
        incident = None
        if flag is not None:
            incident = (await session.execute(
                select(Incident).where(Incident.primary_flag_id == str(flag.flag_id)))).scalars().first()
    await dispose_engine()

    print(f"\n=== RUN {run_id} ===")
    if run is not None:
        print(f"  status={run.status}  goal={run.declared_goal!r}")
    if sampler is not None:
        print(f"  sampler: tier={sampler.tier_fired}  reason={sampler.reason}")
    else:
        print("  sampler: (not yet audited — try again in a few seconds)")

    if flag is None:
        print("  AUDIT RESULT: [CLEAN] no flag raised")
        return

    print(f"  AUDIT RESULT: [FLAG] severity={flag.severity.upper()}  categories={flag.asi_categories}")

    by_check: dict[Check, list[Verdict]] = {}
    for verdict in verdicts:
        if verdict.result == "OK":
            continue
        check = check_for_detector(verdict.detector, verdict.asi_category)
        if check is not None:
            by_check.setdefault(check, []).append(verdict)

    for check in Check:
        findings = by_check.get(check, [])
        if not findings:
            continue
        print(f"\n  [{CHECK_TITLES[check]}]")
        for verdict in findings:
            reason = verdict.evidence[0].get("reason", "") if verdict.evidence else ""
            print(f"     - {verdict.detector}: {verdict.result}  — {reason[:110]}")

    if incident is not None:
        print(f"\n  INCIDENT {incident.incident_id}  state={incident.state}")


if __name__ == "__main__":
    # The judge / evidence text may contain non-cp1252 chars on Windows consoles; never let printing crash.
    with contextlib.suppress(Exception):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    if len(sys.argv) != 2:
        print("usage: python scripts/show_run.py <run_id>")
        raise SystemExit(2)
    asyncio.run(show(UUID(sys.argv[1])))
