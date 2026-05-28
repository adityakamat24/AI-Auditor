"""Manual ground-truth labeling CLI (PRD §9.12.1).

Usage::

    python -m auditor.calibration.label --add --run-id <uuid|uri> --category ASI06 --label VIOLATION
    python -m auditor.calibration.label --add --run-id <uuid|uri> --category ASI06 --label VIOLATION --source manual
    python -m auditor.calibration.label --list
    python -m auditor.calibration.label --list --category ASI06

Exit codes: 0 - success, 2 - usage / validation error.

# Testing seam
# ---------------
# ``get_sessionmaker`` is imported at the top of this module as a module-level name.  Tests
# monkeypatch ``auditor.calibration.label.get_sessionmaker`` to inject a fake async session
# factory so no live DB is needed.  The ``_add_ground_truth`` and ``_list_ground_truth`` helpers
# accept an explicit ``session`` argument for even finer-grained unit testing.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import UTC, datetime
from typing import Any

# Module-level import so tests can monkeypatch it.
from auditor.db.session import get_sessionmaker

VALID_CATEGORIES: frozenset[str] = frozenset(f"ASI{i:02d}" for i in range(1, 11))
VALID_LABELS: frozenset[str] = frozenset({"VIOLATION", "OK"})

# ------------------------------------------------------------------------------- DB helpers


async def _add_ground_truth(
    session: Any,
    *,
    trace_uri: str,
    asi_category: str,
    label: str,
    source: str,
) -> Any:
    """Insert a GroundTruth row into *session* and flush (no commit - caller handles it).

    Returns the inserted row so callers can inspect it (useful in tests).
    """
    from auditor.db.models import GroundTruth
    from auditor.ids import uuid7

    row = GroundTruth(
        gt_id=uuid7(),
        asi_category=asi_category,
        label=label,
        trace_uri=trace_uri,
        source=source,
        version=1,
        created_at=datetime.now(tz=UTC),
    )
    session.add(row)
    await session.flush()
    return row


async def _list_ground_truth(
    session: Any,
    *,
    category: str | None,
    limit: int = 50,
) -> list[Any]:
    """Return recent GroundTruth rows, optionally filtered by *category*."""
    from sqlalchemy import select

    from auditor.db.models import GroundTruth

    q = select(GroundTruth)
    if category is not None:
        q = q.where(GroundTruth.asi_category == category)
    q = q.order_by(GroundTruth.created_at.desc()).limit(limit)
    result = await session.execute(q)
    return list(result.scalars().all())


# ------------------------------------------------------------------------------- async actions


async def _do_add(
    *,
    run_id: str,
    category: str,
    label: str,
    source: str,
) -> int:
    """Insert a GroundTruth row; return 0 on success."""
    sm = get_sessionmaker()
    async with sm() as session, session.begin():
        row = await _add_ground_truth(
            session,
            trace_uri=run_id,
            asi_category=category,
            label=label,
            source=source,
        )
    print(f"Added ground truth: gt_id={row.gt_id} category={category} label={label} uri={run_id}")
    return 0


async def _do_list(*, category: str | None) -> int:
    """Print recent GroundTruth rows; return 0."""
    sm = get_sessionmaker()
    async with sm() as session:
        rows = await _list_ground_truth(session, category=category)
    if not rows:
        print("(no ground truth rows found)")
        return 0
    header = f"{'gt_id':<38}  {'category':<8}  {'label':<10}  {'source':<12}  trace_uri"
    print(header)
    print("-" * len(header))
    for r in rows:
        print(
            f"{str(r.gt_id):<38}  {r.asi_category:<8}  {r.label:<10}  {r.source:<12}  {r.trace_uri}"
        )
    return 0


# ------------------------------------------------------------------------------- CLI


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m auditor.calibration.label",
        description="Manage ground-truth labels for calibration.",
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--add", action="store_true", help="Insert a new ground-truth label.")
    mode.add_argument("--list", action="store_true", help="List existing ground-truth labels.")

    # --add flags
    parser.add_argument(
        "--run-id",
        metavar="UUID_OR_URI",
        help="Run ID or trace URI to label (required with --add).",
    )
    parser.add_argument(
        "--category",
        metavar="ASIxx",
        help="ASI category, e.g. ASI06 (required with --add; optional filter with --list).",
    )
    parser.add_argument(
        "--label",
        choices=sorted(VALID_LABELS),
        help="Ground-truth label: VIOLATION or OK (required with --add).",
    )
    parser.add_argument(
        "--source",
        default="manual",
        help="Label provenance (default: manual).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns 0 on success, 2 on usage/validation error."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.add:
        # Validate required args for --add.
        missing = [name for name, val in [("--run-id", args.run_id), ("--label", args.label)] if not val]
        if missing:
            parser.error(f"--add requires: {', '.join(missing)}")

        # Validate category (required for --add).
        if not args.category:
            parser.error("--add requires --category")
        category = args.category.upper()
        if category not in VALID_CATEGORIES:
            parser.error(
                f"--category must be one of {sorted(VALID_CATEGORIES)}; got {args.category!r}"
            )

        label = args.label.upper()
        if label not in VALID_LABELS:
            parser.error(f"--label must be one of {sorted(VALID_LABELS)}; got {args.label!r}")

        return asyncio.run(
            _do_add(
                run_id=args.run_id,
                category=category,
                label=label,
                source=args.source,
            )
        )

    # --list mode
    category: str | None = None
    if args.category:
        category = args.category.upper()
        if category not in VALID_CATEGORIES:
            parser.error(
                f"--category must be one of {sorted(VALID_CATEGORIES)}; got {args.category!r}"
            )
    return asyncio.run(_do_list(category=category))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())


__all__ = [
    "main",
    "get_sessionmaker",
    "_add_ground_truth",
    "_list_ground_truth",
    "VALID_CATEGORIES",
    "VALID_LABELS",
]
