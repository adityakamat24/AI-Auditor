"""Adversarial test runner (PRD §12.4) — drives red-team scenarios against the auditor's inline gate.

Spins up an in-process auditor gate (mTLS) + a scripted harness via :func:`adversarial.gate_harness.gate_session`,
runs the selected attack, and checks the gate decision against the category's ``expected_flags.json``.

Usage:  python -m adversarial.runner --category ASI02 | --all | --demo
(Requires the backing services up: docker compose up -d postgres redis opa.)
"""

from __future__ import annotations

import argparse
import asyncio
import importlib
import json
from pathlib import Path

from adversarial.gate_harness import gate_session

_HERE = Path(__file__).parent

# category -> (attack module, expected_flags.json path)
CATEGORIES: dict[str, tuple[str, Path]] = {
    "ASI02": (
        "adversarial.per_category.asi02_tool_misuse.agent",
        _HERE / "per_category" / "asi02_tool_misuse" / "expected_flags.json",
    ),
    "ASI05": (
        "adversarial.per_category.asi05_code_execution.agent",
        _HERE / "per_category" / "asi05_code_execution" / "expected_flags.json",
    ),
}


async def run_category(category: str) -> bool:
    module_path, expected_path = CATEGORIES[category]
    attack = importlib.import_module(module_path)
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    async with gate_session() as (telemetry, _run_id, agent_id):
        result = await attack.run_attack(telemetry, agent_id)
    reason_ok = any(expected["reason_contains"] in r for r in result.get("reasons", []))
    passed = bool(result.get("denied")) and reason_ok
    print(
        f"[{category}] denied={result.get('denied')} reasons={result.get('reasons')} "
        f"-> {'PASS' if passed else 'FAIL'}"
    )
    return passed


async def _run(categories: list[str]) -> int:
    results = [await run_category(c) for c in categories]
    ok = all(results)
    print(f"\nadversarial: {sum(results)}/{len(results)} passed -> {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="adversarial.runner",
        description="Run adversarial red-team scenarios against the AI Auditor's inline gate.",
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--all", action="store_true", help="run every implemented category")
    group.add_argument("--category", metavar="ASI", help="run one category, e.g. ASI02")
    group.add_argument("--demo", action="store_true", help="run the curated demo subset")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.all or args.demo:
        categories = list(CATEGORIES)
    elif args.category:
        key = args.category.upper()
        if key not in CATEGORIES:
            print(f"unknown category {args.category!r}; known: {', '.join(CATEGORIES)}")
            return 2
        categories = [key]
    else:
        print("specify --category ASI02 | --all | --demo")
        return 2
    return asyncio.run(_run(categories))


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["build_parser", "main", "run_category", "CATEGORIES"]
