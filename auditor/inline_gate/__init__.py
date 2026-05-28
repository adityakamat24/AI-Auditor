"""Inline synchronous gate (PRD §9.4): OPA policy + Presidio PII + Redis tool-budget, combined into one
ALLOW/DENY/CONFIRM decision on the critical path. Channel divergence joins in Phase 3.
"""

from auditor.inline_gate.budget import BudgetEnforcer
from auditor.inline_gate.decide import GateOutcome, decide, opa_input
from auditor.inline_gate.pii_scanner import PiiScanner
from auditor.inline_gate.policy_engine import OpaClient

__all__ = ["BudgetEnforcer", "GateOutcome", "decide", "opa_input", "PiiScanner", "OpaClient"]
