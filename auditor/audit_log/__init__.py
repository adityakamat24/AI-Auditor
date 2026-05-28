"""Tamper-evident audit log (PRD §9.11) - write, verify, redact. STUB - Phase 5.

An append-only, hash-chained record of every decision (gate, verdict, HITL action) for compliance and
replay. The writer chains entries; the verifier validates the chain; the redactor handles GDPR erasure
while preserving verifiability. Submodules are stubs.
"""

from __future__ import annotations

# TODO(phase5): writer (hash-chained append) + verifier (chain integrity) + redactor (verifiable erasure).

__all__: list[str] = []
