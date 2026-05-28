"""Post-hoc PII scanners for data already at rest.

The auditor redacts PII at write time (see ``auditor/events/store.py``), but two cases still need
a sweep:

1. **Events written before the redaction wiring** (pre-2026-05) or where redaction was disabled
   for debugging. These payloads contain raw PII; the scanner finds it and emits a rollup flag
   against the originating ``run_id``.
2. **Memory entries** whose content metadata may contain PII fragments leaked from the agent's
   memory layer.

This module never mutates data. It only reads and emits :class:`auditor.verdicts.schemas.Verdict`
rows + an aggregated :class:`auditor.verdicts.aggregator.Flag`. Operator-driven via the CLI
(``python -m auditor.scanner.memory_log_scan``) or the admin API
(``POST /admin/scanner/scan``).
"""
