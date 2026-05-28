"""Unit tests for ``auditor.scanner.memory_log_scan``.

DB-touching tests (``scan_events`` end-to-end) live in
``tests/integration/test_scanner_integration.py`` so this file stays Postgres-free and runs in
CI without external services. These tests cover the pure logic: ``--since`` parsing, the
``RunFinding`` aggregation, severity hinting, payload extraction (both the fast ``_pii_redacted``
path and the slow recognizer-pass path), and ``_finding_to_verdict``.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from auditor.audit_log.redactor import reset_redactor_for_tests
from auditor.scanner.memory_log_scan import (
    RunFinding,
    _extract_entities_from_payload,
    _finding_to_verdict,
    _parse_since,
)
from auditor.verdicts.schemas import VerdictResult


@pytest.fixture(autouse=True)
def _force_regex_backend() -> None:
    """Force regex backend so tests don't depend on the spaCy model."""
    reset_redactor_for_tests()
    from auditor.audit_log import redactor as redactor_mod

    redactor_mod._SINGLETON = redactor_mod.Redactor(force_regex=True)
    yield
    reset_redactor_for_tests()


class TestParseSince:
    def test_hours(self) -> None:
        ref = datetime.now(tz=UTC)
        out = _parse_since("24h")
        assert out is not None
        assert ref - timedelta(hours=24, seconds=2) <= out <= ref - timedelta(hours=23, minutes=59, seconds=58)

    def test_days(self) -> None:
        ref = datetime.now(tz=UTC)
        out = _parse_since("7d")
        assert out is not None
        assert (ref - out) >= timedelta(days=6, hours=23)

    def test_iso_timestamp(self) -> None:
        out = _parse_since("2026-01-01T00:00:00+00:00")
        assert out == datetime(2026, 1, 1, tzinfo=UTC)

    def test_none_returns_none(self) -> None:
        assert _parse_since(None) is None
        assert _parse_since("") is None

    def test_invalid_token_raises(self) -> None:
        with pytest.raises(ValueError):
            _parse_since("yesterday")


class TestRunFinding:
    def test_total_counts_across_entity_types(self) -> None:
        run_id, tenant_id = uuid4(), uuid4()
        f = RunFinding(run_id=run_id, tenant_id=tenant_id)
        f.counts["EMAIL_ADDRESS"] = 3
        f.counts["US_SSN"] = 1
        assert f.total == 4
        assert f.entity_types == ["EMAIL_ADDRESS", "US_SSN"]

    def test_severity_high_for_protected_classes(self) -> None:
        """SSN, credit card, API key, private key promote severity to high."""
        for cat in ("US_SSN", "CREDIT_CARD", "GENERIC_API_KEY", "PRIVATE_KEY"):
            f = RunFinding(run_id=uuid4(), tenant_id=uuid4())
            f.counts[cat] = 1
            assert f.severity_hint() == "high", f"expected high for {cat}"

    def test_severity_medium_for_volume(self) -> None:
        """A lot of low-sensitivity PII (emails, phones) still warrants medium."""
        f = RunFinding(run_id=uuid4(), tenant_id=uuid4())
        f.counts["EMAIL_ADDRESS"] = 5
        assert f.severity_hint() == "medium"

    def test_severity_low_for_handful(self) -> None:
        f = RunFinding(run_id=uuid4(), tenant_id=uuid4())
        f.counts["EMAIL_ADDRESS"] = 2
        assert f.severity_hint() == "low"


class TestExtractEntitiesFromPayload:
    def test_fast_path_reads_pii_marker(self) -> None:
        """When payload was redacted at write time, ``_pii_redacted`` is the source of truth."""
        payload = {
            "to": "<EMAIL_ADDRESS>",
            "_pii_redacted": ["EMAIL_ADDRESS", "PHONE_NUMBER"],
        }
        entities = _extract_entities_from_payload(payload)
        assert sorted(entities) == ["EMAIL_ADDRESS", "PHONE_NUMBER"]

    def test_slow_path_walks_payload(self) -> None:
        """Old events (pre-redaction wiring) get a full recognizer pass."""
        payload = {"to": "alice@example.com", "body": "ssn 123-45-6789"}
        entities = _extract_entities_from_payload(payload)
        assert "EMAIL_ADDRESS" in entities
        assert "US_SSN" in entities

    def test_clean_payload_returns_empty(self) -> None:
        assert _extract_entities_from_payload({"tool_name": "file_read"}) == []

    def test_empty_marker_falls_through_to_walk(self) -> None:
        """An empty ``_pii_redacted`` list should not short-circuit a re-scan."""
        payload = {"to": "alice@example.com", "_pii_redacted": []}
        entities = _extract_entities_from_payload(payload)
        assert "EMAIL_ADDRESS" in entities


class TestFindingToVerdict:
    def test_verdict_shape(self) -> None:
        run_id, tenant_id = uuid4(), uuid4()
        f = RunFinding(run_id=run_id, tenant_id=tenant_id)
        f.counts["EMAIL_ADDRESS"] = 3
        f.counts["US_SSN"] = 1
        f.event_ids = [uuid4() for _ in range(7)]

        v = _finding_to_verdict(f)

        assert v.run_id == run_id
        assert v.tenant_id == tenant_id
        assert v.detector == "pii_at_rest"
        assert v.asi_category == "PII_AT_REST"
        assert v.result == VerdictResult.VIOLATION
        # First evidence is the human-readable summary; the rest are up to 5 event_id pointers.
        assert "EMAIL_ADDRESSx3" in v.evidence[0].reason
        assert "US_SSNx1" in v.evidence[0].reason
        # Severity hint surfaces in rubric_scores so the severity classifier picks it up.
        assert v.rubric_scores["severity"] == "high"  # US_SSN promotes to high
        assert v.rubric_scores["entity_counts"] == {"EMAIL_ADDRESS": 3, "US_SSN": 1}
        # No more than 5 event_id pointers added (keeps the verdict row bounded).
        event_evidence = [e for e in v.evidence if e.event_id is not None]
        assert len(event_evidence) == 5

    def test_memory_hits_called_out_in_reason(self) -> None:
        f = RunFinding(run_id=uuid4(), tenant_id=uuid4())
        f.counts["EMAIL_ADDRESS"] = 1
        f.memory_hits = 2

        v = _finding_to_verdict(f)
        assert "memory entrie(s)" in v.evidence[0].reason
        assert v.rubric_scores["memory_hits"] == 2
