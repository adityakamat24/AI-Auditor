"""Unit tests for ASI04 catalog-integrity startup check (PRD §15 Phase-4 acceptance item ASI04).

Covers:
1. Unchanged files  -> no violation (OK verdict).
2. Modified file    -> CRITICAL VIOLATION; aggregate() yields a Flag with Severity.CRITICAL.
3. Tool removed     -> CRITICAL VIOLATION.
4. Tool added       -> CRITICAL VIOLATION.
"""

from __future__ import annotations

from uuid import uuid4

from auditor.detectors.asi04_catalog_integrity import (
    CatalogIntegrityCheck,
    publish_catalog,
    verify_catalog_integrity,
)
from auditor.verdicts.aggregator import aggregate
from auditor.verdicts.schemas import Severity, VerdictResult

RUN = uuid4()
TENANT = uuid4()


# ---------------------------------------------------------------------------
# Case 1 - unchanged files produce an OK verdict (no violation)
# ---------------------------------------------------------------------------


def test_no_violation_when_files_unchanged(tmp_path):
    tool_a = tmp_path / "tool_a.py"
    tool_b = tmp_path / "tool_b.py"
    tool_a.write_bytes(b"def tool_a(): pass\n")
    tool_b.write_bytes(b"def tool_b(): pass\n")

    tool_files = {"tool_a": tool_a, "tool_b": tool_b}

    published = publish_catalog(tool_files)
    verdicts = verify_catalog_integrity(published, tool_files, run_id=RUN, tenant_id=TENANT)

    assert len(verdicts) == 1
    v = verdicts[0]
    assert v.result == VerdictResult.OK
    assert v.asi_category == "ASI04"
    assert v.detector == "asi04_catalog_integrity"
    # No flag should be raised (aggregate returns None for all-OK)
    flag = aggregate(RUN, TENANT, verdicts)
    assert flag is None


# ---------------------------------------------------------------------------
# Case 2 - modified file -> CRITICAL VIOLATION; aggregate yields CRITICAL Flag
# ---------------------------------------------------------------------------


def test_critical_violation_when_file_modified(tmp_path):
    tool_a = tmp_path / "tool_a.py"
    tool_a.write_bytes(b"def tool_a(): pass\n")

    tool_files = {"tool_a": tool_a}
    published = publish_catalog(tool_files)

    # Modify the file after publish
    tool_a.write_bytes(b"def tool_a(): return 'MODIFIED'\n")

    verdicts = verify_catalog_integrity(published, tool_files, run_id=RUN, tenant_id=TENANT)

    violation_verdicts = [v for v in verdicts if v.result == VerdictResult.VIOLATION]
    assert len(violation_verdicts) == 1, f"expected exactly one violation, got: {verdicts}"

    v = violation_verdicts[0]
    assert v.rubric_scores is not None
    assert v.rubric_scores["severity"] == "critical"
    assert v.asi_category == "ASI04"
    assert v.detector == "asi04_catalog_integrity"
    assert "tool_a" in v.evidence[0].reason

    # aggregate() must produce a CRITICAL Flag
    flag = aggregate(RUN, TENANT, verdicts)
    assert flag is not None
    assert flag.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Case 3 - tool removed after publish -> CRITICAL VIOLATION
# ---------------------------------------------------------------------------


def test_critical_violation_when_tool_removed(tmp_path):
    tool_a = tmp_path / "tool_a.py"
    tool_b = tmp_path / "tool_b.py"
    tool_a.write_bytes(b"def tool_a(): pass\n")
    tool_b.write_bytes(b"def tool_b(): pass\n")

    published = publish_catalog({"tool_a": tool_a, "tool_b": tool_b})

    # tool_b is no longer registered at run-start (removed from current_files)
    current_files = {"tool_a": tool_a}

    verdicts = verify_catalog_integrity(published, current_files, run_id=RUN, tenant_id=TENANT)

    violation_verdicts = [v for v in verdicts if v.result == VerdictResult.VIOLATION]
    assert len(violation_verdicts) == 1

    v = violation_verdicts[0]
    assert v.rubric_scores == {"severity": "critical"}
    assert "tool_b" in v.evidence[0].reason
    # The reason should mention removal / missing
    assert any(word in v.evidence[0].reason.lower() for word in ("missing", "removed", "absent"))

    flag = aggregate(RUN, TENANT, verdicts)
    assert flag is not None
    assert flag.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Case 3b - implementation file deleted from disk (FileNotFoundError path)
# ---------------------------------------------------------------------------


def test_critical_violation_when_implementation_file_deleted(tmp_path):
    tool_a = tmp_path / "tool_a.py"
    tool_a.write_bytes(b"def tool_a(): pass\n")

    published = publish_catalog({"tool_a": tool_a})

    # Delete the file from disk after publish
    tool_a.unlink()

    current_files = {"tool_a": tool_a}
    verdicts = verify_catalog_integrity(published, current_files, run_id=RUN, tenant_id=TENANT)

    violation_verdicts = [v for v in verdicts if v.result == VerdictResult.VIOLATION]
    assert len(violation_verdicts) == 1

    v = violation_verdicts[0]
    assert v.rubric_scores == {"severity": "critical"}
    assert "tool_a" in v.evidence[0].reason

    flag = aggregate(RUN, TENANT, verdicts)
    assert flag is not None
    assert flag.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# Case 4 - tool added after publish -> CRITICAL VIOLATION
# ---------------------------------------------------------------------------


def test_critical_violation_when_tool_added(tmp_path):
    tool_a = tmp_path / "tool_a.py"
    tool_a.write_bytes(b"def tool_a(): pass\n")

    published = publish_catalog({"tool_a": tool_a})

    # A new tool appears at run-start that wasn't present at publish
    tool_injected = tmp_path / "tool_injected.py"
    tool_injected.write_bytes(b"def evil(): exfiltrate()\n")

    current_files = {"tool_a": tool_a, "tool_injected": tool_injected}
    verdicts = verify_catalog_integrity(published, current_files, run_id=RUN, tenant_id=TENANT)

    violation_verdicts = [v for v in verdicts if v.result == VerdictResult.VIOLATION]
    assert len(violation_verdicts) == 1

    v = violation_verdicts[0]
    assert v.rubric_scores == {"severity": "critical"}
    assert "tool_injected" in v.evidence[0].reason
    # Reason should mention injection / not present at publish
    assert any(word in v.evidence[0].reason.lower() for word in ("inject", "not present", "not in", "after publish"))

    flag = aggregate(RUN, TENANT, verdicts)
    assert flag is not None
    assert flag.severity == Severity.CRITICAL


# ---------------------------------------------------------------------------
# CatalogIntegrityCheck convenience wrapper - smoke test
# ---------------------------------------------------------------------------


def test_catalog_integrity_check_wrapper_ok(tmp_path):
    tool_a = tmp_path / "tool_a.py"
    tool_a.write_bytes(b"def tool_a(): pass\n")

    check = CatalogIntegrityCheck()
    manifest = check.publish({"tool_a": tool_a})
    assert "tool_a" in manifest
    assert len(manifest["tool_a"]) == 64  # sha256 hex

    verdicts = check.verify({"tool_a": tool_a}, run_id=RUN, tenant_id=TENANT)
    assert verdicts[0].result == VerdictResult.OK


def test_catalog_integrity_check_wrapper_violation(tmp_path):
    tool_a = tmp_path / "tool_a.py"
    tool_a.write_bytes(b"original\n")

    check = CatalogIntegrityCheck()
    check.publish({"tool_a": tool_a})

    tool_a.write_bytes(b"tampered\n")
    verdicts = check.verify({"tool_a": tool_a}, run_id=RUN, tenant_id=TENANT)

    assert any(v.result == VerdictResult.VIOLATION for v in verdicts)


# ---------------------------------------------------------------------------
# Multiple simultaneous violations
# ---------------------------------------------------------------------------


def test_multiple_violations(tmp_path):
    tool_a = tmp_path / "tool_a.py"
    tool_b = tmp_path / "tool_b.py"
    tool_a.write_bytes(b"def tool_a(): pass\n")
    tool_b.write_bytes(b"def tool_b(): pass\n")

    published = publish_catalog({"tool_a": tool_a, "tool_b": tool_b})

    # Modify tool_a, remove tool_b, add tool_c
    tool_a.write_bytes(b"tampered\n")
    tool_c = tmp_path / "tool_c.py"
    tool_c.write_bytes(b"injected\n")

    current_files = {"tool_a": tool_a, "tool_c": tool_c}
    verdicts = verify_catalog_integrity(published, current_files, run_id=RUN, tenant_id=TENANT)

    violation_verdicts = [v for v in verdicts if v.result == VerdictResult.VIOLATION]
    # tool_a modified, tool_b removed, tool_c added -> 3 violations
    assert len(violation_verdicts) == 3

    flag = aggregate(RUN, TENANT, verdicts)
    assert flag is not None
    assert flag.severity == Severity.CRITICAL
