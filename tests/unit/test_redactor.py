"""Unit tests for auditor.audit_log.redactor (PRD §9.11.2).

Tests run against the regex fallback by default (force_regex=True) so no spaCy model
download is required in CI. A separate test class exercises the Presidio path when the
model is available, skipping gracefully when it is not.
"""

from __future__ import annotations

import pytest
from auditor.audit_log.redactor import Redactor

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_regex_redactor() -> Redactor:
    """Always use the regex backend - no spaCy needed."""
    return Redactor(force_regex=True)


# ---------------------------------------------------------------------------
# Regex backend tests (always run)
# ---------------------------------------------------------------------------


class TestRegexBackend:
    """Core redaction logic via the regex fallback path."""

    def test_backend_is_regex(self) -> None:
        r = _make_regex_redactor()
        assert r.backend == "regex"

    def test_email_redacted(self) -> None:
        r = _make_regex_redactor()
        result = r.redact_text("contact alice@example.com for details")
        assert "alice@example.com" not in result
        assert "<EMAIL_ADDRESS>" in result

    def test_phone_redacted(self) -> None:
        r = _make_regex_redactor()
        result = r.redact_text("call me at 555-123-4567 today")
        assert "555-123-4567" not in result
        assert "<PHONE_NUMBER>" in result

    def test_ssn_redacted(self) -> None:
        r = _make_regex_redactor()
        result = r.redact_text("SSN is 123-45-6789")
        assert "123-45-6789" not in result
        assert "<US_SSN>" in result

    def test_credit_card_redacted(self) -> None:
        r = _make_regex_redactor()
        result = r.redact_text("card number 4111111111111111 declined")
        assert "4111111111111111" not in result
        assert "<CREDIT_CARD>" in result

    def test_api_key_redacted(self) -> None:
        r = _make_regex_redactor()
        result = r.redact_text("api_key=AKIA1234567890ABCDEFGHIJ")
        assert "AKIA1234567890ABCDEFGHIJ" not in result
        assert "<GENERIC_API_KEY>" in result

    def test_clean_text_unchanged(self) -> None:
        r = _make_regex_redactor()
        text = "the quarterly report is ready for review"
        assert r.redact_text(text) == text

    def test_empty_string_unchanged(self) -> None:
        r = _make_regex_redactor()
        assert r.redact_text("") == ""

    def test_multiple_pii_types_in_one_text(self) -> None:
        r = _make_regex_redactor()
        text = "User bob@example.com has SSN 987-65-4320 and phone 800-555-1234"
        result = r.redact_text(text)
        assert "bob@example.com" not in result
        assert "987-65-4320" not in result
        assert "800-555-1234" not in result
        assert "<EMAIL_ADDRESS>" in result


# ---------------------------------------------------------------------------
# redact_dict tests (always run, regex backend)
# ---------------------------------------------------------------------------


class TestRedactDict:
    """Deep-redaction of structured payloads."""

    def test_flat_dict_string_values(self) -> None:
        r = _make_regex_redactor()
        payload = {"email": "user@corp.example.com", "note": "nothing sensitive"}
        result = r.redact_dict(payload)
        assert "user@corp.example.com" not in result["email"]
        assert "<EMAIL_ADDRESS>" in result["email"]
        assert result["note"] == "nothing sensitive"

    def test_nested_dict(self) -> None:
        r = _make_regex_redactor()
        payload = {
            "user": {"contact": "admin@example.org", "role": "admin"},
            "meta": {"ssn": "321-54-9876"},
        }
        result = r.redact_dict(payload)
        assert "admin@example.org" not in result["user"]["contact"]
        assert "<EMAIL_ADDRESS>" in result["user"]["contact"]
        assert "321-54-9876" not in result["meta"]["ssn"]
        assert "<US_SSN>" in result["meta"]["ssn"]

    def test_list_values_redacted(self) -> None:
        r = _make_regex_redactor()
        payload = {"notes": ["call 555-987-6543", "regular note"]}
        result = r.redact_dict(payload)
        assert "555-987-6543" not in result["notes"][0]
        assert "<PHONE_NUMBER>" in result["notes"][0]
        assert result["notes"][1] == "regular note"

    def test_non_string_values_pass_through(self) -> None:
        r = _make_regex_redactor()
        payload = {"count": 42, "active": True, "data": None}
        result = r.redact_dict(payload)
        assert result["count"] == 42
        assert result["active"] is True
        assert result["data"] is None

    def test_dict_keys_not_redacted(self) -> None:
        # Keys should be preserved even if they look like PII
        r = _make_regex_redactor()
        payload = {"admin@example.com": "value"}
        result = r.redact_dict(payload)
        assert "admin@example.com" in result  # key unchanged

    def test_empty_dict(self) -> None:
        r = _make_regex_redactor()
        assert r.redact_dict({}) == {}


# ---------------------------------------------------------------------------
# Presidio backend (skipped when model unavailable)
# ---------------------------------------------------------------------------


def _presidio_available() -> bool:
    try:
        import spacy  # noqa: F401

        spacy.load("en_core_web_sm")
        import presidio_analyzer  # noqa: F401
        import presidio_anonymizer  # noqa: F401

        return True
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.skipif(not _presidio_available(), reason="Presidio/spaCy model not available")
class TestPresidioBackend:
    """Tests run only when the full Presidio stack + spaCy model is installed."""

    @pytest.fixture(scope="class")
    def r(self) -> Redactor:
        return Redactor(force_regex=False)

    def test_backend_is_presidio(self, r: Redactor) -> None:
        assert r.backend == "presidio"

    def test_email_redacted(self, r: Redactor) -> None:
        result = r.redact_text("Contact bob@example.com for assistance")
        assert "bob@example.com" not in result
        # Presidio uses <EMAIL_ADDRESS>
        assert "<EMAIL_ADDRESS>" in result or "<" in result  # placeholder present

    def test_raw_pii_absent(self, r: Redactor) -> None:
        text = "SSN 111-22-3333 and phone 212-555-9876"
        result = r.redact_text(text)
        assert "111-22-3333" not in result
        assert "212-555-9876" not in result
