"""Presidio scanner: deterministic custom recognizers (private key / API key) + severity tiers."""

from __future__ import annotations

import pytest
from auditor.inline_gate.pii_scanner import PiiScanner


@pytest.fixture(scope="module")
def scanner() -> PiiScanner:
    # One shared analyzer for the module (the spaCy model loads once on first scan).
    return PiiScanner()


async def test_private_key_denies(scanner: PiiScanner) -> None:
    text = "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIaBcD\n-----END RSA PRIVATE KEY-----"
    out = await scanner.evaluate_outbound(text)
    assert out["decision"] == "DENY"
    assert "PRIVATE_KEY" in out["entities"]


async def test_api_key_denies(scanner: PiiScanner) -> None:
    out = await scanner.evaluate_outbound("api_key=AKIA1234567890ABCDEFG_extra_long_value")
    assert out["decision"] == "DENY"
    assert "GENERIC_API_KEY" in out["entities"]


async def test_email_is_medium_allow(scanner: PiiScanner) -> None:
    # Email is a medium entity -> log-only, no gate impact.
    out = await scanner.evaluate_outbound("please contact alice@example.com")
    assert out["decision"] == "ALLOW"


async def test_clean_text_allows(scanner: PiiScanner) -> None:
    out = await scanner.evaluate_outbound("the quarterly report is ready for review")
    assert out["decision"] == "ALLOW"
