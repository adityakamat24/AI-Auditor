"""PII redactor (PRD §9.11.2) — Presidio-backed with regex fallback.

Replaces PII spans with ``<ENTITY_TYPE>`` placeholders using Presidio's ``replace``
anonymisation strategy. Falls back to a pure-regex engine when Presidio or the spaCy
model is unavailable so the module is always importable and unit-testable without the
heavy NLP stack.

Usage::

    from auditor.audit_log.redactor import Redactor

    r = Redactor()
    clean = r.redact_text("Call me at 555-123-4567 or alice@example.com")
    # → "Call me at <PHONE_NUMBER> or <EMAIL_ADDRESS>"

    clean_dict = r.redact_dict({"msg": "SSN 123-45-6789"})
    # → {"msg": "SSN <US_SSN>"}
"""

from __future__ import annotations

import re
from typing import Any

from auditor.logging import get_logger

log = get_logger("auditor.audit_log.redactor")

# ---------------------------------------------------------------------------
# Regex fallback patterns (ordered: most-specific first to avoid partial clobber)
# ---------------------------------------------------------------------------
#
# Each entry is (pattern, replacement_tag).
# Applied in order — earlier patterns win on overlapping spans.

_REGEX_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # Generic API key / secret / token — MUST run first to avoid digit sub-patterns
    # matching inside the value before we get a chance to redact the whole field.
    # Matches: key=value or key: value styles, alphanumeric value ≥20 chars.
    (
        re.compile(
            r"(?i)(?:api[_\-]?key|secret|token|password)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}['\"]?"
        ),
        "<GENERIC_API_KEY>",
    ),
    # SSN: NNN-NN-NNNN (before credit-card and phone to avoid partial overlaps)
    (
        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "<US_SSN>",
    ),
    # Credit card: 13-19 digits, optionally space/dash separated
    (
        re.compile(
            r"\b(?:\d[ -]?){13,18}\d\b",
        ),
        "<CREDIT_CARD>",
    ),
    # Email address
    (
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "<EMAIL_ADDRESS>",
    ),
    # Phone: various formats (US-centric but catches international too)
    (
        re.compile(
            r"(?<!\d)"
            r"(?:\+?1[\s.\-]?)?"
            r"(?:\(?\d{3}\)?[\s.\-]?)"
            r"\d{3}[\s.\-]?\d{4}"
            r"(?!\d)"
        ),
        "<PHONE_NUMBER>",
    ),
]


def _regex_redact(text: str) -> str:
    """Apply regex patterns sequentially, replacing each match with its tag."""
    for pattern, tag in _REGEX_PATTERNS:
        text = pattern.sub(tag, text)
    return text


# ---------------------------------------------------------------------------
# Presidio engine (lazy-initialised at first use)
# ---------------------------------------------------------------------------

_ANALYZER: Any | None = None
_ANONYMIZER: Any | None = None
_PRESIDIO_AVAILABLE: bool | None = None  # None = not yet probed


def _try_init_presidio() -> bool:
    """Attempt to initialise Presidio engines; return True on success."""
    global _ANALYZER, _ANONYMIZER, _PRESIDIO_AVAILABLE  # noqa: PLW0603
    if _PRESIDIO_AVAILABLE is not None:
        return _PRESIDIO_AVAILABLE

    try:
        from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
        from presidio_analyzer.nlp_engine import NlpEngineProvider
        from presidio_anonymizer import AnonymizerEngine

        nlp = NlpEngineProvider(
            nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
            }
        ).create_engine()

        analyzer = AnalyzerEngine(nlp_engine=nlp)

        # Extra custom recognisers mirroring pii_scanner.py
        analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity="PRIVATE_KEY",
                patterns=[
                    Pattern(
                        "private_key",
                        r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----",
                        0.9,
                    )
                ],
            )
        )
        analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity="GENERIC_API_KEY",
                patterns=[
                    Pattern(
                        "generic_api_key",
                        r"(?i)(?:api[_-]?key|secret|token|password)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{20,}",
                        0.7,
                    )
                ],
            )
        )

        _ANALYZER = analyzer
        _ANONYMIZER = AnonymizerEngine()
        _PRESIDIO_AVAILABLE = True
        log.info("redactor.presidio_ready")

    except Exception as exc:  # noqa: BLE001
        _PRESIDIO_AVAILABLE = False
        log.warning("redactor.presidio_unavailable", error=str(exc))

    return _PRESIDIO_AVAILABLE


# ---------------------------------------------------------------------------
# Public Redactor class
# ---------------------------------------------------------------------------


class Redactor:
    """Redacts PII from text and structured payloads.

    Attributes
    ----------
    backend : str
        ``"presidio"`` when the Presidio engine initialised successfully,
        ``"regex"`` when falling back to the built-in regex patterns.
    """

    def __init__(self, *, force_regex: bool = False) -> None:
        """Initialise the redactor.

        Parameters
        ----------
        force_regex:
            When *True*, skip Presidio entirely and use the regex fallback.
            Useful in unit tests that must run without the spaCy model.
        """
        self._force_regex = force_regex
        if not force_regex:
            _try_init_presidio()

    @property
    def backend(self) -> str:
        """Which redaction backend is active: ``"presidio"`` or ``"regex"``."""
        if self._force_regex:
            return "regex"
        return "presidio" if _PRESIDIO_AVAILABLE else "regex"

    # ------------------------------------------------------------------
    # Core public methods
    # ------------------------------------------------------------------

    def redact_text(self, text: str) -> str:
        """Return *text* with PII spans replaced by ``<ENTITY_TYPE>`` tokens.

        Uses Presidio when available, regex fallback otherwise.
        """
        if not text:
            return text

        if self.backend == "presidio":
            return self._presidio_redact(text)
        return _regex_redact(text)

    def redact_dict(self, payload: dict) -> dict:
        """Deep-redact all string values in *payload* (nested dicts/lists supported)."""
        return self._redact_value(payload)  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _redact_value(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.redact_text(value)
        if isinstance(value, dict):
            return {k: self._redact_value(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self._redact_value(item) for item in value]
        return value

    @staticmethod
    def _presidio_redact(text: str) -> str:
        """Run Presidio analyze + anonymize (replace strategy)."""
        from presidio_anonymizer.entities import OperatorConfig

        results = _ANALYZER.analyze(text=text, language="en")
        if not results:
            return text

        # Build operator map: one "replace" operator per detected entity type.
        operators: dict[str, OperatorConfig] = {}
        for res in results:
            entity = res.entity_type
            if entity not in operators:
                operators[entity] = OperatorConfig(
                    "replace", {"new_value": f"<{entity}>"}
                )

        anonymized = _ANONYMIZER.anonymize(
            text=text,
            analyzer_results=results,
            operators=operators,
        )
        return anonymized.text


__all__ = ["Redactor"]
