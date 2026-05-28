"""PII / secret scanner for the inline gate - Presidio-backed (PRD §9.4.2).

Lazy, shared ``AnalyzerEngine`` (spaCy ``en_core_web_sm``); analysis runs in a worker thread
(``asyncio.to_thread``) so the sync/CPU-bound NER never blocks the event loop. Decision logic:
- critical entity (private key, AWS/API secret) in outbound payload → DENY
- high entity (SSN, credit card, passport) → DENY (or CONFIRM to an allowlisted destination)
- medium (email/phone/IP) → log only.
"""

from __future__ import annotations

import asyncio
from typing import Any

from auditor.logging import get_logger

log = get_logger("auditor.gate.pii")

CRITICAL_ENTITIES = {"PRIVATE_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "GENERIC_API_KEY"}
HIGH_ENTITIES = {"US_SSN", "CREDIT_CARD", "US_PASSPORT"}
MEDIUM_ENTITIES = {"EMAIL_ADDRESS", "PHONE_NUMBER", "IP_ADDRESS"}
_ALL = CRITICAL_ENTITIES | HIGH_ENTITIES | MEDIUM_ENTITIES


class PiiScanner:
    def __init__(self, model_name: str = "en_core_web_sm") -> None:
        self._model_name = model_name
        self._analyzer: Any | None = None

    def _ensure(self) -> Any:
        if self._analyzer is None:
            from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
            from presidio_analyzer.nlp_engine import NlpEngineProvider

            nlp = NlpEngineProvider(
                nlp_configuration={
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": self._model_name}],
                }
            ).create_engine()
            analyzer = AnalyzerEngine(nlp_engine=nlp)
            analyzer.registry.add_recognizer(
                PatternRecognizer(
                    supported_entity="PRIVATE_KEY",
                    patterns=[Pattern("private_key", r"-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----", 0.9)],
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
            self._analyzer = analyzer
            log.info("pii.analyzer_ready", model=self._model_name)
        return self._analyzer

    def _scan_sync(self, text: str) -> list[str]:
        results = self._ensure().analyze(text=text, language="en", entities=sorted(_ALL))
        return [r.entity_type for r in results]

    async def scan(self, text: str) -> list[str]:
        if not text:
            return []
        return await asyncio.to_thread(self._scan_sync, text)

    async def evaluate_outbound(self, text: str, *, allowlisted_dest: bool = False) -> dict:
        types = set(await self.scan(text))
        critical = types & CRITICAL_ENTITIES
        high = types & HIGH_ENTITIES
        decision, reasons = "ALLOW", []
        if critical:
            decision = "DENY"
            reasons.append(f"secret in outbound payload: {sorted(critical)}")
        elif high:
            if allowlisted_dest:
                decision = "CONFIRM"
                reasons.append(f"PII to allowlisted destination: {sorted(high)}")
            else:
                decision = "DENY"
                reasons.append(f"PII to non-allowlisted destination: {sorted(high)}")
        return {"decision": decision, "reasons": reasons, "entities": sorted(types)}


__all__ = ["PiiScanner", "CRITICAL_ENTITIES", "HIGH_ENTITIES", "MEDIUM_ENTITIES"]
