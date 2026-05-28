"""The four operator-facing checks (the product's headline lenses) and the detectors behind each.

The detection engine is the ten ASI detectors + the divergence/integrity detectors; operators don't think
in ASI codes, they ask four questions:

1. **Instruction Following** - is the agent doing what the user asked, or deviating?
2. **Unauthorized Access** - is it touching files/resources/tools it shouldn't?
3. **Data Exfiltration** - is it sending or writing data out?
4. **Sensitive-Data Hygiene** - is it putting secrets/PII into memory or logs?

This module maps each detector to its **primary** check so a Flag can be presented under these four lenses.
A few detectors span two concerns (e.g. ASI01 goal-hijack is primarily instruction-following but its
egress facet is exfiltration); we assign the dominant lens and keep the full per-detector detail underneath.
"""

from __future__ import annotations

from enum import StrEnum


class Check(StrEnum):
    INSTRUCTION_FOLLOWING = "instruction_following"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXFILTRATION = "data_exfiltration"
    SENSITIVE_DATA_HYGIENE = "sensitive_data_hygiene"


CHECK_TITLES: dict[Check, str] = {
    Check.INSTRUCTION_FOLLOWING: "Instruction Following",
    Check.UNAUTHORIZED_ACCESS: "Unauthorized Access",
    Check.DATA_EXFILTRATION: "Data Exfiltration",
    Check.SENSITIVE_DATA_HYGIENE: "Sensitive-Data Hygiene",
}

CHECK_QUESTIONS: dict[Check, str] = {
    Check.INSTRUCTION_FOLLOWING: "Is the agent doing what the user asked, or deviating?",
    Check.UNAUTHORIZED_ACCESS: "Is it touching files, resources, or tools it shouldn't?",
    Check.DATA_EXFILTRATION: "Is it sending or writing data out?",
    Check.SENSITIVE_DATA_HYGIENE: "Is it putting secrets or PII into memory or logs?",
}

# Primary check per detector name. (The divergence detector emits per-category verdicts; see
# ``check_for_category`` for the category-keyed fallback used by detectors that aren't named here.)
DETECTOR_CHECK: dict[str, Check] = {
    "instruction_following": Check.INSTRUCTION_FOLLOWING,
    "asi01_goal_hijack": Check.INSTRUCTION_FOLLOWING,
    "asi10_rogue_agent": Check.INSTRUCTION_FOLLOWING,
    "asi09_trust_exploit": Check.INSTRUCTION_FOLLOWING,
    "asi02_tool_misuse": Check.UNAUTHORIZED_ACCESS,
    "asi03_identity_abuse": Check.UNAUTHORIZED_ACCESS,
    "asi04_supply_chain": Check.UNAUTHORIZED_ACCESS,
    "asi04_catalog_integrity": Check.UNAUTHORIZED_ACCESS,
    "asi05_code_execution": Check.UNAUTHORIZED_ACCESS,
    "asi08_cascading": Check.UNAUTHORIZED_ACCESS,
    "asi07_inter_agent": Check.DATA_EXFILTRATION,
    "channel_divergence": Check.DATA_EXFILTRATION,
    "asi06_memory_poisoning": Check.SENSITIVE_DATA_HYGIENE,
}

# Category-keyed fallback (used when a verdict's detector name isn't in DETECTOR_CHECK - e.g. divergence
# findings tagged by ASI category).
_CATEGORY_CHECK: dict[str, Check] = {
    "INSTRUCTION_FOLLOWING": Check.INSTRUCTION_FOLLOWING,
    "ASI01": Check.INSTRUCTION_FOLLOWING,
    "ASI10": Check.INSTRUCTION_FOLLOWING,
    "ASI09": Check.INSTRUCTION_FOLLOWING,
    "ASI02": Check.UNAUTHORIZED_ACCESS,
    "ASI03": Check.UNAUTHORIZED_ACCESS,
    "ASI04": Check.UNAUTHORIZED_ACCESS,
    "ASI05": Check.UNAUTHORIZED_ACCESS,
    "ASI08": Check.UNAUTHORIZED_ACCESS,
    "ASI07": Check.DATA_EXFILTRATION,
    "ASI06": Check.SENSITIVE_DATA_HYGIENE,
}


def check_for_detector(detector: str, asi_category: str | None = None) -> Check | None:
    """Return the operator check a detector maps to, falling back to its ASI category."""
    if detector in DETECTOR_CHECK:
        return DETECTOR_CHECK[detector]
    if asi_category and asi_category in _CATEGORY_CHECK:
        return _CATEGORY_CHECK[asi_category]
    return None


def checks_for_verdicts(verdicts: list) -> dict[str, list]:
    """Group non-OK verdicts by operator check (Check value -> list of verdicts)."""
    grouped: dict[str, list] = {}
    for verdict in verdicts:
        result = getattr(getattr(verdict, "result", None), "value", getattr(verdict, "result", None))
        if result == "OK":
            continue
        check = check_for_detector(
            getattr(verdict, "detector", ""), getattr(verdict, "asi_category", None)
        )
        if check is not None:
            grouped.setdefault(check.value, []).append(verdict)
    return grouped


__all__ = [
    "Check",
    "CHECK_TITLES",
    "CHECK_QUESTIONS",
    "DETECTOR_CHECK",
    "check_for_detector",
    "checks_for_verdicts",
]
