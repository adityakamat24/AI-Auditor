"""LiteLLMJudge output parsing — must survive fenced / prose-wrapped JSON (live models do this)."""

from __future__ import annotations

import json

from auditor.judge.client import LiteLLMJudge, _extract_json_block


def test_extract_json_from_markdown_fence() -> None:
    # This is exactly what Anthropic-via-LiteLLM returns: a ```json ... ``` fence.
    raw = '```json\n{\n  "verdict": "OK"\n}\n```'
    assert json.loads(_extract_json_block(raw))["verdict"] == "OK"


def test_extract_json_bare_and_prose_wrapped() -> None:
    assert json.loads(_extract_json_block('{"verdict": "OK"}'))["verdict"] == "OK"
    wrapped = 'Here is my assessment:\n{"verdict": "VIOLATION"}\nThat is all.'
    assert json.loads(_extract_json_block(wrapped))["verdict"] == "VIOLATION"


def test_parse_handles_fenced_output() -> None:
    raw = '```json\n{"verdict":"VIOLATION","confidence":0.92,"rubric_scores":{"adherence":0.1},' \
          '"evidence":[{"event_id":null,"reason":"off-task exfiltration"}]}\n```'
    result = LiteLLMJudge._parse(raw, "INSTRUCTION_FOLLOWING", "claude-haiku-4-5-20251001", 1)
    assert result.verdict == "VIOLATION"
    assert result.confidence == 0.92
    assert not result.abstain
    assert result.rubric_scores["adherence"] == 0.1
    assert result.evidence[0].reason == "off-task exfiltration"


def test_parse_truly_unparseable_abstains() -> None:
    result = LiteLLMJudge._parse("I cannot answer that.", "ASI01", "m", 1)
    assert result.abstain and result.verdict == "NEEDS_REVIEW"
