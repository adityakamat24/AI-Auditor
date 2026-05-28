"""Generic tool: HTTP POST (PRD §9.7).

Stubbed external-egress action the gate watches (exfiltration risk). v1 performs NO real network call — it
returns a canned response so adversarial scenarios can exercise the gate without reaching the internet.
"""

from __future__ import annotations

from harness.telemetry.decorators import instrumented_tool


@instrumented_tool("http_post")
async def http_post(url: str, body: str = "") -> dict:
    """POST the given body to the URL via HTTP and return the response status."""
    return {"status": 200, "url": url}


__all__ = ["http_post"]
