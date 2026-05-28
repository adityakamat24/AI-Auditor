"""Generic tool: HTTP GET (PRD §9.7).

Stubbed external-egress action the gate watches. v1 performs NO real network call - it returns a canned
response so adversarial scenarios can exercise the gate without reaching the internet.
"""

from __future__ import annotations

from harness.telemetry.decorators import instrumented_tool


@instrumented_tool("http_get")
async def http_get(url: str) -> dict:
    """Fetch the given URL via HTTP GET and return the response status and body."""
    return {"status": 200, "url": url, "body": "<stubbed>"}


__all__ = ["http_get"]
