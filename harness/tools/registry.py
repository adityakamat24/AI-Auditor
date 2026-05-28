"""Tool catalog (PRD §9.7.4).

Maps each instrumented tool's catalog name to its callable and computes a stable per-tool schema hash
(name + sorted parameter names). The auditor compares a tool call's ``schema_hash`` against this catalog to
detect supply-chain tampering (ASI04, wired later).
"""

from __future__ import annotations

import hashlib
import inspect
from collections.abc import Callable

from harness.tools.atomicwork.create_ticket import create_ticket
from harness.tools.atomicwork.kb_search import kb_search
from harness.tools.atomicwork.query_employee import query_employee
from harness.tools.atomicwork.reset_password import reset_password
from harness.tools.atomicwork.send_email import send_email
from harness.tools.generic.exec_shell import exec_shell
from harness.tools.generic.file_read import file_read
from harness.tools.generic.file_write import file_write
from harness.tools.generic.http_get import http_get
from harness.tools.generic.http_post import http_post

_ALL_TOOLS: tuple[Callable, ...] = (
    kb_search,
    create_ticket,
    query_employee,
    reset_password,
    send_email,
    http_get,
    http_post,
    file_read,
    file_write,
    exec_shell,
)


def schema_hash(fn: Callable) -> str:
    """Return a stable sha256 hex over the tool's name and its sorted parameter names."""
    params = sorted(inspect.signature(fn).parameters)
    payload = f"{fn.tool_meta.name}:{params}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


TOOL_CATALOG: dict[str, Callable] = {fn.tool_meta.name: fn for fn in _ALL_TOOLS}


def get_tool(name: str) -> Callable:
    """Return the tool callable registered under ``name`` (raises ``KeyError`` if unknown)."""
    return TOOL_CATALOG[name]


__all__ = ["schema_hash", "TOOL_CATALOG", "get_tool"]
