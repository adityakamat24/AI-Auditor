"""Sysmon XML -> event-schema translator (PRD §9.2.2).

Pure translation from rendered Sysmon ``Microsoft-Windows-Sysmon/Operational`` event XML to the
cross-platform involuntary ``Syscall*`` / ``DnsQueryEvent`` schemas (``channel = INVOLUNTARY``). This
module is deliberately **side-effect free and Windows-API free** (stdlib + ``auditor`` only) so it
imports anywhere and is fully unit-testable on any platform.

Sysmon EventID -> schema mapping:

==========  =======================  =============================================================
 EventID     Sysmon event             Normalized event
==========  =======================  =============================================================
 1           ProcessCreate            ``SyscallExecve`` (binary=Image, argv from CommandLine)
 3           NetworkConnect           ``SyscallConnect`` (family from SourceIsIpv6, addr/port=Dest*)
 11          FileCreate               ``SyscallOpenat`` (path=TargetFilename, flags=0)
 22          DnsQuery                 ``DnsQueryEvent`` (query_name=QueryName, results=QueryResults)
 23          FileDelete               ``SyscallOpenat`` (path=TargetFilename, flags=0) — see note
 *           anything else            ``None`` (unmapped — caller drops it)
==========  =======================  =============================================================

Notes / mapping decisions:

* **EventID 23 (FileDelete)** is mapped to ``SyscallOpenat`` (a file *touch*). The normalized schema
  has no delete event; the channel-divergence detector cares that the harness touched a sensitive
  path, not the access mode. ``flags`` stays ``0`` (we do not synthesize ``O_*`` constants — Sysmon
  does not report Windows ``CreateFile`` desired-access in a portable way).
* **EventID 10 (ProcessAccess)** returns ``None`` for now. It is relevant to ASI03 (identity abuse,
  one process opening another) but there is no faithful ``Syscall*`` target — it is neither a connect
  nor an openat. It is handled in a later phase (P4); mapping it here would be a lie to the detector.
* **EventID 13 (RegistryValueSet)** returns ``None`` (Windows-specific; no portable schema).
* ``pid`` comes from the ``ProcessId`` ``EventData`` field, which Sysmon renders in **decimal**.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET  # noqa: S405 - parsing our own EvtRender output, not untrusted XML
from datetime import UTC, datetime
from uuid import UUID

from auditor.events.schemas import (
    BaseEvent,
    DnsQueryEvent,
    SyscallConnect,
    SyscallExecve,
    SyscallOpenat,
)
from auditor.ids import uuid7

# Sysmon events live in the Windows event-schema namespace.
_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
# Sysmon renders UtcTime like "2026-05-27 18:30:01.123".
_SYSMON_TS_FMT = "%Y-%m-%d %H:%M:%S.%f"


def _localname(tag: str) -> str:
    """Strip an ``{namespace}local`` ElementTree tag down to ``local``."""
    return tag.rsplit("}", 1)[-1]


def _find_child(elem: ET.Element | None, local: str) -> ET.Element | None:
    """Find a direct child by local name, ignoring XML namespace."""
    if elem is None:
        return None
    for child in elem:
        if _localname(child.tag) == local:
            return child
    return None


def parse_event_data(xml_str: str) -> dict:
    """Parse a rendered Sysmon event XML string into a flat dict.

    Returns ``{"event_id": <int System/EventID>, "process_id": <int> | None,
    "image": <str> | None, **{Data@Name: text for every EventData/Data}}``.

    The XML namespace is stripped when locating ``System``/``EventID``/``EventData``/``Data`` so the
    function works regardless of the namespace prefix the renderer chose. Robust to missing fields.
    """
    root = ET.fromstring(xml_str)  # noqa: S314 - input is our own EvtRender XML, not attacker-controlled

    system = _find_child(root, "System")
    event_id_elem = _find_child(system, "EventID")
    event_id: int | None = None
    if event_id_elem is not None and event_id_elem.text and event_id_elem.text.strip():
        event_id = int(event_id_elem.text.strip())

    data: dict = {"event_id": event_id, "process_id": None, "image": None}

    event_data = _find_child(root, "EventData")
    if event_data is not None:
        for child in event_data:
            if _localname(child.tag) != "Data":
                continue
            name = child.get("Name")
            if name is None:
                continue
            data[name] = child.text  # may be None for empty <Data/> elements

    process_id_raw = data.get("ProcessId")
    if process_id_raw is not None and str(process_id_raw).strip():
        data["process_id"] = int(str(process_id_raw).strip())
    data["image"] = data.get("Image")
    return data


def _parse_ts(utc_time: str | None) -> datetime:
    """Parse a Sysmon ``UtcTime`` field; fall back to ``now(UTC)`` when absent/malformed."""
    if utc_time:
        try:
            return datetime.strptime(utc_time.strip(), _SYSMON_TS_FMT).replace(tzinfo=UTC)
        except ValueError:
            pass
    return datetime.now(UTC)


def _header(data: dict, *, run_id: UUID, tenant_id: UUID) -> dict:
    """Build the common :class:`BaseEvent` header fields from parsed Sysmon data."""
    pid = data.get("process_id")
    return {
        "event_id": uuid7(),
        "run_id": run_id,
        "tenant_id": tenant_id,
        "span_id": uuid7(),
        "ts": _parse_ts(data.get("UtcTime")),
        "pid": int(pid) if pid is not None else None,
    }


def _argv_from_command_line(command_line: str | None) -> list[str]:
    """Best-effort argv from a Sysmon ``CommandLine`` string.

    Whitespace-split (no shell-quoting awareness — Sysmon does not expose a tokenized argv on
    Windows). Falls back to a single-element list so quoted commands are not silently dropped.
    """
    if not command_line:
        return []
    parts = command_line.split()
    return parts if parts else [command_line]


def translate(xml_str: str, *, run_id: UUID, tenant_id: UUID) -> BaseEvent | None:
    """Translate one rendered Sysmon event XML into a normalized involuntary event.

    Returns ``None`` for Sysmon EventIDs that have no faithful ``Syscall*`` mapping (see module
    docstring). ``run_id`` / ``tenant_id`` are supplied by the observer; ``event_id`` / ``span_id``
    are freshly minted UUIDv7s.
    """
    data = parse_event_data(xml_str)
    event_id = data.get("event_id")
    if event_id is None:
        return None

    header = _header(data, run_id=run_id, tenant_id=tenant_id)

    if event_id == 1:  # ProcessCreate ~ execve
        return SyscallExecve(
            binary=data.get("Image") or "",
            argv=_argv_from_command_line(data.get("CommandLine")),
            **header,
        )

    if event_id == 3:  # NetworkConnect ~ connect / tcp_v4_connect
        is_ipv6 = (data.get("SourceIsIpv6") or "").strip().lower() == "true"
        port_raw = data.get("DestinationPort")
        return SyscallConnect(
            family="AF_INET6" if is_ipv6 else "AF_INET",
            addr=data.get("DestinationIp") or data.get("DestinationHostname") or "",
            port=int(port_raw) if port_raw and str(port_raw).strip() else None,
            **header,
        )

    if event_id == 11:  # FileCreate ~ openat with create intent
        return SyscallOpenat(path=data.get("TargetFilename") or "", flags=0, **header)

    if event_id == 22:  # DnsQuery
        raw_results = data.get("QueryResults") or ""
        # Sysmon QueryResults look like "type:  5 a1.example.com;::ffff:1.2.3.4;" — keep non-empty
        # tokens and strip the leading "type: N " annotation Sysmon sometimes prepends.
        results = [r.strip() for r in raw_results.split(";") if r.strip()]
        return DnsQueryEvent(query_name=data.get("QueryName") or "", results=results, **header)

    if event_id == 23:  # FileDelete — treat as a file touch (see module docstring)
        return SyscallOpenat(path=data.get("TargetFilename") or "", flags=0, **header)

    # EventID 10 (ProcessAccess), 13 (RegistryValueSet), and anything else: unmapped for now.
    return None


__all__ = ["parse_event_data", "translate"]
