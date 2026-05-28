"""Windows Sysmon event subscriber (PRD §9.2.2).

Live wrapper around ``win32evtlog.EvtSubscribe`` for the ``Microsoft-Windows-Sysmon/Operational``
channel. On each delivered event it renders the record to XML with ``EvtRender`` and hands the XML
string to a user callback. Events are post-filtered by ``ProcessId`` against a set of PIDs (the
harness process and its descendants — the observer maintains that set).

All ``win32*`` (pywin32) imports are kept **inside methods** so importing this module never requires
the Windows-only ``windows`` extra. This class is the only piece that touches the OS; it is therefore
**not** covered by the cross-platform unit tests (the translator is). Exercising it for real requires:

* Sysmon (Sysinternals) installed and configured (``sysmon_config.xml``), a one-time admin step, and
* the auditor process to be a member of the built-in **Event Log Readers** group (admin not required
  after Sysmon is installed).

See PRD §9.2.2 for the documented limitations vs the Linux eBPF backend (50-200ms latency, no
per-read file event — file reads are approximated elsewhere via ``psutil`` polling).
"""

from __future__ import annotations

from collections.abc import Callable

# pywin32 is intentionally NOT imported at module top — it is a Windows-only optional extra.
SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"


class SysmonSubscriber:
    """Streams raw Sysmon event XML for a set of process IDs via ``EvtSubscribe``.

    Args:
        process_ids: PIDs to keep (the harness tree). ``None`` means *do not filter* — every Sysmon
            event on the channel is delivered (useful for tests/diagnostics).
    """

    def __init__(self, *, process_ids: set[int] | None = None) -> None:
        self._process_ids = process_ids
        self._callback: Callable[[str], None] | None = None
        self._subscription: object | None = None
        # Keep a strong reference to the bound C callback so it is not GC'd while the
        # subscription is live (pywin32 hands it to the OS; a freed callback would crash).
        self._native_cb: object | None = None

    def _matches(self, process_id: int | None) -> bool:
        """True if an event for ``process_id`` should be forwarded (post-filter)."""
        if self._process_ids is None:
            return True
        return process_id is not None and process_id in self._process_ids

    @staticmethod
    def _extract_process_id(xml_str: str) -> int | None:
        """Pull ``EventData/Data[@Name='ProcessId']`` (decimal) out of rendered XML, if present.

        Local, dependency-free parse (cannot import the translator here without creating a package
        import cycle through ``involuntary`` namespace tooling; the translator does the full mapping
        downstream). Returns ``None`` when the field is absent or unparseable.
        """
        import xml.etree.ElementTree as ET  # noqa: S405 - our own EvtRender output

        try:
            root = ET.fromstring(xml_str)  # noqa: S314 - trusted EvtRender XML
        except ET.ParseError:
            return None
        for elem in root.iter():
            if elem.tag.rsplit("}", 1)[-1] == "Data" and elem.get("Name") == "ProcessId":
                text = (elem.text or "").strip()
                if text:
                    try:
                        return int(text)
                    except ValueError:
                        return None
        return None

    def start(self, callback: Callable[[str], None]) -> None:
        """Subscribe to future Sysmon events; deliver matching events' XML to ``callback``.

        The subscription is push-based: pywin32 invokes our native callback on its own thread for
        each delivered record. We render the record to XML, post-filter by ``ProcessId``, and call
        the user callback. Exceptions from rendering are swallowed per-event so one bad record cannot
        tear down the subscription.
        """
        import win32evtlog

        self._callback = callback

        def _on_event(action: int, _context: object, handle: object) -> int:
            # EvtSubscribeActionDeliver == a record is ready; the other action is Error.
            if action != win32evtlog.EvtSubscribeActionDeliver:
                return 0
            try:
                xml_str = win32evtlog.EvtRender(handle, win32evtlog.EvtRenderEventXml)
            except Exception:  # noqa: BLE001 - never let one bad event kill the subscription
                return 0
            if self._matches(self._extract_process_id(xml_str)):
                self._callback(xml_str)
            return 0

        self._native_cb = _on_event
        self._subscription = win32evtlog.EvtSubscribe(
            SYSMON_CHANNEL,
            win32evtlog.EvtSubscribeToFutureEvents,
            None,  # Bookmark — None: start from now.
            Callback=_on_event,
            Context=None,
            Query=None,  # Server-side XPath; we post-filter by PID in Python instead.
        )

    def stop(self) -> None:
        """Cancel the subscription and release the native callback reference."""
        sub = self._subscription
        self._subscription = None
        self._callback = None
        if sub is not None:
            import contextlib

            import win32api

            with contextlib.suppress(Exception):  # best-effort teardown
                win32api.CloseHandle(sub)
        self._native_cb = None


__all__ = ["SysmonSubscriber", "SYSMON_CHANNEL"]
