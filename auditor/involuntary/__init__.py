"""Involuntary backend selection (PRD §9.2.3).

Picks the platform backend at runtime. There is **no silent fallback** to a less-secure observer:
if no backend is available the call fails loudly.
"""

from __future__ import annotations

import sys

from auditor.involuntary.base import InvoluntaryObserver


def get_observer(*args: object, **kwargs: object) -> InvoluntaryObserver:
    """Instantiate the platform-appropriate involuntary observer."""
    if sys.platform == "win32":
        from auditor.involuntary.windows import SysmonObserver

        return SysmonObserver(*args, **kwargs)
    if sys.platform.startswith("linux"):
        from auditor.involuntary.linux import EbpfObserver

        return EbpfObserver(*args, **kwargs)
    raise RuntimeError(
        f"no involuntary telemetry backend available for platform {sys.platform!r} "
        "(supported: win32 via Sysmon, linux via eBPF)"
    )


__all__ = ["InvoluntaryObserver", "get_observer"]
