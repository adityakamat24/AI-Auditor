"""Cross-run behavioral baselines for ASI10 (PRD §9.7.10, §15 Phase-4).

Maintains a per-(tenant, role) rolling distribution of run summary statistics ("axes" such as
``tool_calls``, ``distinct_tools``, ``egress_count``) so a single run can be scored for drift against
the role's historical norm. After each run the pipeline calls :meth:`BaselineStore.observe`; before
scoring a run it calls :meth:`BaselineStore.baseline`, which yields exactly the
``{"z_threshold", "axes": {axis: {"mean", "std"}}}`` shape the ASI10 detector consumes.

The running mean/variance use Welford's online algorithm (numerically stable, O(1) memory per axis). The
PRD references a t-digest; a t-digest adds *quantile* estimation, which we don't need for z-score drift —
mean/std are sufficient and exact for streaming updates. A t-digest (or a Redis-backed store) can replace
the in-memory accumulator behind the same interface if quantile-based gating is added later.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from uuid import UUID

DEFAULT_Z_THRESHOLD = 3.0


@dataclass
class _Running:
    """Welford online mean/variance for one axis."""

    count: int = 0
    mean: float = 0.0
    m2: float = 0.0

    def update(self, value: float) -> None:
        self.count += 1
        delta = value - self.mean
        self.mean += delta / self.count
        self.m2 += delta * (value - self.mean)

    @property
    def std(self) -> float:
        # Sample standard deviation; undefined for n<2, reported as 0 (the detector skips std<=0 axes).
        return math.sqrt(self.m2 / (self.count - 1)) if self.count >= 2 else 0.0


@dataclass
class BaselineStore:
    """Accumulates per-(tenant, role) run statistics and emits baselines for the ASI10 detector."""

    z_threshold: float = DEFAULT_Z_THRESHOLD
    _stats: dict[tuple[str, str], dict[str, _Running]] = field(default_factory=dict)

    def observe(self, *, tenant_id: UUID | str, role: str, run_stats: dict[str, float]) -> None:
        """Fold one completed run's summary stats into the (tenant, role) baseline."""
        axes = self._stats.setdefault((str(tenant_id), role), {})
        for axis, value in run_stats.items():
            axes.setdefault(axis, _Running()).update(float(value))

    def observation_count(self, *, tenant_id: UUID | str, role: str, axis: str) -> int:
        axes = self._stats.get((str(tenant_id), role), {})
        running = axes.get(axis)
        return running.count if running else 0

    def baseline(self, *, tenant_id: UUID | str, role: str) -> dict | None:
        """Return the baseline dict the ASI10 detector consumes, or None if nothing observed yet."""
        axes = self._stats.get((str(tenant_id), role))
        if not axes:
            return None
        return {
            "z_threshold": self.z_threshold,
            "axes": {axis: {"mean": r.mean, "std": r.std} for axis, r in axes.items()},
        }


__all__ = ["BaselineStore", "DEFAULT_Z_THRESHOLD"]
