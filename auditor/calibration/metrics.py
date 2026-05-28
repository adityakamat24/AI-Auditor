"""Calibration metrics (PRD §9.12) — confusion matrix → precision/recall/F1/FP-rate.

Pure, dependency-free: turns ``(labeled_violation, predicted_violation)`` pairs into per-category detector
quality metrics used by the nightly run and the lifecycle gates. Binary task per ASI category: positive =
VIOLATION.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ConfusionMatrix:
    """Binary confusion matrix where positive = VIOLATION."""

    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    def add(self, *, labeled_violation: bool, predicted_violation: bool) -> None:
        if labeled_violation and predicted_violation:
            self.tp += 1
        elif labeled_violation and not predicted_violation:
            self.fn += 1
        elif (not labeled_violation) and predicted_violation:
            self.fp += 1
        else:
            self.tn += 1

    @property
    def n(self) -> int:
        return self.tp + self.fp + self.fn + self.tn

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fp_rate(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def has_positives(self) -> bool:
        """Whether any labeled VIOLATION exists — precision is only meaningful then."""
        return (self.tp + self.fn) > 0

    def as_dict(self) -> dict:
        return {
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fp_rate": round(self.fp_rate, 4),
            "tp": self.tp, "fp": self.fp, "fn": self.fn, "tn": self.tn, "n": self.n,
        }


def confusion_from_pairs(pairs: list[tuple[bool, bool]]) -> ConfusionMatrix:
    """Build a ConfusionMatrix from ``(labeled_violation, predicted_violation)`` pairs."""
    cm = ConfusionMatrix()
    for labeled, predicted in pairs:
        cm.add(labeled_violation=labeled, predicted_violation=predicted)
    return cm


def overall_metrics(per_category: dict[str, ConfusionMatrix]) -> dict:
    """Aggregate a micro-averaged overall metric block across categories."""
    total = ConfusionMatrix()
    for cm in per_category.values():
        total.tp += cm.tp
        total.fp += cm.fp
        total.fn += cm.fn
        total.tn += cm.tn
    return total.as_dict()


__all__ = ["ConfusionMatrix", "confusion_from_pairs", "overall_metrics"]
