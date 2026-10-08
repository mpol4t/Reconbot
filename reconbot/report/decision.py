from __future__ import annotations

from typing import Any


DISCOVERY_CONFIDENCE_FACTORS: dict[str, float] = {
    "CRITICAL": 0.30,
    "LOW": 0.50,
    "MEDIUM": 0.75,
    "HIGH": 1.00,
}


def scale_confidence_value(raw_value: Any, factor: float) -> int:
    try:
        base = int(raw_value or 0)
    except Exception:
        base = 0
    scaled = int(round(max(0, min(100, base)) * max(0.0, float(factor or 0.0))))
    return max(0, min(100, scaled))


def _confidence_label_rank(label: str) -> int:
    normalized = str(label or "").strip().lower()
    if normalized == "high":
        return 3
    if normalized == "medium":
        return 2
    return 1


def merge_confidence_labels(primary: str, secondary: str) -> str:
    merged_rank = min(_confidence_label_rank(primary), _confidence_label_rank(secondary))
    if merged_rank >= 3:
        return "High"
    if merged_rank == 2:
        return "Medium"
    return "Low"
