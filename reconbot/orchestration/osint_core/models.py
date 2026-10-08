"""Shared passive OSINT collector contracts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PassiveCollectorResult:
    """Normalized shape for future passive OSINT collectors.

    Future leak/darkweb-style collectors must return redacted public metadata
    only: source health row data, observed evidence rows with redacted snippets,
    no credential material, no account/password collection, no secret
    validation, and `risk_score_impact=0` unless a separate validated exposure
    rule is explicitly introduced.
    """

    source: dict[str, Any]
    signals: list[dict[str, Any]] = field(default_factory=list)
    suppressed: list[dict[str, Any]] = field(default_factory=list)
    operator_tasks: list[dict[str, Any]] = field(default_factory=list)

