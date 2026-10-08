from __future__ import annotations

from typing import Any


def compute_ffuf_scoring_contribution(scoring_inputs: dict[str, Any] | None) -> dict[str, Any]:
    """Compute bounded, explainable FFUF score contribution.

    This policy intentionally avoids raw-path-volume amplification:
    - scores per family (not per finding),
    - applies one capped booster per family for correlated signals,
    - caps global impact on risk/priority.
    """
    scoring_inputs = scoring_inputs if isinstance(scoring_inputs, dict) else {}
    raw_signals = scoring_inputs.get("ffuf_family_signals", [])
    family_signals = raw_signals if isinstance(raw_signals, list) else []

    effective_units = 0
    high_value_family_count = 0
    sensitive_marker_family_count = 0
    security_query_family_count = 0
    diverse_family_count = 0
    unique_family_count = 0
    confirmed_family_count = 0

    for item in family_signals:
        if not isinstance(item, dict):
            continue

        is_unique = bool(item.get("ffuf_unique"))
        is_confirmed = bool(item.get("ffuf_confirmed_by_other_tools"))
        is_high_value = bool(item.get("high_value_bucket"))
        is_sensitive_marker = bool(item.get("sensitive_marker"))
        has_sec_query = bool(item.get("security_relevant_query"))
        has_diversity = bool(item.get("meaningful_response_diversity"))

        if is_unique:
            unique_family_count += 1
        if is_confirmed:
            confirmed_family_count += 1
        if is_high_value:
            high_value_family_count += 1
        if is_sensitive_marker:
            sensitive_marker_family_count += 1
        if has_sec_query:
            security_query_family_count += 1
        if has_diversity:
            diverse_family_count += 1

        # Base family weight (mutually exclusive base class).
        if is_unique:
            family_units = 3
        elif is_confirmed:
            family_units = 2
        else:
            family_units = 1

        # Anti-double-count rule:
        # correlated quality signals contribute at most +1 per family.
        if is_high_value or is_sensitive_marker or has_sec_query or has_diversity:
            family_units += 1

        # Hard cap per family.
        family_units = min(4, family_units)
        effective_units += family_units

    overlap_ratio = float(scoring_inputs.get("ffuf_overlap_ratio", 0.0) or 0.0)
    overlap_penalty = int(round(min(8.0, max(0.0, overlap_ratio) * 8.0)))

    risk_bonus = max(0, min(12, effective_units - overlap_penalty))
    if (
        confirmed_family_count > 0
        and overlap_ratio < 0.75
        and (high_value_family_count > 0 or sensitive_marker_family_count > 0 or security_query_family_count > 0 or diverse_family_count > 0)
    ):
        risk_bonus = min(14, risk_bonus + min(2, confirmed_family_count))

    priority_count = max(
        unique_family_count,
        high_value_family_count,
        sensitive_marker_family_count,
    )
    priority_score = 0
    if priority_count > 0:
        priority_score = max(
            52,
            min(72, 56 + min(10, int(effective_units / 2)) - overlap_penalty),
        )

    why = (
        "FFUF katkısı aile-bazlı normalize edilir; unique/confirmed sinyal tabanı "
        "ve tek booster kuralı ile hacim kaynaklı şişme engellenir."
    )
    test_first = (
        "FFUF high-value/sensitive family representative endpointlerde auth/access control, "
        "debug exposure ve sensitive-file kontrollerini önceliklendir."
    )
    signals = [
        f"ffuf_unique_clusters={unique_family_count}",
        f"ffuf_confirmed_clusters={confirmed_family_count}",
        f"ffuf_high_value_clusters={high_value_family_count}",
        f"ffuf_sensitive_marker_clusters={sensitive_marker_family_count}",
        f"ffuf_security_relevant_clusters={security_query_family_count}",
        f"ffuf_diverse_response_clusters={diverse_family_count}",
        f"ffuf_overlap_ratio={overlap_ratio:.2f}",
        f"ffuf_effective_units={effective_units}",
        f"ffuf_overlap_penalty={overlap_penalty}",
        "anti_double_count=single_booster_per_family",
    ]

    return {
        "risk_bonus": risk_bonus,
        "priority_count": priority_count,
        "priority_score": priority_score,
        "why": why,
        "test_first": test_first,
        "signals": signals,
        "metrics": {
            "ffuf_unique_clusters": unique_family_count,
            "ffuf_confirmed_clusters": confirmed_family_count,
            "ffuf_high_value_clusters": high_value_family_count,
            "ffuf_sensitive_marker_clusters": sensitive_marker_family_count,
            "ffuf_security_relevant_clusters": security_query_family_count,
            "ffuf_diverse_response_clusters": diverse_family_count,
            "ffuf_overlap_ratio": overlap_ratio,
            "ffuf_effective_units": effective_units,
            "ffuf_overlap_penalty": overlap_penalty,
        },
    }
