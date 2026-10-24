from typing import List, Dict, Any


def calculate_confidence(evidence_results: List[Dict[str, Any]]) -> float:
    """
    Calculate overall investigation confidence score as a percentage (0.0 to 100.0).

    Weighted formula:
    - Verified / Corroborated evidence = 1.0 weight
    - Inferred evidence = 0.6 weight
    - Insufficient evidence = 0.0 weight
    """
    if not evidence_results:
        return 0.0

    verified = sum(
        1 for item in evidence_results
        if item.get("evidence_status") == "Verified"
    )

    inferred = sum(
        1 for item in evidence_results
        if item.get("evidence_status") == "Inferred"
    )

    total = len(evidence_results)
    if total == 0:
        return 0.0

    score = ((verified * 1.0) + (inferred * 0.6)) / total
    return round(score * 100.0, 2)


def calculate_confidence_breakdown(evidence_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Provide detailed, explainable confidence audit breakdown."""
    if not evidence_results:
        return {
            "confidence": 0.0,
            "total_events": 0,
            "verified_count": 0,
            "inferred_count": 0,
            "corroborated_count": 0,
            "strength": "None",
            "formula": "((verified * 1.0) + (inferred * 0.6)) / total * 100",
        }

    verified = sum(1 for item in evidence_results if item.get("evidence_status") == "Verified")
    inferred = sum(1 for item in evidence_results if item.get("evidence_status") == "Inferred")
    corroborated = sum(1 for item in evidence_results if item.get("evidence_tier") == "corroborated")
    total = len(evidence_results)

    conf = calculate_confidence(evidence_results)

    strength = "Strong" if conf >= 85.0 else ("Moderate" if conf >= 60.0 else "Weak")

    return {
        "confidence": conf,
        "total_events": total,
        "verified_count": verified,
        "inferred_count": inferred,
        "corroborated_count": corroborated,
        "strength": strength,
        "formula": "((verified * 1.0) + (inferred * 0.6)) / total * 100",
    }


def calculate_completeness(timeline: List[Dict[str, Any]], expected_stages: List[str]) -> float:
    """
    Calculate attack stage coverage completeness against expected kill-chain stages.

    Returns completeness percentage (0.0 to 100.0).
    """
    if not expected_stages:
        return 0.0

    observed_stages = {
        item.get("stage")
        for item in timeline
        if item.get("stage")
    }

    matched = observed_stages.intersection(set(expected_stages))

    return round(
        len(matched) / len(expected_stages) * 100.0,
        2
    )

