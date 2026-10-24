from datetime import datetime, timezone
from typing import Any, Optional, Tuple, List, Dict
from models.event import SecurityEvent


def parse_timestamp(timestamp: Any) -> Optional[datetime]:
    """Parse ISO timestamp handling Z, UTC offsets, and malformed strings safely."""
    if not timestamp:
        return None
    if isinstance(timestamp, datetime):
        return timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)
    try:
        ts_str = str(timestamp).strip().replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_str)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None


def get_attr(event: Any, key: str, default: Any = None) -> Any:
    """Retrieve attribute from SecurityEvent object or dict safely."""
    if isinstance(event, dict):
        return event.get(key, default)
    return getattr(event, key, default)


def calculate_correlation(
    current: Any,
    next_event: Any,
    time_difference: float,
) -> Tuple[int, List[str], List[str], str]:
    """
    Calculate explainable correlation between two candidate events.

    Returns:
        (score, reasons, matched_fields, rationale)
    """
    score = 0
    reasons = []
    matched_fields = []

    c_user = get_attr(current, "user")
    n_user = get_attr(next_event, "user")
    if c_user and n_user and c_user == n_user:
        score += 1
        reasons.append("same_user")
        matched_fields.append("user")

    c_shost = get_attr(current, "source_host")
    n_shost = get_attr(next_event, "source_host")
    if c_shost and n_shost and c_shost == n_shost:
        score += 3
        reasons.append("same_source_host")
        matched_fields.append("source_host")

    c_dhost = get_attr(current, "destination_host")
    n_dhost = get_attr(next_event, "destination_host")
    if c_dhost and n_dhost and c_dhost == n_dhost:
        score += 2
        reasons.append("same_destination_host")
        matched_fields.append("destination_host")

    # Network Pivot Transition: current destination becomes next source host
    if c_dhost and n_shost and c_dhost == n_shost:
        score += 3
        reasons.append("network_pivot_transition")
        matched_fields.append("destination_to_source_pivot")

    # IP match
    c_sip = get_attr(current, "source_ip")
    n_sip = get_attr(next_event, "source_ip")
    if c_sip and n_sip and c_sip == n_sip:
        score += 1
        reasons.append("same_source_ip")
        matched_fields.append("source_ip")

    # Sequential process execution after authentication
    c_type = str(get_attr(current, "event_type", "")).lower()
    n_type = str(get_attr(next_event, "event_type", "")).lower()
    if "login" in c_type and ("process" in n_type or "exec" in n_type) and time_difference <= 180:
        score += 2
        reasons.append("auth_to_execution_sequence")
        matched_fields.append("attack_sequence")

    if time_difference <= 60:
        score += 1
        reasons.append("close_in_time")
        matched_fields.append("temporal_proximity")

    rationale_parts = []
    if "same_user" in reasons:
        rationale_parts.append(f"shared principal '{c_user}'")
    if "same_source_host" in reasons:
        rationale_parts.append(f"co-located on host '{c_shost}'")
    if "network_pivot_transition" in reasons:
        rationale_parts.append(f"lateral transition from {c_shost} to {n_shost}")
    if "same_destination_host" in reasons:
        rationale_parts.append(f"converging on target host '{c_dhost}'")
    if "auth_to_execution_sequence" in reasons:
        rationale_parts.append("immediate post-authentication execution")
    if "close_in_time" in reasons:
        rationale_parts.append(f"within {int(time_difference)}s")

    rationale = f"Correlated via {', '.join(rationale_parts)}." if rationale_parts else "Weak contextual correlation."

    return score, reasons, matched_fields, rationale


def correlate_events(
    events: List[Any],
    time_window_seconds: float = 300,
    minimum_score: int = 3,
) -> List[Dict[str, Any]]:
    """
    Correlate sequential events within a sliding time window.

    Supports both SecurityEvent objects and dictionaries.
    """
    correlations = []
    n = len(events)

    for i in range(n):
        current = events[i]
        c_time = parse_timestamp(get_attr(current, "timestamp"))
        if not c_time:
            continue

        c_id = get_attr(current, "event_id")

        for j in range(i + 1, n):
            next_event = events[j]
            n_time = parse_timestamp(get_attr(next_event, "timestamp"))
            if not n_time:
                continue

            time_difference = (n_time - c_time).total_seconds()
            if time_difference < 0:
                continue
            if time_difference > time_window_seconds:
                break

            score, reasons, matched_fields, rationale = calculate_correlation(
                current,
                next_event,
                time_difference
            )

            if score >= minimum_score:
                correlations.append({
                    "event_1": c_id,
                    "event_2": get_attr(next_event, "event_id"),
                    "time_difference": time_difference,
                    "score": score,
                    "reasons": reasons,
                    "matched_fields": matched_fields,
                    "rationale": rationale,
                })

    return correlations