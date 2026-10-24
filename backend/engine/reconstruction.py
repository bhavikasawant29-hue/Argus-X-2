from datetime import datetime, timezone
from typing import Any, Optional, Tuple, List, Dict
from models.event import SecurityEvent


ATTACK_EVENTS = {
    "login_failed": "Initial Access",
    "login_success": "Initial Access",
    "process_execution": "Execution",
    "credential_access": "Credential Access",
    "lateral_movement": "Lateral Movement",
    "privilege_escalation": "Privilege Escalation",
    "database_connection": "Database Access",
    "database_access": "Database Access"
}


def parse_timestamp(timestamp: Any) -> Optional[datetime]:
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
    if isinstance(event, dict):
        return event.get(key, default)
    return getattr(event, key, default)


def evaluate_attack_transition(previous: Any, current: Any, max_gap_seconds: float = 600) -> Tuple[bool, str]:
    """
    Evaluate if current candidate event plausibly follows previous attack step.

    Returns:
        (is_related, rationale)
    """
    p_time = parse_timestamp(get_attr(previous, "timestamp"))
    c_time = parse_timestamp(get_attr(current, "timestamp"))

    if not p_time or not c_time:
        return False, "Missing timestamp"

    time_gap = (c_time - p_time).total_seconds()
    if time_gap < 0 or time_gap > max_gap_seconds:
        return False, f"Time gap ({int(time_gap)}s) outside allowed window ({int(max_gap_seconds)}s)"

    p_user = get_attr(previous, "user")
    c_user = get_attr(current, "user")
    p_shost = get_attr(previous, "source_host")
    c_shost = get_attr(current, "source_host")
    p_dhost = get_attr(previous, "destination_host")
    c_dhost = get_attr(current, "destination_host")

    same_user = bool(p_user and c_user and p_user == c_user)
    same_source = bool(p_shost and c_shost and p_shost == c_shost)
    pivot_transition = bool(p_dhost and c_shost and p_dhost == c_shost)
    same_destination = bool(p_dhost and c_dhost and p_dhost == c_dhost)

    if same_user and same_source:
        return True, f"Same actor '{c_user}' active on host '{c_shost}' within {int(time_gap)}s"

    if same_user and pivot_transition:
        return True, f"Lateral pivot: actor '{c_user}' transitioned from {p_shost} to {c_shost}"

    if same_user and same_destination:
        return True, f"Actor '{c_user}' continuing operations against target '{c_dhost}'"

    if same_source and not same_user:
        return True, f"Co-located on host '{c_shost}' within {int(time_gap)}s"

    return False, "Insufficient entity continuity or network progression"


def is_related(previous: Any, current: Any, max_gap_seconds: float = 600) -> bool:
    """Check entity relationship and temporal continuity."""
    related, _ = evaluate_attack_transition(previous, current, max_gap_seconds)
    return related


def reconstruct_attack(events: List[Any]) -> List[Dict[str, Any]]:
    """
    Reconstruct attack narrative from candidate telemetry events.

    Preserves chronological timeline, stage transitions, and rationales.
    """
    suspicious_events = [
        event for event in events
        if get_attr(event, "event_type") in ATTACK_EVENTS
    ]

    suspicious_events.sort(
        key=lambda event: parse_timestamp(get_attr(event, "timestamp")) or datetime.min.replace(tzinfo=timezone.utc)
    )

    if not suspicious_events:
        return []

    attack_chain = [suspicious_events[0]]
    transition_rationales = ["Initial observable suspicious entry point"]

    for event in suspicious_events[1:]:
        previous = attack_chain[-1]
        related, rationale = evaluate_attack_transition(previous, event)

        if related:
            attack_chain.append(event)
            transition_rationales.append(rationale)

    timeline = []

    for index, event in enumerate(attack_chain):
        previous = attack_chain[index - 1] if index > 0 else None
        time_gap = None

        if previous:
            p_time = parse_timestamp(get_attr(previous, "timestamp"))
            c_time = parse_timestamp(get_attr(event, "timestamp"))
            if p_time and c_time:
                time_gap = (c_time - p_time).total_seconds()

        timeline.append({
            "sequence": index + 1,
            "stage": ATTACK_EVENTS[get_attr(event, "event_type")],
            "event_id": get_attr(event, "event_id"),
            "event_type": get_attr(event, "event_type"),
            "timestamp": get_attr(event, "timestamp"),
            "user": get_attr(event, "user"),
            "source_host": get_attr(event, "source_host"),
            "destination_host": get_attr(event, "destination_host"),
            "severity": get_attr(event, "severity"),
            "time_since_previous": time_gap,
            "transition_rationale": transition_rationales[index],
        })

    return timeline