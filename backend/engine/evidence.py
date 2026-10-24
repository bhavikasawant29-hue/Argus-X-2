from datetime import datetime, timezone
from typing import Any, Optional, List, Dict


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


def is_supporting_event(event: Any, other: Any, max_gap_seconds: float = 300) -> bool:
    e_id = get_attr(event, "event_id")
    o_id = get_attr(other, "event_id")
    if e_id and o_id and e_id == o_id:
        return False

    e_time = parse_timestamp(get_attr(event, "timestamp"))
    o_time = parse_timestamp(get_attr(other, "timestamp"))
    if not e_time or not o_time:
        return False

    time_gap = abs((e_time - o_time).total_seconds())
    if time_gap > max_gap_seconds:
        return False

    e_user = get_attr(event, "user")
    o_user = get_attr(other, "user")
    same_user = bool(e_user and o_user and e_user == o_user)

    e_shost = get_attr(event, "source_host")
    o_shost = get_attr(other, "source_host")
    same_source = bool(e_shost and o_shost and e_shost == o_shost)

    e_dhost = get_attr(event, "destination_host")
    o_dhost = get_attr(other, "destination_host")
    same_destination = bool(e_dhost and o_dhost and e_dhost == o_dhost)

    same_path = bool(
        e_shost and e_dhost and o_shost and o_dhost
        and e_shost == o_shost and e_dhost == o_dhost
    )

    if same_path:
        return True

    if same_user and (same_source or same_destination):
        return True

    return False


def classify_evidence(event: Any, supporting_events: List[Any]) -> Dict[str, Any]:
    """
    Classify evidence into a documented 4-tier taxonomy based on telemetry corroboration.

    Tiers:
    - corroborated: Directly recorded in primary log and corroborated by >= 2 related signals,
      typically across different telemetry sources.
    - directly_observed: Directly observed in telemetry with at least 1 supporting signal.
    - inferred: Supported by chronological timeline progression but lacking supporting events.
    - insufficient_evidence: Missing critical entity attributes (host or user).
    """
    user = get_attr(event, "user")
    source_host = get_attr(event, "source_host")

    if not user and not source_host:
        return {
            "evidence_tier": "insufficient_evidence",
            "evidence_status": "Inferred",
            "rationale": "Missing critical host and user attributes in telemetry."
        }

    sources = {
        get_attr(e, "source_type", "unknown")
        for e in supporting_events
    }
    primary_source = get_attr(event, "source_type", "unknown")
    sources.add(primary_source)

    count = len(supporting_events)

    if count >= 2:
        return {
            "evidence_tier": "corroborated",
            "evidence_status": "Verified",
            "corroborating_sources": sorted(sources),
            "rationale": f"Corroborated across {len(sources)} telemetry sources with {count} supporting events."
        }

    if count == 1:
        return {
            "evidence_tier": "directly_observed",
            "evidence_status": "Verified",
            "corroborating_sources": sorted(sources),
            "rationale": "Directly observed primary event with 1 supporting contextual event."
        }

    return {
        "evidence_tier": "inferred",
        "evidence_status": "Inferred",
        "corroborating_sources": [primary_source],
        "rationale": "Inferred from attack chain progression; no independent supporting events found in window."
    }


def analyze_evidence(timeline: List[Dict[str, Any]], events: List[Any]) -> List[Dict[str, Any]]:
    """Analyze evidence strength and corroboration for each timeline event."""
    event_map = {
        get_attr(event, "event_id"): event
        for event in events
        if get_attr(event, "event_id")
    }

    results = []

    for item in timeline:
        e_id = item["event_id"]
        event = event_map.get(e_id)
        if not event:
            continue

        supporting_events = []
        for other in events:
            if is_supporting_event(event, other):
                supporting_events.append(other)

        classification = classify_evidence(event, supporting_events)

        results.append({
            "event_id": e_id,
            "event_type": get_attr(event, "event_type"),
            "stage": item["stage"],
            "timestamp": get_attr(event, "timestamp"),
            "evidence_status": classification["evidence_status"],
            "evidence_tier": classification["evidence_tier"],
            "evidence_rationale": classification["rationale"],
            "corroborating_sources": classification.get("corroborating_sources", []),
            "supporting_event_count": len(supporting_events),
            "supporting_events": [
                get_attr(e, "event_id") for e in supporting_events[:10]
            ],
        })

    return results