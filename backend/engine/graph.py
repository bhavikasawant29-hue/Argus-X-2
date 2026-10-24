from typing import List, Dict, Any
from engine.correlation import calculate_correlation, parse_timestamp


RELATIONSHIPS = {
    ("Initial Access", "Initial Access"): "AUTHENTICATES",
    ("Initial Access", "Execution"): "EXECUTES",
    ("Execution", "Credential Access"): "ACCESS_CREDENTIALS",
    ("Credential Access", "Lateral Movement"): "MOVES_TO",
    ("Lateral Movement", "Privilege Escalation"): "ESCALATES",
    ("Privilege Escalation", "Database Access"): "CONNECTS_TO",
    ("Database Access", "Database Access"): "ACCESSES"
}


def get_relationship(current: Dict[str, Any], next_event: Dict[str, Any]) -> str:
    key = (
        current.get("stage", ""),
        next_event.get("stage", "")
    )

    return RELATIONSHIPS.get(
        key,
        "LEADS_TO"
    )


def describe_edge(current: Dict[str, Any], next_event: Dict[str, Any], relationship: str) -> str:
    """Generate explainable narrative rationale for attack graph edge."""
    c_stage = current.get("stage", "")
    n_stage = next_event.get("stage", "")
    c_host = current.get("source_host") or current.get("host")
    n_host = next_event.get("source_host") or next_event.get("host")
    n_dest = next_event.get("destination_host") or next_event.get("destination")
    user = current.get("user") or next_event.get("user") or "actor"

    if relationship == "AUTHENTICATES":
        return f"Repeated authentication activity by '{user}' on {c_host} establishes initial foothold."
    if relationship == "EXECUTES":
        return f"Foothold on {c_host} transitions directly to execution by '{user}'."
    if relationship == "ACCESS_CREDENTIALS":
        return f"Process execution on {c_host} followed by credential access techniques."
    if relationship == "MOVES_TO":
        return f"Obtained credentials leveraged to laterally pivot from {c_host} to {n_dest or n_host}."
    if relationship == "ESCALATES":
        return f"Post-pivot privilege escalation executed on internal server {n_host}."
    if relationship == "CONNECTS_TO":
        return f"Elevated privileges on {c_host} used to establish database connection to {n_dest}."
    if relationship == "ACCESSES":
        return f"Database session actively queries restricted data tables on {n_dest or c_host}."

    return f"{c_stage} on {c_host} logically precedes {n_stage} on {n_host}."


def build_attack_graph(timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Build evidence-backed attack graph from reconstructed timeline.

    Nodes represent individual attack events with host and stage context.
    Edges represent verified or supported transitions with rationale and support level.
    """
    nodes = []
    edges = []

    for item in timeline:
        nodes.append({
            "id": item["event_id"],
            "label": item["event_type"],
            "stage": item["stage"],
            "timestamp": item["timestamp"],
            "host": item.get("source_host"),
            "destination": item.get("destination_host"),
            "user": item.get("user"),
            "severity": item.get("severity"),
        })

    for i in range(len(timeline) - 1):
        current = timeline[i]
        next_event = timeline[i + 1]

        relationship = get_relationship(current, next_event)
        rationale = describe_edge(current, next_event, relationship)

        # Calculate transition correlation score
        c_time = parse_timestamp(current.get("timestamp"))
        n_time = parse_timestamp(next_event.get("timestamp"))
        time_diff = (n_time - c_time).total_seconds() if (c_time and n_time) else 0

        score, reasons, matched_fields, _ = calculate_correlation(current, next_event, time_diff)

        support_level = "high" if score >= 4 else ("medium" if score >= 2 else "low")

        edges.append({
            "source": current["event_id"],
            "target": next_event["event_id"],
            "relationship": relationship,
            "correlation_score": score,
            "rationale": rationale,
            "support_level": support_level,
            "evidence_references": [current["event_id"], next_event["event_id"]],
        })

    return {
        "nodes": nodes,
        "edges": edges
    }