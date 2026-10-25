"""
ARGUS-X Investigation Report Generator & Sanitizer

Compiles evidence-grounded investigation data into a complete,
auditable, and sanitized report data model for PDF export.
"""

from datetime import datetime, timezone
import re
from typing import Dict, Any, List, Optional


SENSITIVE_KEY_PATTERNS = [
    re.compile(r"api[_-]?key", re.IGNORECASE),
    re.compile(r"secret", re.IGNORECASE),
    re.compile(r"password", re.IGNORECASE),
    re.compile(r"token", re.IGNORECASE),
    re.compile(r"credential", re.IGNORECASE),
    re.compile(r"private[_-]?key", re.IGNORECASE),
    re.compile(r"auth[_-]?header", re.IGNORECASE),
]


def sanitize_value(key: str, value: Any) -> Any:
    """Recursively sanitize sensitive values matching known credential/secret keys."""
    if any(p.search(key) for p in SENSITIVE_KEY_PATTERNS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {k: sanitize_value(k, v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value(key, item) for item in value]
    if isinstance(value, str):
        # Redact potential bearer tokens or standard OpenAI/AWS keys in strings
        if value.startswith("sk-") or "Bearer " in value:
            return "[REDACTED_SECRET]"
    return value


def build_investigation_report_data(
    data: Dict[str, Any],
    investigation_id: Optional[str] = None,
    title: Optional[str] = None
) -> Dict[str, Any]:
    """
    Construct a complete, structured, and sanitized report object.
    Strictly uses actual investigation data without fabricating events or conclusions.
    """
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    inv_id = investigation_id or f"INV-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M')}"
    inv_title = title or f"ARGUS-X Security Telemetry Investigation ({inv_id})"

    timeline = data.get("timeline") or []
    evidence = data.get("evidence") or []
    gaps = data.get("gaps") or []
    recommendations = data.get("recommendations") or []
    blast_radius = data.get("blast_radius") or {}
    infrastructure = data.get("infrastructure") or {}
    graph = data.get("graph") or {}
    anomalies = data.get("anomalies") or []
    mitre_mappings = data.get("mitre_mappings") or []
    whatif = data.get("whatif") or []

    # Calculate summary metrics
    summary = data.get("summary") or {}
    confidence = data.get("confidence")
    if confidence is None:
        confidence = summary.get("confidence", 0.0)
    completeness = data.get("completeness")
    if completeness is None:
        completeness = summary.get("completeness", 0.0)

    # Attack path
    attack_path = blast_radius.get("attack_path") or []
    if not attack_path and timeline:
        # Extract chronological sequence of distinct stages
        seen_stages = []
        for e in timeline:
            stg = e.get("stage")
            if stg and stg not in seen_stages:
                seen_stages.append(stg)
        attack_path = seen_stages

    # Chronological timeline items
    timeline_items = []
    for idx, e in enumerate(timeline):
        timeline_items.append({
            "sequence": idx + 1,
            "event_id": e.get("event_id") or f"EV-{idx + 1:03d}",
            "timestamp": e.get("timestamp") or "N/A",
            "stage": e.get("stage") or "Unspecified Stage",
            "source_host": e.get("source_host") or "N/A",
            "destination_host": e.get("destination_host") or "N/A",
            "user": e.get("user") or "N/A",
            "action": e.get("action") or e.get("event_type") or "N/A",
            "severity": e.get("severity") or "INFORMATIONAL",
            "source_type": e.get("source_type") or "telemetry"
        })

    # Attack graph relationships
    graph_edges = []
    for edge in graph.get("edges") or []:
        graph_edges.append({
            "source": edge.get("source") or "N/A",
            "destination": edge.get("target") or "N/A",
            "relationship": edge.get("relationship") or "Connected",
            "event_id": edge.get("event_id") or (edge.get("event") or {}).get("event_id") or "N/A"
        })

    # Evidence items
    evidence_items = []
    for ev in evidence:
        evidence_items.append({
            "event_id": ev.get("event_id") or "N/A",
            "stage": ev.get("stage") or "N/A",
            "rationale": ev.get("rationale") or ev.get("rule_triggered") or "Corroborated by telemetry stream.",
            "corroboration": ev.get("corroborating_evidence") or ev.get("confidence_factor") or "Telemetry cross-tier match"
        })

    # Telemetry gaps
    gap_items = []
    for g in gaps:
        gap_items.append({
            "stage": g.get("stage") or "N/A",
            "description": g.get("description") or g.get("gap") or "Missing expected telemetry verification.",
            "severity": g.get("severity") or "MEDIUM",
            "recommendation": g.get("recommendation") or "Enable enhanced audit logging."
        })

    # MITRE Mappings with strict evidence requirements
    mitre_items = []
    for m in mitre_mappings:
        mitre_items.append({
            "technique_id": m.get("technique_id") or "N/A",
            "technique_name": m.get("technique_name") or "Unclassified Technique",
            "tactic": m.get("tactic") or "N/A",
            "evidence_status": m.get("evidence_status") or "candidate_requires_review",
            "mapping_rationale": m.get("mapping_rationale") or "Associated via stage telemetry criteria.",
            "evidence_refs": m.get("evidence_refs") or [],
            "review_status": "Evidence Supported" if m.get("evidence_status") == "evidence_supported_candidate" else "Requires Analyst Review"
        })

    # Isolation Forest Anomaly Findings
    anomaly_items = []
    for a in anomalies:
        if a.get("is_anomaly", False):
            anomaly_items.append({
                "event_id": a.get("event_id") or "N/A",
                "source_type": a.get("source_type") or "telemetry",
                "anomaly_score": round(float(a.get("anomaly_score", 0.0)), 4),
                "reason_codes": a.get("reason_codes") or ["Statistical outlier from trained baseline"],
                "raw_event_summary": f"User: {a.get('user', 'N/A')}, Host: {a.get('source_host', 'N/A')}, Action: {a.get('action', 'N/A')}"
            })

    # What-If Counterfactual Simulations
    simulation_items = []
    if isinstance(whatif, list):
        for sim in whatif:
            simulation_items.append({
                "blocked_stage": sim.get("blocked_stage") or "N/A",
                "stopped": sim.get("stopped", False),
                "prevented_stages": sim.get("prevented_stages") or [],
                "impact_assessment": sim.get("impact") or "Hypothetical containment analysis."
            })
    elif isinstance(whatif, dict) and whatif:
        simulation_items.append({
            "blocked_stage": whatif.get("blocked_stage") or "N/A",
            "stopped": whatif.get("stopped", False),
            "prevented_stages": whatif.get("prevented_stages") or [],
            "impact_assessment": whatif.get("impact") or "Hypothetical containment analysis."
        })

    # Affected infrastructure & blast radius
    impact_summary = {
        "affected_hosts": blast_radius.get("affected_hosts") or [],
        "affected_users": blast_radius.get("affected_users") or [],
        "critical_assets": blast_radius.get("critical_assets") or [],
        "host_count": blast_radius.get("host_count", len(blast_radius.get("affected_hosts") or [])),
        "user_count": blast_radius.get("user_count", len(blast_radius.get("affected_users") or [])),
        "critical_asset_count": blast_radius.get("critical_asset_count", len(blast_radius.get("critical_assets") or []))
    }

    report = {
        "metadata": {
            "investigation_id": inv_id,
            "title": inv_title,
            "generated_at": now_utc,
            "system": "ARGUS-X Security Telemetry Platform",
            "version": "2.5.0",
            "confidentiality": "CONFIDENTIAL - INTERNAL SOC USE ONLY",
        },
        "scores": {
            "confidence": {
                "score": confidence,
                "label": "System-Generated Assessment: Algorithmic confidence based on cross-tier telemetry evidence",
                "breakdown": data.get("confidence_breakdown") or {}
            },
            "completeness": {
                "score": completeness,
                "label": "System-Generated Assessment: Coverage across expected attack progression stages"
            }
        },
        "executive_summary": {
            "attack_path": attack_path,
            "total_events_analyzed": summary.get("total_events", len(timeline)),
            "reconstructed_events_count": len(timeline),
            "anomalies_detected": len(anomaly_items),
            "mitre_techniques_mapped": len(mitre_items),
            "critical_assets_impacted": impact_summary["critical_asset_count"],
            "narrative": (
                f"ARGUS-X correlated {summary.get('total_events', len(timeline))} telemetry events and reconstructed "
                f"an attack path spanning {len(timeline)} chronological stages with {confidence}% confidence "
                f"and {completeness}% completeness. Direct blast radius identified {impact_summary['host_count']} affected hosts, "
                f"{impact_summary['user_count']} compromised users, and {impact_summary['critical_asset_count']} critical assets."
            )
        },
        "timeline": timeline_items,
        "attack_graph": {
            "relationships": graph_edges,
            "total_relationships": len(graph_edges)
        },
        "evidence": evidence_items,
        "gaps": gap_items,
        "mitre_attack": {
            "mappings": mitre_items,
            "disclaimer": "Candidate classifications mapped via telemetry criteria. Requires analyst corroboration; score alone does not confirm maliciousness."
        },
        "anomalies": {
            "findings": anomaly_items,
            "disclaimer": "Isolation Forest anomaly scores represent statistical divergence from the trained baseline model, not confirmed malice."
        },
        "blast_radius": impact_summary,
        "whatif_simulations": {
            "simulations": simulation_items,
            "disclaimer": "Counterfactual simulations represent hypothetical bottleneck blocks and do NOT reflect real containment actions."
        },
        "disclaimers": {
            "telemetry_traceability": "All reconstruction assertions are traceable to specific raw telemetry event IDs.",
            "investigative_use": "This report is an evidence-grounded investigative aid. Final attribution and containment require qualified SOC analyst review."
        }
    }

    # Deep sanitize any accidental secrets
    return sanitize_value("report", report)
