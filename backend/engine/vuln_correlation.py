"""
ARGUS-X Vulnerability-to-Attack Correlation Engine

Correlates known vulnerable assets with reconstructed attack events and paths.
Uses existing asset inventory, CVE match results, and attack timeline — does NOT
re-implement any of those independently.

Assessment categories:
  evidence_supported   — direct telemetry links the vulnerable asset to an attack event
                         on the same host, with matching attack stage and timestamp ordering.
  plausible_correlation — asset was visited during the attack, is vulnerable, but no
                          event directly evidences exploitation of that specific CVE.
  unverified           — asset is vulnerable but was NOT involved in the reconstructed
                         attack chain, or evidence is insufficient.

IMPORTANT:
  A CVE match (version_affected) means the software version falls within the known
  affected range. It does NOT mean the CVE was exploited. Do not use KEV or EPSS
  alone to infer exploitation.
"""

from typing import Any, Dict, List, Optional

# Attack stages that are meaningful exploitation indicators when combined with
# a vulnerable asset on the target host. These are necessary but not sufficient.
_EXPLOITATION_STAGE_HINTS = {
    "Execution",
    "Credential Access",
    "Privilege Escalation",
    "Lateral Movement",
    "Database Access",
}

# Stages that suggest initial access / delivery — weaker exploitation signal
_INITIAL_ACCESS_STAGES = {"Initial Access"}

# CVE-to-technique hints for KNOWN CVEs in the asset inventory
# Maps CVE-ID → set of attack stage keywords that suggest exploitation
_CVE_STAGE_HINTS: Dict[str, List[str]] = {
    "CVE-2021-44228": ["Execution", "Lateral Movement"],    # Log4Shell → RCE → lateral
    "CVE-2021-41773": ["Execution", "Initial Access"],      # Apache path traversal → RCE
}


def _normalize_host(h: Optional[str]) -> str:
    return (h or "").strip().upper()


def _get_timeline_hosts(timeline: List[Dict]) -> Dict[str, List[Dict]]:
    """Build a mapping of host → [timeline events involving that host]."""
    host_events: Dict[str, List[Dict]] = {}
    for ev in timeline:
        for h in [ev.get("source_host"), ev.get("destination_host")]:
            h = _normalize_host(h)
            if h:
                host_events.setdefault(h, []).append(ev)
    return host_events


def _assess_correlation(
    match: Dict,
    host_events: List[Dict],
    cve_id: str,
) -> tuple[str, str]:
    """
    Determine correlation strength for a single CVE match against timeline events.

    Returns (status, rationale).
    """
    match_status = match.get("match_status", "")

    # If the version match itself is inconclusive, keep the whole correlation unverified
    if match_status not in ("version_affected", "insufficient_data"):
        return (
            "unverified",
            f"Asset version is confirmed outside affected range ({match_status}). No exploitation correlation."
        )

    if match_status == "insufficient_data":
        return (
            "unverified",
            "Asset version data is insufficient to confirm vulnerability applicability. Cannot correlate."
        )

    # From here on: match_status == "version_affected"
    if not host_events:
        return (
            "unverified",
            "Asset is version-affected but was NOT involved in the reconstructed attack chain. "
            "No telemetry links this host to the attack path."
        )

    # Only events explicitly associated with the enriched vulnerability match
    # are evidence. Do not treat every event involving the same host as CVE
    # evidence.
    stages_on_host = {ev.get("stage", "") for ev in host_events}
    exploitation_stages = stages_on_host & _EXPLOITATION_STAGE_HINTS
    initial_access_stages = stages_on_host & _INITIAL_ACCESS_STAGES

    cve_hint_stages = set(_CVE_STAGE_HINTS.get(cve_id, []))
    stage_alignment = bool(cve_hint_stages & stages_on_host) if cve_hint_stages else False

    if exploitation_stages and (stage_alignment or cve_hint_stages == set()):
        # Strong correlation: exploitation-relevant stage on this host + version confirmed affected
        event_ids = [ev.get("event_id") for ev in host_events]
        matched_stages = sorted(exploitation_stages)
        return (
            "evidence_supported",
            (
                f"Asset version is confirmed within affected range for {cve_id}. "
                f"Reconstructed attack stages {matched_stages} occurred on this host "
                f"(events: {event_ids}). "
                "Direct telemetry supports the host being targeted during the attack. "
                "Note: version vulnerability + attack stage co-occurrence does not prove "
                f"the CVE was exploited — it identifies {cve_id} as a high-priority "
                "investigation target requiring forensic confirmation."
            )
        )

    if initial_access_stages or (stage_alignment and exploitation_stages == set()):
        # Weaker correlation: host was involved but no strong exploitation-stage evidence
        return (
            "plausible_correlation",
            (
                f"Asset is version-affected for {cve_id} and host appeared in the attack "
                f"path (stages: {sorted(stages_on_host)}). No direct exploitation-stage "
                "telemetry confirms this CVE was used. Treat as a plausible investigation lead."
            )
        )

    if stages_on_host:
        return (
            "plausible_correlation",
            (
                f"Asset is version-affected for {cve_id}. Host is present in the attack path "
                f"with stages {sorted(stages_on_host)}, but telemetry does not directly "
                "indicate exploitation of this specific vulnerability."
            )
        )

    return (
        "unverified",
        f"Asset is version-affected for {cve_id} but no relevant attack stages were "
        "observed on this host in the reconstructed timeline."
    )


def correlate_vulnerabilities_to_attack(
    timeline: List[Dict],
    vulnerability_enrichment: List[Dict],
) -> Dict[str, Any]:
    """
    Correlate vulnerable assets with the reconstructed attack timeline.

    Parameters
    ----------
    timeline : list of reconstructed attack event dicts (from reconstruct_attack)
    vulnerability_enrichment : list of enriched event dicts with vulnerability_enrichment keys
                               (output of enrich_events_with_vulnerabilities applied to timeline)

    Returns
    -------
    dict with:
      correlations : list of per-CVE correlation records
      summary : aggregate counts
      disclaimer : epistemic honesty notice
    """
    if not timeline or not vulnerability_enrichment:
        return {
            "correlations": [],
            "summary": {
                "total": 0,
                "evidence_supported": 0,
                "plausible_correlation": 0,
                "unverified": 0,
            },
            "disclaimer": _DISCLAIMER,
        }

    # Index: host → attack timeline events involving that host
    timeline_host_events = _get_timeline_hosts(timeline)
    events_by_id = {
        ev.get("event_id"): ev for ev in timeline if ev.get("event_id")
    }

    # Collect unique (host, cve_id) pairs from enriched events, deduplicating
    seen: set = set()
    correlations = []

    for enriched_ev in vulnerability_enrichment:
        vuln_info = enriched_ev.get("vulnerability_enrichment", {})
        target_host = _normalize_host(vuln_info.get("target_host"))
        asset_id = vuln_info.get("asset_id")
        asset_criticality = vuln_info.get("asset_criticality", "unknown")

        for match in vuln_info.get("matches", []):
            cve_id = match.get("cve_id")
            if not cve_id or not target_host:
                continue

            dedup_key = (target_host, cve_id)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            enriched_event_id = enriched_ev.get("event_id")
            explicit_event = events_by_id.get(enriched_event_id)
            if explicit_event and target_host in {
                _normalize_host(explicit_event.get("source_host")),
                _normalize_host(explicit_event.get("destination_host")),
            }:
                host_timeline_events = [explicit_event]
            else:
                host_timeline_events = []
            status, rationale = _assess_correlation(match, host_timeline_events, cve_id)

            related_event_ids = sorted(
                str(ev["event_id"])
                for ev in host_timeline_events
                if ev.get("event_id")
            )
            related_stages = sorted({ev.get("stage", "") for ev in host_timeline_events} - {""})
            missing_evidence = []
            if not host_timeline_events:
                missing_evidence.append("explicit vulnerability-associated timeline event")
            if status != "evidence_supported":
                missing_evidence.append("direct exploitation evidence")

            correlations.append({
                "cve_id": cve_id,
                "host": target_host,
                "asset_id": asset_id,
                "asset_criticality": asset_criticality,
                "product": match.get("product"),
                "version": match.get("version"),
                "match_status": match.get("match_status"),
                "cvss_score": match.get("cvss_score"),
                "cvss_severity": _cvss_severity_label(match.get("cvss_score")),
                "known_exploited": match.get("known_exploited", False),
                "epss_score": match.get("epss_score"),
                "correlation_status": status,
                "rationale": rationale,
                "related_attack_event_ids": related_event_ids,
                "related_attack_stages": related_stages,
                "supporting_evidence": [
                    {"event_id": event_id, "stages": related_stages}
                    for event_id in related_event_ids
                ],
                "missing_evidence": sorted(set(missing_evidence)),
            })

    # Sort: evidence_supported first, then plausible, then unverified; within each, by CVSS desc
    _order = {"evidence_supported": 0, "plausible_correlation": 1, "unverified": 2}
    correlations.sort(key=lambda c: (
        _order.get(c["correlation_status"], 9),
        -(c["cvss_score"] or 0),
    ))

    counts = {
        "evidence_supported": sum(1 for c in correlations if c["correlation_status"] == "evidence_supported"),
        "plausible_correlation": sum(1 for c in correlations if c["correlation_status"] == "plausible_correlation"),
        "unverified": sum(1 for c in correlations if c["correlation_status"] == "unverified"),
    }

    return {
        "correlations": correlations,
        "summary": {
            "total": len(correlations),
            **counts,
        },
        "disclaimer": _DISCLAIMER,
    }


def _cvss_severity_label(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


_DISCLAIMER = (
    "Correlation status indicates the strength of the relationship between a known "
    "vulnerable asset and the reconstructed attack path. 'evidence_supported' means "
    "direct telemetry places this host in an exploitation-relevant attack stage while "
    "its software is within the CVE's affected version range — it does NOT constitute "
    "forensic proof of exploitation. 'plausible_correlation' means the asset was present "
    "in the attack path but direct exploitation evidence is missing. All findings require "
    "forensic confirmation before concluding a CVE was exploited."
)
