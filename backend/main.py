from ingestion.vulnerability_loader import (
    ingest_vulnerabilities,
    list_vulnerabilities,
)

import sys
from pathlib import Path
from typing import Optional, Dict, Any

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi import FastAPI, UploadFile, File, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from ingestion.loader import load_all_events, load_csv_from_bytes
from engine.reconstruction import reconstruct_attack
from engine.evidence import analyze_evidence
from engine.scoring import calculate_confidence, calculate_completeness, calculate_confidence_breakdown
from engine.gaps import find_evidence_gaps
from engine.graph import build_attack_graph
from engine.blast_radius import calculate_blast_radius
from engine.infrastructure import build_infrastructure_map
from engine.recommendations import generate_telemetry_recommendations
from engine.counterfactual import simulate_counterfactual
from engine.investigator import investigate
from engine.replay import build_attack_replay
from engine.asset_inventory import get_asset_inventory
from engine.vulnerability_matcher import enrich_events_with_vulnerabilities
from engine.anomaly_detector import predict_anomalies, train_anomaly_model, evaluate_anomaly_model
from engine.mitre_mapper import map_attack_timeline_to_mitre, get_mitre_repo
from engine.vuln_correlation import correlate_vulnerabilities_to_attack
from normalization.ocsf_normalization import normalize_event, normalize_events

app = FastAPI(
    title="ARGUS-X Security Telemetry Analysis API",
    description="Evidence-Driven Security Telemetry Correlation & Attack Reconstruction Engine",
    version="2.5.0"
)

# Allow local frontend and deployed Vercel frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://argusx-one.vercel.app",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

EXPECTED_STAGES = [
    "Initial Access",
    "Execution",
    "Credential Access",
    "Lateral Movement",
    "Privilege Escalation",
    "Database Access"
]


def run_full_analysis(events, include_vulnerability_correlation=False):
    timeline = reconstruct_attack(events)
    evidence = analyze_evidence(timeline, events)
    confidence = calculate_confidence(evidence)
    confidence_breakdown = calculate_confidence_breakdown(evidence)
    completeness = calculate_completeness(timeline, EXPECTED_STAGES)
    gaps = find_evidence_gaps(timeline, events)
    recommendations = generate_telemetry_recommendations(gaps, timeline, events)
    graph = build_attack_graph(timeline)
    blast_radius = calculate_blast_radius(timeline)
    infrastructure = build_infrastructure_map(timeline, events)
    replay = build_attack_replay(timeline)
    anomalies = predict_anomalies(events)
    mitre_mappings = map_attack_timeline_to_mitre(timeline, all_events=events)
    anomalous_events_count = sum(1 for a in anomalies if a.get("is_anomaly", False))

    result = {
        "summary": {
            "total_events": len(events),
            "reconstructed_events": len(timeline),
            "confidence": confidence,
            "completeness": completeness,
            "evidence_strength": confidence_breakdown.get("strength", "Strong"),
            "anomalies_detected": anomalous_events_count,
            "mitre_techniques_mapped": len(mitre_mappings),
        },
        "timeline": timeline,
        "evidence": evidence,
        "confidence": confidence,
        "confidence_breakdown": confidence_breakdown,
        "completeness": completeness,
        "gaps": gaps,
        "recommendations": recommendations,
        "graph": graph,
        "blast_radius": blast_radius,
        "infrastructure": infrastructure,
        "replay": replay,
        "anomalies": anomalies,
        "mitre_mappings": mitre_mappings,
    }

    if include_vulnerability_correlation:
        # Keep the correlation implementation available through its dedicated API
        # without making the normal investigation workflow depend on it.
        enriched_timeline = enrich_events_with_vulnerabilities(timeline)
        vuln_correlations = correlate_vulnerabilities_to_attack(timeline, enriched_timeline)
        result["vulnerability_enrichment"] = enriched_timeline
        result["vuln_correlations"] = vuln_correlations
        result["summary"]["vuln_correlations_total"] = vuln_correlations["summary"]["total"]
        result["summary"]["vuln_evidence_supported"] = vuln_correlations["summary"]["evidence_supported"]

    return result


@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "service": "ARGUS-X Security Telemetry Engine",
        "version": "2.4.0"
    }


class VulnerabilityIngestRequest(BaseModel):
    cve_ids: list[str] = []
    include_recent_nvd: bool = False


@app.post("/api/vulnerabilities/ingest")
def ingest_vulnerability_feeds(req: VulnerabilityIngestRequest):
    cve_ids = [item.strip().upper() for item in req.cve_ids if item.strip()]

    invalid_ids = [
        item for item in cve_ids
        if not item.startswith("CVE-")
    ]
    if invalid_ids:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid CVE ID format: {invalid_ids}",
        )

    try:
        return ingest_vulnerabilities(
            cve_ids=cve_ids or None,
            include_recent_nvd=req.include_recent_nvd,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Vulnerability ingestion failed: {exc}",
        )


@app.get("/api/vulnerabilities")
def get_vulnerabilities(
    kev_only: bool = False,
    limit: int = 100,
):
    return {
        "count": len(
            list_vulnerabilities(kev_only=kev_only, limit=limit)
        ),
        "vulnerabilities": list_vulnerabilities(
            kev_only=kev_only,
            limit=limit,
        ),
    }


@app.post("/api/vulnerabilities/correlate")
def correlate_vulnerabilities_endpoint():
    """
    Correlate known vulnerable assets with the reconstructed attack timeline.

    Reuses the full analysis pipeline. Returns per-CVE correlation records with
    evidence-grounded assessment categories:
      - evidence_supported: direct telemetry places the vulnerable host in an
        exploitation-relevant attack stage.
      - plausible_correlation: asset was in the attack path but direct exploitation
        evidence is missing.
      - unverified: asset is vulnerable but not involved in the attack chain.

    Note: 'evidence_supported' does NOT prove exploitation occurred.
    Forensic confirmation is always required.
    """
    try:
        events = load_all_events()
        analysis = run_full_analysis(events, include_vulnerability_correlation=True)
        return analysis["vuln_correlations"]
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Vulnerability correlation failed: {str(exc)}",
        )


@app.get("/api/inventory")
def get_inventory():
    """Return enterprise asset catalog with software configurations and criticality."""
    inv = get_asset_inventory()
    assets = inv.list_all()
    return {
        "count": len(assets),
        "assets": [
            a.model_dump() if hasattr(a, "model_dump") else a.dict()
            for a in assets
        ],
    }


class OCSFNormalizeBatchRequest(BaseModel):
    events: list[dict]
    source_type: Optional[str] = None


@app.post("/api/ocsf/normalize")
def normalize_telemetry_batch(req: OCSFNormalizeBatchRequest):
    """Normalize a batch of raw telemetry events into OCSF v1.1.0 records with diagnostics."""
    if not req.events:
        return {
            "ocsf_version": "1.1.0",
            "total_events": 0,
            "valid_events": 0,
            "events": [],
        }

    normalized = normalize_events(req.events, source_type=req.source_type, continue_on_error=True)
    valid_count = sum(1 for e in normalized if e.get("is_valid", False))

    return {
        "ocsf_version": "1.1.0",
        "total_events": len(normalized),
        "valid_events": valid_count,
        "invalid_events": len(normalized) - valid_count,
        "events": normalized,
    }


@app.post("/api/demo")
def run_demo():
    try:
        events = load_all_events()
        return run_full_analysis(events)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing benchmark demo analysis: {str(e)}"
        )


@app.post("/api/analyze")
async def analyze_uploaded_telemetry(
    authentication: Optional[UploadFile] = File(None),
    endpoint: Optional[UploadFile] = File(None),
    network: Optional[UploadFile] = File(None),
    application: Optional[UploadFile] = File(None)
):
    files = {
        "authentication": authentication,
        "endpoint": endpoint,
        "network": network,
        "application": application
    }

    parsed_events = []
    provided_count = 0

    for source_type, file_obj in files.items():
        if file_obj is not None and file_obj.filename:
            provided_count += 1

            try:
                content = await file_obj.read()

                if content and len(content.strip()) > 0:
                    events = load_csv_from_bytes(content, source_type)
                    parsed_events.extend(events)

            except Exception as err:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=(
                        f"Failed to parse {source_type} CSV log file "
                        f"'{file_obj.filename}': {str(err)}"
                    )
                )

    if provided_count == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "No telemetry CSV files provided. "
                "Please upload at least one valid log file."
            )
        )

    if not parsed_events:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded telemetry files contained no valid or parseable events."
        )

    parsed_events.sort(key=lambda event: event.timestamp or "")

    try:
        return run_full_analysis(parsed_events)

    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Telemetry analysis failed: {str(err)}"
        )


class InvestigateRequest(BaseModel):
    question: str
    selected_event: Optional[Dict[str, Any]] = None
    context: Optional[Dict[str, Any]] = None


@app.post("/api/investigate")
def run_investigation(req: InvestigateRequest):

    if not req.question or not req.question.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Investigative question cannot be empty."
        )

    try:
        if req.context and "timeline" in req.context:
            timeline = req.context.get("timeline", [])
            evidence = req.context.get("evidence", [])
            gaps = req.context.get("gaps", [])
            blast_radius = req.context.get("blast_radius", {})

        else:
            events = load_all_events()
            analysis = run_full_analysis(events)

            timeline = analysis["timeline"]
            evidence = analysis["evidence"]
            gaps = analysis["gaps"]
            blast_radius = analysis["blast_radius"]

        return investigate(
            req.question,
            timeline,
            evidence,
            gaps,
            blast_radius
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"AI Investigation failed: {str(e)}"
        )


class CounterfactualRequest(BaseModel):
    blocked_stage: str


@app.post("/api/counterfactual")
def run_counterfactual_simulation(req: CounterfactualRequest):

    if not req.blocked_stage:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="blocked_stage parameter is required."
        )

    try:
        events = load_all_events()
        timeline = reconstruct_attack(events)

        return simulate_counterfactual(
            timeline,
            req.blocked_stage
        )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Counterfactual simulation failed: {str(e)}"
        )


class AnomaliesRequest(BaseModel):
    events: Optional[list[dict]] = None
    contamination: Optional[float] = 0.05


@app.post("/api/ml/anomalies")
def detect_anomalies_endpoint(req: AnomaliesRequest):
    """Run Isolation Forest anomaly detection on provided events or baseline demo dataset."""
    try:
        events = req.events if req.events else load_all_events()
        anomalies = predict_anomalies(events)
        flagged = [a for a in anomalies if a.get("is_anomaly", False)]
        return {
            "total_events": len(events),
            "flagged_anomalies_count": len(flagged),
            "anomaly_rate": round(len(flagged) / len(events), 4) if events else 0.0,
            "anomalies": anomalies,
            "disclaimer": (
                "Anomaly scores represent statistical divergence from the trained baseline. "
                "An anomaly score is NOT an attack probability and requires corroboration."
            )
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Anomaly detection failed: {str(exc)}"
        )



class TrainAnomalyModelRequest(BaseModel):
    contamination: Optional[float] = 0.05
    random_state: Optional[int] = 42


@app.post("/api/ml/train")
def train_anomaly_model_endpoint(req: TrainAnomalyModelRequest):
    """Train and persist an updated Isolation Forest anomaly baseline model."""
    try:
        events = load_all_events()
        res = train_anomaly_model(
            events,
            contamination=req.contamination or 0.05,
            random_state=req.random_state or 42,
            is_demo_baseline=True
        )
        return res
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Model training failed: {str(exc)}"
        )


@app.get("/api/mitre/techniques")
def query_mitre_techniques(
    tactic: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = 50
):
    """Query local MITRE ATT&CK Enterprise techniques catalog."""
    repo = get_mitre_repo()
    techniques = repo.list_techniques(tactic=tactic, query=query, limit=limit)
    return {
        "dataset_version": repo.dataset_version,
        "count": len(techniques),
        "techniques": techniques
    }


class MitreMapRequest(BaseModel):
    events: Optional[list[dict]] = None
    timeline: Optional[list[dict]] = None


@app.post("/api/mitre/map")
def map_mitre_endpoint(req: MitreMapRequest):
    """Evidence-based mapping of security telemetry or timeline events to candidate MITRE ATT&CK techniques."""
    try:
        all_events = req.events if req.events else load_all_events()
        timeline = req.timeline if req.timeline else reconstruct_attack(all_events)
        mappings = map_attack_timeline_to_mitre(timeline, all_events=all_events)
        supported = [m for m in mappings if m.get("evidence_status") == "evidence_supported_candidate"]
        review = [m for m in mappings if m.get("evidence_status") == "candidate_requires_review"]

        return {
            "dataset_version": get_mitre_repo().dataset_version,
            "total_mappings": len(mappings),
            "evidence_supported_count": len(supported),
            "requires_review_count": len(review),
            "mappings": mappings,
            "disclaimer": (
                "MITRE ATT&CK technique associations are candidate classifications mapped via telemetry evidence. "
                "Techniques marked 'candidate_requires_review' require additional host/network telemetry."
            )
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"MITRE mapping failed: {str(exc)}"
        )
