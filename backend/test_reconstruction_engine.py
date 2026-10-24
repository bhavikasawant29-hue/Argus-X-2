"""
Comprehensive Tests for ARGUS-X Correlation, Reconstruction, Evidence Tiers, and Graph Engine.
"""

import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from ingestion.loader import load_all_events
from engine.correlation import calculate_correlation, correlate_events
from engine.reconstruction import reconstruct_attack, evaluate_attack_transition
from engine.evidence import analyze_evidence, classify_evidence
from engine.graph import build_attack_graph
from engine.scoring import calculate_confidence, calculate_completeness, calculate_confidence_breakdown
from models.event import SecurityEvent


def test_correlation_logic():
    print("[1] Testing Correlation scoring and explainable rationale...")
    e1 = {
        "event_id": "E1",
        "timestamp": "2026-09-11T10:00:00Z",
        "user": "rahul",
        "source_host": "PC-25",
        "destination_host": "SRV-02",
        "source_ip": "192.168.1.25",
        "event_type": "lateral_movement",
    }
    e2 = {
        "event_id": "E2",
        "timestamp": "2026-09-11T10:00:45Z",
        "user": "rahul",
        "source_host": "SRV-02",
        "destination_host": "DB-01",
        "source_ip": "10.0.0.2",
        "event_type": "database_connection",
    }

    score, reasons, matched_fields, rationale = calculate_correlation(e1, e2, 45.0)

    # same_user (+1), network_pivot_transition (+3), close_in_time (+1) = 5
    assert score >= 4
    assert "same_user" in reasons
    assert "network_pivot_transition" in reasons
    assert "close_in_time" in reasons
    assert "destination_to_source_pivot" in matched_fields
    assert "lateral transition from PC-25 to SRV-02" in rationale
    print(f"  PASS: Correlation score={score}, matched_fields={matched_fields}")
    print(f"  Rationale: {rationale}")


def test_attack_reconstruction_8_stages():
    print("\n[2] Testing Attack Reconstruction with full dataset (809 events)...")
    events = load_all_events()
    timeline = reconstruct_attack(events)

    assert len(timeline) == 8, f"Expected 8 reconstructed events, got {len(timeline)}"

    expected_sequence = [
        ("AUTHENTICATION_0001", "Initial Access"),
        ("AUTHENTICATION_0002", "Initial Access"),
        ("ENDPOINT_0001", "Execution"),
        ("ENDPOINT_0002", "Credential Access"),
        ("NETWORK_0002", "Lateral Movement"),
        ("ENDPOINT_0003", "Privilege Escalation"),
        ("NETWORK_0006", "Database Access"),
        ("APPLICATION_0004", "Database Access"),
    ]

    for idx, (expected_id, expected_stage) in enumerate(expected_sequence):
        item = timeline[idx]
        assert item["event_id"] == expected_id, f"Step {idx+1}: expected {expected_id}, got {item['event_id']}"
        assert item["stage"] == expected_stage, f"Step {idx+1}: expected stage {expected_stage}, got {item['stage']}"
        assert "transition_rationale" in item
        print(f"  Step {idx+1}: {item['event_id']} | {item['stage']} -> {item['transition_rationale']}")

    print("  PASS: Reconstructed exact 8-event attack chain with transition rationales")


def test_evidence_tiers_and_corroboration():
    print("\n[3] Testing Evidence Analysis and 4-tier model...")
    events = load_all_events()
    timeline = reconstruct_attack(events)
    evidence = analyze_evidence(timeline, events)

    assert len(evidence) == 8

    # In the demo incident, every timeline event is corroborated across multiple telemetry sources
    for item in evidence:
        assert item["evidence_status"] == "Verified"
        assert item["evidence_tier"] == "corroborated"
        assert item["supporting_event_count"] >= 2
        assert len(item["corroborating_sources"]) >= 2
        assert "Corroborated across" in item["evidence_rationale"]
        print(f"  {item['event_id']}: tier={item['evidence_tier']}, sources={item['corroborating_sources']}, count={item['supporting_event_count']}")

    # Unit test for inferred tier when no supporting events exist
    solo_event = SecurityEvent(
        event_id="SOLO_01",
        timestamp="2026-09-11T12:00:00",
        source_type="endpoint",
        event_type="process_execution",
        user="unknown_user",
        source_host="PC-99",
    )
    classification = classify_evidence(solo_event, [])
    assert classification["evidence_tier"] == "inferred"
    assert classification["evidence_status"] == "Inferred"
    print("  PASS: Solo event properly classified as 'inferred' (status='Inferred')")


def test_attack_graph_enrichment():
    print("\n[4] Testing Attack Graph edge enrichment...")
    events = load_all_events()
    timeline = reconstruct_attack(events)
    graph = build_attack_graph(timeline)

    assert len(graph["nodes"]) == 8
    assert len(graph["edges"]) == 7

    for edge in graph["edges"]:
        assert "relationship" in edge
        assert "correlation_score" in edge
        assert "rationale" in edge
        assert "support_level" in edge
        assert edge["support_level"] in ("high", "medium", "low")
        assert len(edge["evidence_references"]) == 2
        print(f"  Edge {edge['source']} -> {edge['target']} | {edge['relationship']} (score={edge['correlation_score']}, support={edge['support_level']})")

    print("  PASS: All 7 graph edges enriched with rationale, score, and support level")


def test_scoring_and_confidence():
    print("\n[5] Testing Confidence and Completeness scoring...")
    events = load_all_events()
    timeline = reconstruct_attack(events)
    evidence = analyze_evidence(timeline, events)

    conf = calculate_confidence(evidence)
    assert conf == 100.0, f"Expected 100.0, got {conf}"

    breakdown = calculate_confidence_breakdown(evidence)
    assert breakdown["confidence"] == 100.0
    assert breakdown["verified_count"] == 8
    assert breakdown["inferred_count"] == 0
    assert breakdown["corroborated_count"] == 8
    assert breakdown["strength"] == "Strong"
    print(f"  Confidence: {conf}% (Strength: {breakdown['strength']}, Corroborated: {breakdown['corroborated_count']}/8)")

    expected_stages = [
        "Initial Access", "Execution", "Credential Access",
        "Lateral Movement", "Privilege Escalation", "Database Access"
    ]
    completeness = calculate_completeness(timeline, expected_stages)
    assert completeness == 100.0
    print(f"  Completeness: {completeness}% across all 6 expected kill-chain stages")


if __name__ == "__main__":
    print("Running ARGUS-X Correlation, Reconstruction & Evidence Test Suite...\n")
    test_correlation_logic()
    test_attack_reconstruction_8_stages()
    test_evidence_tiers_and_corroboration()
    test_attack_graph_enrichment()
    test_scoring_and_confidence()
    print("\nALL RECONSTRUCTION & EVIDENCE TESTS PASSED SUCCESSFULLY!")
