"""
Tests for AI Investigator Resilience, Deterministic Fallback, and Zero Secret Leakage.
"""

import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from engine.investigator import (
    investigate,
    deterministic_investigate,
    is_api_key_configured,
    validate_evidence,
    calculate_ai_confidence,
)


mock_timeline = [
    {"event_id": "AUTHENTICATION_0001", "stage": "Initial Access", "timestamp": "2026-09-11T10:00:30", "user": "rahul", "source_host": "PC-25"},
    {"event_id": "AUTHENTICATION_0002", "stage": "Initial Access", "timestamp": "2026-09-11T10:01:10", "user": "rahul", "source_host": "PC-25"},
    {"event_id": "ENDPOINT_0001", "stage": "Execution", "timestamp": "2026-09-11T10:02:20", "user": "rahul", "source_host": "PC-25"},
    {"event_id": "ENDPOINT_0002", "stage": "Credential Access", "timestamp": "2026-09-11T10:06:10", "user": "rahul", "source_host": "PC-25"},
    {"event_id": "NETWORK_0002", "stage": "Lateral Movement", "timestamp": "2026-09-11T10:09:20", "user": "rahul", "source_host": "PC-25", "destination_host": "SRV-02"},
    {"event_id": "ENDPOINT_0003", "stage": "Privilege Escalation", "timestamp": "2026-09-11T10:12:10", "user": "rahul", "source_host": "SRV-02"},
    {"event_id": "NETWORK_0006", "stage": "Database Access", "timestamp": "2026-09-11T10:14:30", "user": "rahul", "source_host": "SRV-02", "destination_host": "DB-01"},
    {"event_id": "APPLICATION_0004", "stage": "Database Access", "timestamp": "2026-09-11T10:15:10", "user": "rahul", "source_host": "SRV-02", "destination_host": "DB-01"},
]

mock_evidence = [
    {"event_id": item["event_id"], "evidence_status": "Verified"}
    for item in mock_timeline
]

mock_gaps = [
    {"gap": "Outbound connection telemetry is supporting evidence only", "severity": "medium"}
]

mock_blast_radius = {
    "affected_hosts": ["DB-01", "PC-25", "SRV-02"],
    "affected_users": ["rahul"],
    "critical_assets": ["DB-01"],
}


def test_secret_hygiene():
    print("[1] Testing Secret Configuration and Hygiene...")
    configured = is_api_key_configured()
    # Ensure boolean is returned without printing or returning the key string
    assert isinstance(configured, bool)
    print(f"  PASS: Key configured check returned boolean: {configured} (Zero secret exposure)")


def test_deterministic_fallback():
    print("\n[2] Testing Deterministic Evidence-Grounded Investigation Engine...")
    result = deterministic_investigate(
        "How did the attacker reach DB-01?",
        mock_timeline,
        mock_evidence,
        mock_gaps,
        mock_blast_radius,
    )
    assert "answer" in result
    assert len(result["evidence_refs"]) >= 6
    assert "AUTHENTICATION_0001" in result["evidence_refs"]
    assert "APPLICATION_0004" in result["evidence_refs"]
    assert result["confidence"] == 100.0
    assert result["mode"] == "deterministic_fallback"
    print("  PASS: Deterministic answer generated with 100% confidence and evidence citations:")
    print(f"  Cited Event IDs: {result['evidence_refs']}")


def test_investigator_error_resilience():
    print("\n[3] Testing Resilient Fallback on Live or Quota Exhaustion...")
    # This calls investigate(), which either uses live LLM or seamlessly falls back
    # to deterministic investigation without crashing or leaking secrets
    result = investigate(
        "How did the attacker reach DB-01?",
        mock_timeline,
        mock_evidence,
        mock_gaps,
        mock_blast_radius,
    )
    assert "answer" in result
    assert "evidence_refs" in result
    assert "confidence" in result
    assert len(result["evidence_refs"]) > 0
    assert result["confidence"] > 0
    # Strict secret leak check
    for field in ("answer", "mode", "provider_notice"):
        val = str(result.get(field, ""))
        assert "sk-" not in val, f"Secret leaked in field {field}!"
    print(f"  PASS: Investigation succeeded via mode '{result.get('mode')}' with confidence {result['confidence']}%")


def test_empty_evidence_handling():
    print("\n[4] Testing Empty Evidence Edge Cases...")
    result = deterministic_investigate("Any question", [], [], [], {})
    assert "Insufficient evidence" in result["answer"]
    assert result["evidence_refs"] == []
    assert result["confidence"] == 0.0
    print("  PASS: Empty timeline correctly yields 'Insufficient evidence' and confidence 0")


if __name__ == "__main__":
    print("Running ARGUS-X AI Investigator Resilience Test Suite...\n")
    test_secret_hygiene()
    test_deterministic_fallback()
    test_investigator_error_resilience()
    test_empty_evidence_handling()
    print("\nALL INVESTIGATOR RESILIENCE TESTS PASSED SUCCESSFULLY!")
