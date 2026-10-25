import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from main import app
from engine.report import build_investigation_report_data, sanitize_value

client = TestClient(app)


def test_build_investigation_report_unit():
    """Unit test for report data model builder."""
    mock_data = {
        "summary": {"total_events": 50, "confidence": 95.0, "completeness": 90.0},
        "timeline": [
            {
                "event_id": "AUTH_001",
                "timestamp": "2026-10-25T08:00:00Z",
                "stage": "Initial Access",
                "source_host": "WS-22",
                "destination_host": "SRV-03",
                "user": "arjun",
                "severity": "HIGH",
            }
        ],
        "evidence": [
            {"event_id": "AUTH_001", "stage": "Initial Access", "rationale": "Compromised credential login."}
        ],
        "blast_radius": {
            "affected_hosts": ["WS-22", "SRV-03"],
            "critical_assets": ["DB-03"],
            "affected_users": ["arjun"],
        },
        "graph": {
            "edges": [
                {"source": "WS-22", "target": "SRV-03", "relationship": "Lateral Movement", "event_id": "AUTH_001"}
            ]
        },
        "mitre_mappings": [
            {
                "technique_id": "T1078",
                "technique_name": "Valid Accounts",
                "evidence_status": "evidence_supported_candidate",
                "evidence_refs": ["AUTH_001"]
            }
        ],
        "anomalies": [
            {
                "event_id": "AUTH_001",
                "is_anomaly": True,
                "anomaly_score": -0.152,
                "source_type": "authentication",
                "reason_codes": ["Off-hours access"]
            }
        ],
        "whatif": [
            {
                "blocked_stage": "Lateral Movement",
                "stopped": True,
                "prevented_stages": ["Privilege Escalation", "Database Access"],
                "impact": "Hypothetical containment prevented DB reach."
            }
        ]
    }

    report = build_investigation_report_data(mock_data, investigation_id="INV-CUSTOM-001", title="Custom Incident")

    assert report["metadata"]["investigation_id"] == "INV-CUSTOM-001"
    assert report["metadata"]["title"] == "Custom Incident"
    assert "generated_at" in report["metadata"]

    # Scores
    assert report["scores"]["confidence"]["score"] == 95.0
    assert "System-Generated Assessment" in report["scores"]["confidence"]["label"]
    assert report["scores"]["completeness"]["score"] == 90.0

    # Executive Summary
    assert report["executive_summary"]["total_events_analyzed"] == 50
    assert len(report["timeline"]) == 1
    assert report["timeline"][0]["event_id"] == "AUTH_001"
    assert report["timeline"][0]["user"] == "arjun"

    # Graph
    assert len(report["attack_graph"]["relationships"]) == 1
    assert report["attack_graph"]["relationships"][0]["source"] == "WS-22"

    # MITRE & Anomalies disclaimers
    assert len(report["mitre_attack"]["mappings"]) == 1
    assert "candidate" in report["mitre_attack"]["disclaimer"].lower()
    assert len(report["anomalies"]["findings"]) == 1
    assert "statistical divergence" in report["anomalies"]["disclaimer"].lower()

    # What-if simulation disclaimer
    assert len(report["whatif_simulations"]["simulations"]) == 1
    assert "hypothetical" in report["whatif_simulations"]["disclaimer"].lower()


def test_report_sanitization_removes_sensitive_data():
    """Verify that credentials, tokens, API keys, and passwords are fully redacted."""
    sensitive_data = {
        "api_key": "sk-1234567890abcdef",
        "secret_token": "bearer xyz987",
        "password": "supersecretpassword",
        "nested": {
            "private_key": "-----BEGIN RSA PRIVATE KEY-----",
            "safe_field": "public_telemetry_id"
        },
        "raw_string": "Token is Bearer eyJhbGciOi...",
        "openai_key": "sk-proj-abc123456789"
    }

    sanitized = sanitize_value("data", sensitive_data)
    assert sanitized["api_key"] == "[REDACTED]"
    assert sanitized["secret_token"] == "[REDACTED]"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["nested"]["private_key"] == "[REDACTED]"
    assert sanitized["nested"]["safe_field"] == "public_telemetry_id"
    assert sanitized["raw_string"] == "[REDACTED_SECRET]"
    assert sanitized["openai_key"] == "[REDACTED_SECRET]"


def test_report_endpoint_custom_investigation():
    """Test POST /api/report/data with custom investigation payload."""
    payload = {
        "investigation_id": "INV-TEST-42",
        "title": "Operation Nightshade",
        "investigation_data": {
            "summary": {"total_events": 10, "confidence": 88.0, "completeness": 80.0},
            "timeline": [
                {
                    "event_id": "EP_100",
                    "timestamp": "2026-10-25T07:10:00Z",
                    "stage": "Lateral Movement",
                    "source_host": "WS-22",
                    "destination_host": "SRV-03",
                    "user": "arjun",
                    "severity": "CRITICAL"
                }
            ],
            "blast_radius": {
                "affected_hosts": ["WS-22", "SRV-03"],
                "critical_assets": ["DB-03"]
            }
        }
    }

    response = client.post("/api/report/data", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["metadata"]["investigation_id"] == "INV-TEST-42"
    assert data["metadata"]["title"] == "Operation Nightshade"
    assert data["scores"]["confidence"]["score"] == 88.0
    assert data["timeline"][0]["event_id"] == "EP_100"
    assert data["blast_radius"]["critical_assets"] == ["DB-03"]


def test_report_endpoint_empty_handling():
    """Verify empty/missing data returns structured 'No data available' / empty items without crashing."""
    payload = {
        "investigation_id": "INV-EMPTY",
        "investigation_data": {}
    }
    response = client.post("/api/report/data", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["metadata"]["investigation_id"] == "INV-EMPTY"
    assert data["timeline"] == []
    assert data["evidence"] == []
    assert data["gaps"] == []
    assert data["mitre_attack"]["mappings"] == []
    assert data["anomalies"]["findings"] == []
    assert data["whatif_simulations"]["simulations"] == []
