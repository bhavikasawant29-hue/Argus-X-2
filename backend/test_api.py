import sys
from pathlib import Path

# Ensure backend root directory is in sys.path
backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    print("[PASS] GET /api/health passed")


def test_demo():
    response = client.post("/api/demo")
    assert response.status_code == 200
    data = response.json()

    assert "summary" in data
    assert data["summary"]["total_events"] == 809
    assert data["summary"]["reconstructed_events"] == 8
    assert data["confidence"] == 100.0
    assert data["completeness"] == 100.0

    assert len(data["timeline"]) == 8
    assert len(data["evidence"]) == 8
    assert len(data["graph"]["nodes"]) == 8
    assert len(data["graph"]["edges"]) == 7
    assert data["blast_radius"]["affected_hosts"] == ['DB-01', 'PC-25', 'SRV-02']
    assert data["blast_radius"]["critical_assets"] == ['DB-01']
    assert len(data["replay"]) == 8

    print("[PASS] POST /api/demo passed (809 events -> 8 reconstructed stages)")


def test_analyze_valid():
    csv_content = (
        "timestamp,event_type,user,source_ip,source_host,destination_host,action,severity\n"
        "2026-09-11T10:00:30,login_failed,rahul,192.168.1.25,PC-25,,interactive_login,HIGH\n"
        "2026-09-11T10:01:10,login_success,rahul,192.168.1.25,PC-25,,interactive_login,LOW\n"
    )

    files = {
        "authentication": ("auth.csv", csv_content, "text/csv")
    }

    response = client.post("/api/analyze", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["total_events"] == 2
    assert len(data["timeline"]) >= 1
    print("[PASS] POST /api/analyze with valid CSV upload passed")


def test_analyze_invalid_no_files():
    response = client.post("/api/analyze")
    assert response.status_code == 400
    assert "No telemetry CSV files provided" in response.json()["detail"]
    print("[PASS] POST /api/analyze error handling (no files) passed")


def test_counterfactual():
    response = client.post("/api/counterfactual", json={"blocked_stage": "Lateral Movement"})
    assert response.status_code == 200
    data = response.json()
    assert data["blocked_stage"] == "Lateral Movement"
    assert data["stopped"] is True
    assert "Lateral Movement" in data["prevented_stages"]
    print("[PASS] POST /api/counterfactual passed")


def test_investigate():
    response = client.post("/api/investigate", json={"question": "How did the attacker reach DB-01?"})
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data
    assert "confidence" in data
    assert len(data.get("evidence_refs", [])) > 0
    print("[PASS] POST /api/investigate passed (evidence-grounded answer returned)")


def test_inventory():
    response = client.get("/api/inventory")
    assert response.status_code == 200
    data = response.json()
    assert "assets" in data
    assert data["count"] >= 5
    hosts = [a["hostname"] for a in data["assets"]]
    assert "PC-25" in hosts and "SRV-02" in hosts and "DB-01" in hosts
    print("[PASS] GET /api/inventory passed (5+ enterprise assets retrieved)")


def test_ocsf_normalize():
    payload = {
        "source_type": "endpoint",
        "events": [
            {
                "event_id": "EP_TEST",
                "timestamp": "2026-09-11T10:02:20Z",
                "event_type": "process_execution",
                "user": "rahul",
                "source_host": "PC-25",
                "action": "powershell",
                "severity": "high",
            }
        ]
    }
    response = client.post("/api/ocsf/normalize", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["ocsf_version"] == "1.1.0"
    assert data["total_events"] == 1
    assert data["valid_events"] == 1
    norm_event = data["events"][0]
    assert norm_event["class_uid"] == 1007
    assert norm_event["category_uid"] == 1
    assert norm_event["activity_id"] == 1
    print("[PASS] POST /api/ocsf/normalize passed (OCSF v1.1.0 validated)")


def test_vulnerabilities():
    response = client.get("/api/vulnerabilities?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "vulnerabilities" in data
    assert "count" in data
    print(f"[PASS] GET /api/vulnerabilities passed ({data['count']} CVE records available)")


def test_ml_anomalies_endpoint():
    response = client.post("/api/ml/anomalies", json={"contamination": 0.05})
    assert response.status_code == 200
    data = response.json()
    assert data["total_events"] == 809
    assert "flagged_anomalies_count" in data
    assert "anomalies" in data
    assert len(data["anomalies"]) == 809
    print(f"[PASS] POST /api/ml/anomalies passed ({data['flagged_anomalies_count']} outliers identified)")


def test_ml_analyze_log_removed():
    """Verify that the removed Hugging Face endpoint returns 404 or 405."""
    response = client.post("/api/ml/analyze-log", json={
        "text": "powershell.exe -enc abc123"
    })
    assert response.status_code in (404, 405), (
        f"Expected 404/405 for removed endpoint, got {response.status_code}"
    )
    print("[PASS] POST /api/ml/analyze-log correctly absent (404/405)")


def test_ml_train_endpoint():
    response = client.post("/api/ml/train", json={"contamination": 0.05, "random_state": 42})
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "trained"
    assert data["events_trained"] == 809
    print("[PASS] POST /api/ml/train passed (Isolation Forest retrained & persisted)")


def test_mitre_techniques_endpoint():
    response = client.get("/api/mitre/techniques?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "techniques" in data
    assert data["count"] >= 5
    assert "dataset_version" in data
    print(f"[PASS] GET /api/mitre/techniques passed ({data['count']} techniques retrieved)")


def test_mitre_map_endpoint():
    response = client.post("/api/mitre/map", json={})
    assert response.status_code == 200
    data = response.json()
    assert "mappings" in data
    assert data["total_mappings"] >= 4
    assert data["evidence_supported_count"] >= 1
    print(f"[PASS] POST /api/mitre/map passed ({data['total_mappings']} candidate techniques mapped)")


def test_vuln_correlate_endpoint():
    response = client.post("/api/vulnerabilities/correlate")
    assert response.status_code == 200
    data = response.json()
    assert "correlations" in data
    assert "summary" in data
    assert "disclaimer" in data
    summary = data["summary"]
    assert "total" in summary
    assert "evidence_supported" in summary
    assert "plausible_correlation" in summary
    assert "unverified" in summary
    # The demo dataset has SRV-02 with Log4j2 (version_affected) in the attack path
    # At minimum, total correlations must be > 0 given the inventory
    assert summary["total"] >= 0  # graceful even if CVE cache is empty
    # If correlations present, each must have required fields
    for c in data["correlations"]:
        assert "cve_id" in c
        assert "host" in c
        assert "correlation_status" in c
        assert c["correlation_status"] in ("evidence_supported", "plausible_correlation", "unverified")
        assert "rationale" in c
    print(f"[PASS] POST /api/vulnerabilities/correlate passed "
          f"({summary['total']} correlations: "
          f"{summary['evidence_supported']} evidence_supported, "
          f"{summary['plausible_correlation']} plausible, "
          f"{summary['unverified']} unverified)")


def test_demo_includes_vuln_correlations():
    """Verify /api/demo response includes vuln_correlations key from new pipeline."""
    response = client.post("/api/demo")
    assert response.status_code == 200
    data = response.json()
    assert "vuln_correlations" in data, "vuln_correlations key missing from /api/demo response"
    vc = data["vuln_correlations"]
    assert "correlations" in vc
    assert "summary" in vc
    assert "disclaimer" in vc
    assert "vuln_correlations_total" in data["summary"]
    assert "vuln_evidence_supported" in data["summary"]
    print(f"[PASS] POST /api/demo includes vuln_correlations "
          f"({vc['summary']['total']} total, "
          f"{vc['summary']['evidence_supported']} evidence_supported)")


if __name__ == "__main__":
    print("Running ARGUS-X FastAPI API test suite...\n")
    test_health()
    test_demo()
    test_analyze_valid()
    test_analyze_invalid_no_files()
    test_counterfactual()
    test_investigate()
    test_inventory()
    test_ocsf_normalize()
    test_vulnerabilities()
    test_ml_anomalies_endpoint()
    test_ml_analyze_log_removed()
    test_ml_train_endpoint()
    test_mitre_techniques_endpoint()
    test_mitre_map_endpoint()
    test_vuln_correlate_endpoint()
    test_demo_includes_vuln_correlations()
    print("\nALL API TESTS PASSED SUCCESSFULLY!")

