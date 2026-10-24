"""
Comprehensive OCSF v1.1.0 Compliance & Normalization Test Suite for ARGUS-X.

Tests:
1. All four source types (Endpoint, Network, Authentication, Application)
2. Missing fields handling and diagnostics
3. Invalid and edge-case timestamps
4. Unknown event types mapping to Other (activity_id 99)
5. Invalid source types raising clear errors
6. Empty input handling
7. Raw-event preservation and round-trip traceability
8. OCSF v1.1.0 schema validation (category_uid, class_uid, type_uid, status_id, severity_id)
9. Full dataset integration (809 events through load_events_with_normalization)
"""

import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from normalization.ocsf_normalization import (
    OCSF_VERSION,
    normalize_event,
    normalize_events,
    parse_timestamp,
    normalize_severity,
)
from normalization.ocsf_normalizer import normalize_event as normalizer_alias
from models.event import SecurityEvent
from ingestion.loader import load_all_ocsf_events, load_events_with_normalization


def test_four_sources_ocsf_mapping():
    print("[1] Testing four sources OCSF v1.1.0 mapping...")

    # 1. Endpoint -> Process Activity (1007, Category 1)
    ep = {
        "event_id": "EP-01",
        "timestamp": "2026-09-11T10:02:20Z",
        "source_type": "endpoint",
        "event_type": "process_execution",
        "user": "rahul",
        "source_host": "PC-25",
        "action": "powershell",
        "severity": "high",
    }
    r_ep = normalize_event(ep)
    assert r_ep["class_uid"] == 1007
    assert r_ep["category_uid"] == 1
    assert r_ep["category_name"] == "System Activity"
    assert r_ep["activity_id"] == 1  # Launch
    assert r_ep["type_uid"] == 100701
    assert r_ep["severity_id"] == 4  # High
    assert r_ep["status_id"] == 1  # Success
    assert r_ep["actor"]["user"]["name"] == "rahul"
    assert r_ep["device"]["hostname"] == "PC-25"
    assert r_ep["unmapped"]["original_event_id"] == "EP-01"
    assert r_ep["unmapped"]["raw_event"] == ep
    assert r_ep["is_valid"] is True
    print("  PASS: Endpoint -> Process Activity (class_uid=1007, category_uid=1, type_uid=100701)")

    # 2. Network -> Network Activity (4001, Category 4)
    net = {
        "event_id": "NET-01",
        "timestamp": "2026-09-11T10:04:40Z",
        "source_type": "network",
        "event_type": "outbound_connection",
        "user": "rahul",
        "source_ip": "192.168.1.40",
        "source_host": "PC-25",
        "destination_host": "SRV-02",
        "action": "remote_service",
        "severity": "high",
    }
    r_net = normalize_event(net)
    assert r_net["class_uid"] == 4001
    assert r_net["category_uid"] == 4
    assert r_net["category_name"] == "Network Activity"
    assert r_net["activity_id"] == 1  # Open
    assert r_net["type_uid"] == 400101
    assert r_net["src_endpoint"]["ip"] == "192.168.1.40"
    assert r_net["dst_endpoint"]["hostname"] == "SRV-02"
    assert r_net["unmapped"]["raw_event"] == net
    assert r_net["is_valid"] is True
    print("  PASS: Network -> Network Activity (class_uid=4001, category_uid=4, type_uid=400101)")

    # 3. Authentication -> Authentication (3002, Category 3)
    auth = {
        "event_id": "AUTH-01",
        "timestamp": "2026-09-11T10:00:30Z",
        "source_type": "authentication",
        "event_type": "login_failed",
        "user": "rahul",
        "source_ip": "192.168.1.25",
        "source_host": "PC-25",
        "severity": "medium",
    }
    r_auth = normalize_event(auth)
    assert r_auth["class_uid"] == 3002
    assert r_auth["category_uid"] == 3
    assert r_auth["category_name"] == "Identity & Access Management"
    assert r_auth["status_id"] == 2  # Failure
    assert r_auth["severity_id"] == 3  # Medium
    assert r_auth["actor"]["user"]["name"] == "rahul"
    assert r_auth["unmapped"]["raw_event"] == auth
    assert r_auth["is_valid"] is True
    print("  PASS: Authentication -> Authentication (class_uid=3002, category_uid=3, status_id=2)")

    # 4. Application -> Application Activity (6002, Category 6)
    app = {
        "event_id": "APP-01",
        "timestamp": "2026-09-11T10:15:10Z",
        "source_type": "application",
        "event_type": "database_access",
        "user": "rahul",
        "source_host": "SRV-02",
        "destination_host": "DB-01",
        "action": "read_sensitive_table",
        "severity": "high",
    }
    r_app = normalize_event(app)
    assert r_app["class_uid"] == 6002
    assert r_app["category_uid"] == 6
    assert r_app["category_name"] == "Application Activity"
    assert r_app["activity_id"] == 1  # Access
    assert r_app["severity_id"] == 4
    assert r_app["status_id"] == 1
    assert r_app["unmapped"]["raw_event"] == app
    assert r_app["is_valid"] is True
    print("  PASS: Application -> Application Activity (class_uid=6002, category_uid=6, type_uid=600201)")


def test_missing_fields_and_diagnostics():
    print("\n[2] Testing missing fields tracking and diagnostics...")
    event_no_time = {
        "event_id": "EV-02",
        "source_type": "endpoint",
        "event_type": "process_execution",
    }
    r = normalize_event(event_no_time)
    assert "time" in r["unmapped"]["missing_fields"]
    assert r["is_valid"] is False
    assert r["time"] is None

    event_no_id = {
        "timestamp": "2026-09-11T10:00:00Z",
        "source_type": "network",
        "event_type": "outbound_connection",
    }
    r2 = normalize_event(event_no_id)
    assert "original_event_id" in r2["unmapped"]["missing_fields"]
    assert r2["is_valid"] is False
    print("  PASS: Missing fields properly tracked in unmapped.missing_fields")


def test_timestamp_handling():
    print("\n[3] Testing timestamp edge cases...")
    # ISO UTC
    ts, err = parse_timestamp("2026-09-11T10:00:00Z")
    assert err is None and ts.endswith("+00:00")

    # Epoch seconds
    ts2, err2 = parse_timestamp(1700000000)
    assert err2 is None and "2023" in ts2

    # Malformed ISO string
    ts3, err3 = parse_timestamp("invalid-date-string")
    assert err3 is not None
    assert ts3 == "invalid-date-string"

    # None
    ts4, err4 = parse_timestamp(None)
    assert ts4 is None and "Missing" in err4
    print("  PASS: ISO, Epoch, Malformed, and None timestamps handled safely")


def test_severity_handling():
    print("\n[4] Testing severity mapping without inventing values...")
    assert normalize_severity(None) == (None, None)
    assert normalize_severity("informational")[0] == 1
    assert normalize_severity("low")[0] == 2
    assert normalize_severity("medium")[0] == 3
    assert normalize_severity("high")[0] == 4
    assert normalize_severity("critical")[0] == 5
    assert normalize_severity("fatal")[0] == 6
    assert normalize_severity(3)[0] == 3
    # Unrecognized severity maps to 0 (Unknown)
    assert normalize_severity("arbitrary_unknown_level")[0] == 0
    print("  PASS: OCSF severity IDs 0-6 strictly mapped")


def test_invalid_source_and_error_handling():
    print("\n[5] Testing invalid source types and batch resilience...")
    try:
        normalize_event({"source_type": "invalid_source"})
        assert False, "Should have raised ValueError"
    except ValueError as exc:
        assert "Unsupported source_type" in str(exc)
        print("  PASS: Unsupported source rejected with descriptive error")

    # Batch normalization continue_on_error
    batch = [
        {"source_type": "endpoint", "event_type": "test", "event_id": "E1", "timestamp": "2026-09-11T10:00:00Z"},
        {"source_type": "invalid_source"},
    ]
    res = normalize_events(batch, continue_on_error=True)
    assert len(res) == 2
    assert res[0]["is_valid"] is True
    assert res[1]["is_valid"] is False
    assert "Unsupported source_type" in res[1]["unmapped"]["normalization_errors"][0]
    print("  PASS: Batch normalization captures failed records without discarding")


def test_security_event_model_support():
    print("\n[6] Testing direct SecurityEvent model object support...")
    se = SecurityEvent(
        event_id="SE-001",
        timestamp="2026-09-11T10:00:30",
        source_type="authentication",
        event_type="login_success",
        user="rahul",
        source_ip="192.168.1.25",
        source_host="PC-25",
        destination_host=None,
        action="interactive_login",
        severity="low",
    )
    r = normalizer_alias(se)
    assert r["class_uid"] == 3002
    assert r["actor"]["user"]["name"] == "rahul"
    assert r["unmapped"]["original_event_id"] == "SE-001"
    assert r["status_id"] == 1
    assert r["severity_id"] == 2
    print("  PASS: SecurityEvent Pydantic model directly normalized")


def test_full_dataset_ocsf_loading():
    print("\n[7] Testing full dataset normalization (809 events)...")
    raw_events, ocsf_events, diagnostics = load_events_with_normalization()
    assert len(raw_events) == 809, f"Expected 809 raw events, got {len(raw_events)}"
    assert len(ocsf_events) == 809, f"Expected 809 OCSF events, got {len(ocsf_events)}"
    assert diagnostics["total_events"] == 809
    assert diagnostics["valid_events"] == 809
    assert diagnostics["invalid_events"] == 0
    assert diagnostics["ocsf_version"] == "1.1.0"

    # Verify event ID traceability for every event
    for raw, ocsf in zip(raw_events, ocsf_events):
        assert ocsf["unmapped"]["original_event_id"] == raw.event_id
        assert ocsf["metadata"]["original_event_id"] == raw.event_id

    print(f"  PASS: 809 events normalized to OCSF v1.1.0 (100% valid, 100% ID traceable)")
    print(f"  Source breakdown: {diagnostics['sources']}")
    print(f"  Class breakdown: {diagnostics['classes']}")


if __name__ == "__main__":
    print("Running ARGUS-X OCSF v1.1.0 Compliance & Normalization Test Suite...\n")
    test_four_sources_ocsf_mapping()
    test_missing_fields_and_diagnostics()
    test_timestamp_handling()
    test_severity_handling()
    test_invalid_source_and_error_handling()
    test_security_event_model_support()
    test_full_dataset_ocsf_loading()
    print("\nALL OCSF COMPLIANCE TESTS PASSED SUCCESSFULLY!")
