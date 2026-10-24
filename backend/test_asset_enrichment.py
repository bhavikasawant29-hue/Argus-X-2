"""
Tests for Asset Inventory, Vulnerability Matching, and Event Enrichment.
"""

import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from engine.asset_inventory import get_asset_inventory, AssetInventory
from engine.vulnerability_matcher import (
    evaluate_vulnerability_candidate,
    match_vulnerabilities_to_assets,
    enrich_events_with_vulnerabilities,
    check_version_range,
)
from models.event import SecurityEvent


def test_asset_inventory_lookups():
    print("[1] Testing Asset Inventory lookups...")
    inv = get_asset_inventory()

    srv02 = inv.get_by_hostname("SRV-02")
    assert srv02 is not None
    assert srv02.asset_id == "ASSET-SRV02"
    assert srv02.criticality == "high"
    assert any(sw.product == "Log4j2" for sw in srv02.installed_software)
    print("  PASS: Found SRV-02 by hostname with Log4j2 component")

    by_ip = inv.get_by_ip("10.0.0.2")
    assert by_ip is not None
    assert by_ip.hostname == "SRV-02"
    print("  PASS: Found SRV-02 by IP 10.0.0.2")

    db01 = inv.get_by_hostname("DB-01")
    assert db01 is not None
    assert db01.criticality == "critical"
    print("  PASS: Found DB-01 with critical asset status")


def test_full_match_status_taxonomy():
    print("\n[2] Testing full match status taxonomy...")
    affected_log4j = {
        "vendor": "apache",
        "product": "log4j2",
        "version_start_including": "2.0.0",
        "version_end_excluding": "2.15.0",
    }

    # 1. version_affected
    status, reason = evaluate_vulnerability_candidate("Apache", "Log4j2", "2.14.1", affected_log4j)
    assert status == "version_affected"
    print(f"  PASS: version_affected -> {reason}")

    # 2. version_not_affected
    status, reason = evaluate_vulnerability_candidate("Apache", "Log4j2", "2.17.1", affected_log4j)
    assert status == "version_not_affected"
    print(f"  PASS: version_not_affected -> {reason}")

    # 3. insufficient_data (missing asset version)
    status, reason = evaluate_vulnerability_candidate("Apache", "Log4j2", None, affected_log4j)
    assert status == "insufficient_data"
    print(f"  PASS: insufficient_data -> {reason}")

    # 4. vendor_mismatch
    status, reason = evaluate_vulnerability_candidate("Microsoft", "Log4j2", "2.14.1", affected_log4j)
    assert status == "vendor_mismatch"
    print(f"  PASS: vendor_mismatch -> {reason}")

    # 5. product_mismatch
    status, reason = evaluate_vulnerability_candidate("Apache", "Tomcat", "9.0.50", affected_log4j)
    assert status == "product_mismatch"
    print(f"  PASS: product_mismatch -> {reason}")


def test_event_vulnerability_enrichment():
    print("\n[3] Testing Event Vulnerability Enrichment pipeline...")
    inv = get_asset_inventory()

    mock_vulns = [
        {
            "cve_id": "CVE-2021-44228",
            "description": "Log4Shell remote code execution",
            "cvss_score": 10.0,
            "cvss_severity": "CRITICAL",
            "known_exploited": True,
            "epss_score": 0.975,
            "affected_products": [
                {
                    "vendor": "apache",
                    "product": "log4j2",
                    "version_start_including": "2.0.0",
                    "version_end_excluding": "2.15.0",
                }
            ],
        }
    ]

    test_events = [
        SecurityEvent(
            event_id="NET_0002",
            timestamp="2026-09-11T10:09:20",
            source_type="network",
            event_type="lateral_movement",
            user="rahul",
            source_host="PC-25",
            destination_host="SRV-02",
            action="remote_login",
            severity="high",
        ),
        SecurityEvent(
            event_id="AUTH_0001",
            timestamp="2026-09-11T10:00:30",
            source_type="authentication",
            event_type="login_failed",
            user="rahul",
            source_host="PC-25",
            destination_host=None,
            action="interactive_login",
            severity="medium",
        ),
    ]

    enriched = enrich_events_with_vulnerabilities(test_events, asset_inventory=inv, vulnerabilities=mock_vulns)
    assert len(enriched) == 2

    # NET_0002 targeting SRV-02 should have Log4j match
    e1 = enriched[0]
    assert e1["event_id"] == "NET_0002"
    enrichment1 = e1["vulnerability_enrichment"]
    assert enrichment1["target_host"] == "SRV-02"
    assert enrichment1["asset_id"] == "ASSET-SRV02"
    assert enrichment1["asset_criticality"] == "high"
    assert enrichment1["vulnerabilities_found"] == 1
    match = enrichment1["matches"][0]
    assert match["cve_id"] == "CVE-2021-44228"
    assert match["match_status"] == "version_affected"
    assert match["cvss_score"] == 10.0
    assert match["known_exploited"] is True
    assert "threat_disclaimer" in enrichment1
    print("  PASS: NET_0002 targeting SRV-02 enriched with CVE-2021-44228 (version_affected, high criticality)")

    # AUTH_0001 targeting PC-25 should have 0 matches for Log4j
    e2 = enriched[1]
    assert e2["event_id"] == "AUTH_0001"
    enrichment2 = e2["vulnerability_enrichment"]
    assert enrichment2["target_host"] == "PC-25"
    assert enrichment2["vulnerabilities_found"] == 0
    print("  PASS: AUTH_0001 on PC-25 properly enriched with 0 false matches")


if __name__ == "__main__":
    print("Running ARGUS-X Asset Inventory & Vulnerability Enrichment Test Suite...\n")
    test_asset_inventory_lookups()
    test_full_match_status_taxonomy()
    test_event_vulnerability_enrichment()
    print("\nALL ASSET & ENRICHMENT TESTS PASSED SUCCESSFULLY!")
