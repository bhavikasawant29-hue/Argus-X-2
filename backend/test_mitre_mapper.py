"""
Unit tests for ARGUS-X MITRE ATT&CK Mapping Engine.
Tests STIX bundle parsing, caching, querying, rule-based evidence-backed mapping,
status taxonomy, and error handling.
"""

import sys
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from engine.mitre_mapper import (
    MitreAttackRepository,
    get_mitre_repo,
    map_attack_timeline_to_mitre,
)
from engine.reconstruction import reconstruct_attack
from ingestion.loader import load_all_events


def test_repository_cache_and_queries():
    print("[1] Testing MitreAttackRepository caching and search...")
    repo = get_mitre_repo()
    assert len(repo.techniques) >= 10, f"Expected 10+ cached techniques, got {len(repo.techniques)}"

    t1059 = repo.get_technique("T1059.001")
    assert t1059 is not None
    assert t1059["technique_name"] == "Command and Scripting Interpreter: PowerShell"
    assert "execution" in t1059["tactics"]
    assert "https://attack.mitre.org/techniques/T1059/001/" in t1059["official_url"]

    # Search by tactic
    exec_techs = repo.list_techniques(tactic="execution")
    assert any(t["technique_id"] == "T1059" or t["technique_id"] == "T1059.001" for t in exec_techs)

    # Search by query keyword
    cred_techs = repo.list_techniques(query="credential")
    assert any("1003" in t["technique_id"] for t in cred_techs)

    print(f"  PASS: Loaded {len(repo.techniques)} official techniques; querying verified")


def test_stix_bundle_parsing_and_filtering():
    print("[2] Testing STIX 2.1 bundle parsing with revoked/deprecated filtering...")
    repo = MitreAttackRepository(cache_file=Path("test_dummy_stix_cache.json"))

    mock_stix_bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1111",
                "name": "Active Enterprise Technique",
                "description": "Standard active technique.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T9999", "url": "https://attack.mitre.org/techniques/T9999/"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
                "x_mitre_platforms": ["Windows"],
                "revoked": False,
                "x_mitre_deprecated": False,
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2222",
                "name": "Revoked Technique",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T8888"}
                ],
                "revoked": True,
                "x_mitre_deprecated": False,
            },
            {
                "type": "attack-pattern",
                "id": "attack-pattern--3333",
                "name": "Deprecated Technique",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T7777"}
                ],
                "revoked": False,
                "x_mitre_deprecated": True,
            },
            {
                "type": "identity",
                "id": "identity--4444",
                "name": "Non-technique Object",
            }
        ]
    }

    parsed = repo.parse_stix_bundle(mock_stix_bundle)
    assert parsed == 1, f"Expected 1 valid parsed technique, got {parsed}"
    assert repo.get_technique("T9999") is not None
    assert repo.get_technique("T8888") is None, "Revoked technique was not filtered out"
    assert repo.get_technique("T7777") is None, "Deprecated technique was not filtered out"

    # Clean up dummy cache if created
    if Path("test_dummy_stix_cache.json").exists():
        Path("test_dummy_stix_cache.json").unlink()

    print("  PASS: STIX parser correctly parsed active techniques and excluded revoked/deprecated entries")


def test_evidence_based_timeline_mapping():
    print("[3] Testing evidence-based timeline mapping on benchmark attack sequence...")
    events = load_all_events()
    timeline = reconstruct_attack(events)
    assert len(timeline) == 8, f"Expected 8 benchmark stages, got {len(timeline)}"

    mappings = map_attack_timeline_to_mitre(timeline, all_events=events)
    assert len(mappings) >= 4, f"Expected at least 4 candidate technique mappings, got {len(mappings)}"

    mapped_tids = {m["technique_id"]: m for m in mappings}
    print(f"  Mapped techniques: {list(mapped_tids.keys())}")

    # Check that key techniques were identified with proper evidence status
    assert "T1078.003" in mapped_tids or "T1078" in mapped_tids, "Missing Valid Accounts mapping"
    assert "T1059.001" in mapped_tids or "T1059" in mapped_tids, "Missing Command & Scripting mapping"
    assert "T1003" in mapped_tids or "T1003.001" in mapped_tids, "Missing Credential Dumping mapping"
    assert "T1021" in mapped_tids or "T1021.002" in mapped_tids, "Missing Remote Services mapping"
    assert "T1134" in mapped_tids or "T1068" in mapped_tids, "Missing Privilege Escalation mapping"

    for m in mappings:
        assert m["evidence_status"] in ("evidence_supported_candidate", "candidate_requires_review", "unmapped")
        assert len(m["supporting_event_ids"]) > 0
        assert len(m["evidence_explanation"]) > 10
        assert "official_url" in m
        assert m["official_url"].startswith("https://attack.mitre.org/techniques/")

    print("  PASS: Reconstructed attack timeline correctly mapped with technical evidence and review statuses")


def test_unsupported_and_empty_events():
    print("[4] Testing empty and unknown events handling...")
    res = map_attack_timeline_to_mitre([])
    assert res == []

    unknown_event = [{
        "event_id": "UNK_0001",
        "stage": "Unknown Activity",
        "action": "system_idle_heartbeat",
        "context": "periodic ping",
    }]
    res2 = map_attack_timeline_to_mitre(unknown_event)
    assert res2 == [], "Unknown event without attack patterns should not be mapped"
    print("  PASS: Empty and benign events correctly handled without false mappings")


if __name__ == "__main__":
    print("Running ARGUS-X MITRE ATT&CK Mapping Test Suite...")
    test_repository_cache_and_queries()
    test_stix_bundle_parsing_and_filtering()
    test_evidence_based_timeline_mapping()
    test_unsupported_and_empty_events()
    print("\nALL MITRE ATT&CK MAPPER TESTS PASSED SUCCESSFULLY!")

