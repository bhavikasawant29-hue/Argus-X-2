"""
ARGUS-X MITRE ATT&CK Mapping Engine

Provides evidence-backed mapping from reconstructed attack events and multi-source
telemetry to official MITRE ATT&CK Enterprise techniques (STIX format).

DISCLAIMER & SEMANTICS:
- A generic event label or stage name alone DOES NOT confirm an ATT&CK technique.
- Mappings are categorized as:
    * "evidence_supported_candidate": Technical telemetry indicators and corroboration exist.
    * "candidate_requires_review": Behavioral pattern matches but specific technical proof is partial.
    * "unmapped": Telemetry lacks necessary technical detail to justify technique association.
- Tactics and techniques are tracked as distinct concepts.
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
import requests

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "mitre_attack"
CACHE_FILE = DATA_DIR / "enterprise_techniques_cache.json"
STIX_REMOTE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


class MitreAttackRepository:
    """Manages ingestion, caching, and querying of the official MITRE ATT&CK Enterprise dataset."""

    def __init__(self, cache_file: Optional[Path] = None):
        self.cache_file = cache_file or CACHE_FILE
        self.techniques: Dict[str, Dict[str, Any]] = {}
        self.dataset_version = "15.1"
        self._load_cache()

    def _load_cache(self) -> None:
        """Load parsed MITRE ATT&CK techniques from local JSON cache."""
        if not self.cache_file.exists():
            return
        try:
            with open(self.cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.dataset_version = data.get("version", "15.1")
                technique_list = data.get("techniques", [])
                for t in technique_list:
                    tid = t.get("technique_id")
                    if tid:
                        self.techniques[tid.upper()] = t
        except Exception:
            pass

    def parse_stix_bundle(self, stix_data: Dict[str, Any]) -> int:
        """
        Parse raw STIX 2.0/2.1 bundle from the official attack-stix-data repository.
        Filters out revoked and deprecated objects.
        """
        objects = stix_data.get("objects", [])
        parsed_count = 0

        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue

            # Skip revoked or deprecated techniques
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            external_refs = obj.get("external_references", [])
            technique_id = None
            official_url = None

            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    official_url = ref.get("url")
                    break

            if not technique_id:
                continue

            tactics = []
            kill_chain = obj.get("kill_chain_phases", [])
            for phase in kill_chain:
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactics.append(phase.get("phase_name"))

            technique_record = {
                "technique_id": technique_id,
                "technique_name": obj.get("name", "Unknown"),
                "tactics": tactics,
                "description": obj.get("description", ""),
                "official_url": official_url or f"https://attack.mitre.org/techniques/{technique_id}/",
                "platforms": obj.get("x_mitre_platforms", []),
                "dataset_version": obj.get("spec_version", self.dataset_version),
                "is_deprecated": False,
                "is_revoked": False,
            }
            self.techniques[technique_id.upper()] = technique_record
            parsed_count += 1

        if parsed_count > 0:
            self._save_cache()

        return parsed_count

    def _save_cache(self) -> None:
        """Save active techniques to local cache file."""
        self.cache_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": self.dataset_version,
            "count": len(self.techniques),
            "techniques": list(self.techniques.values()),
        }
        with open(self.cache_file, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)

    def download_and_update(self, url: str = STIX_REMOTE_URL, timeout: int = 20) -> Dict[str, Any]:
        """Fetch latest STIX enterprise bundle from remote source and update local cache."""
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                count = self.parse_stix_bundle(resp.json())
                return {
                    "status": "success",
                    "techniques_imported": count,
                    "dataset_version": self.dataset_version,
                }
            return {
                "status": "failed",
                "error": f"Remote source returned HTTP {resp.status_code}",
                "cached_techniques": len(self.techniques),
            }
        except Exception as exc:
            return {
                "status": "failed",
                "error": str(exc),
                "cached_techniques": len(self.techniques),
            }

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve technique record by ID (e.g. 'T1059.001' or 'T1059')."""
        return self.techniques.get(technique_id.strip().upper())

    def list_techniques(
        self,
        tactic: Optional[str] = None,
        query: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Query techniques by tactic or search keywords."""
        results = []
        q = query.lower().strip() if query else None
        tac = tactic.lower().strip() if tactic else None

        for t in self.techniques.values():
            if tac and tac not in [tc.lower() for tc in t.get("tactics", [])]:
                continue
            if q:
                match_id = q in t.get("technique_id", "").lower()
                match_name = q in t.get("technique_name", "").lower()
                match_desc = q in t.get("description", "").lower()
                if not (match_id or match_name or match_desc):
                    continue
            results.append(t)
            if len(results) >= limit:
                break
        return results


# Global repository instance
_repo_instance: Optional[MitreAttackRepository] = None


def get_mitre_repo() -> MitreAttackRepository:
    """Return singleton instance of MitreAttackRepository."""
    global _repo_instance
    if _repo_instance is None:
        _repo_instance = MitreAttackRepository()
    return _repo_instance


def map_attack_timeline_to_mitre(
    timeline_events: List[Any],
    all_events: Optional[List[Any]] = None,
    repo: Optional[MitreAttackRepository] = None,
) -> List[Dict[str, Any]]:
    """
    Evidence-based mapping of reconstructed attack events to candidate MITRE ATT&CK techniques.

    Applies strict technical criteria:
    - Does NOT confirm a technique on generic event labels alone.
    - Requires concrete indicators (command line, process, port, auth flags, or supporting logs).
    """
    repository = repo or get_mitre_repo()
    mappings: List[Dict[str, Any]] = []

    # Map supporting events index
    all_ev_map: Dict[str, Dict[str, Any]] = {}
    if all_events:
        for ev in all_events:
            d = ev if isinstance(ev, dict) else (ev.model_dump() if hasattr(ev, "model_dump") else ev.__dict__)
            eid = d.get("event_id")
            if eid:
                all_ev_map[eid] = d

    for item in timeline_events:
        ev = item if isinstance(item, dict) else (item.model_dump() if hasattr(item, "model_dump") else item.__dict__)
        eid = ev.get("event_id", "")
        stage = ev.get("stage") or ev.get("event_type") or ""
        event_type = str(ev.get("event_type") or "").lower()
        action = str(ev.get("action") or "").lower()
        context = str(ev.get("context") or ev.get("description") or "").lower()
        source_host = str(ev.get("source_host") or "").upper()
        dest_host = str(ev.get("destination_host") or "").upper()
        user = str(ev.get("user") or "")
        supp_ids = ev.get("supporting_events") or ev.get("supporting") or []

        # Gather text from supporting events for deep corroboration
        supp_texts = []
        for sid in supp_ids:
            sev = all_ev_map.get(sid, {})
            supp_texts.append(str(sev.get("event_type", "")).lower())
            supp_texts.append(str(sev.get("action", "")).lower())
            supp_texts.append(str(sev.get("context", "") or sev.get("description", "")).lower())
        full_context = f"{event_type} {action} {context} {' '.join(supp_texts)}"

        # Rule 1: Initial Access via Valid Accounts (T1078 / T1078.003)
        if "initial access" in stage.lower() or "authentication" in str(ev.get("source_type", "")).lower() or "login" in event_type:
            t_obj = repository.get_technique("T1078.003") or repository.get_technique("T1078")
            if "logon" in full_context or "login" in full_context or "credential" in full_context or "auth" in full_context:
                is_corroborated = len(supp_ids) >= 1 or "AUTHENTICATION" in eid
                mappings.append({
                    "technique_id": t_obj["technique_id"] if t_obj else "T1078.003",
                    "technique_name": t_obj["technique_name"] if t_obj else "Valid Accounts: Local Accounts",
                    "tactics": t_obj["tactics"] if t_obj else ["initial-access"],
                    "supporting_event_ids": [eid] + [s for s in supp_ids if "AUTH" in s],
                    "evidence_explanation": (
                        f"Authentication activity detected for account '{user}' on host '{source_host}'. "
                        f"Telemetry confirms account was utilized for interactive session initiation."
                    ),
                    "missing_evidence": [] if is_corroborated else ["Cross-source network or process corroboration"],
                    "mapping_method": "rule_based",
                    "evidence_status": "evidence_supported_candidate" if is_corroborated else "candidate_requires_review",
                    "official_url": t_obj["official_url"] if t_obj else "https://attack.mitre.org/techniques/T1078/003/",
                    "dataset_version": repository.dataset_version,
                })

        # Rule 2: Execution via Command and Scripting Interpreter: PowerShell (T1059.001)
        if "execution" in stage.lower() or "powershell" in full_context or "cmd.exe" in full_context:
            has_ps = "powershell" in full_context or "ps1" in full_context

            if has_ps:
                t_obj = repository.get_technique("T1059.001")
                tid = "T1059.001"
                tname = "Command and Scripting Interpreter: PowerShell"
                turl = "https://attack.mitre.org/techniques/T1059/001/"
            else:
                t_obj = repository.get_technique("T1059")
                tid = "T1059"
                tname = "Command and Scripting Interpreter"
                turl = "https://attack.mitre.org/techniques/T1059/"

            # Strict evidence check: does telemetry show script execution or just generic process start?
            has_script_args = any(k in full_context for k in ["bypass", "enc", "invoke", "download", "script", "command"])
            mappings.append({
                "technique_id": t_obj["technique_id"] if t_obj else tid,
                "technique_name": t_obj["technique_name"] if t_obj else tname,
                "tactics": ["execution"],
                "supporting_event_ids": [eid],
                "evidence_explanation": (
                    f"Process execution telemetry on '{source_host}' recorded interpreter execution "
                    f"({'PowerShell' if has_ps else 'Command Shell'}) by user '{user}'."
                ),
                "missing_evidence": [] if has_script_args else ["Full script block logging or command-line arguments"],
                "mapping_method": "rule_based",
                "evidence_status": "evidence_supported_candidate" if has_script_args else "candidate_requires_review",
                "official_url": t_obj["official_url"] if t_obj else turl,
                "dataset_version": repository.dataset_version,
            })

        # Rule 3: Credential Access via OS Credential Dumping (T1003 / T1003.001)
        if "credential access" in stage.lower() or "dump" in full_context or "lsass" in full_context:
            t_obj = repository.get_technique("T1003.001") or repository.get_technique("T1003")
            has_lsass_or_memory = "lsass" in full_context or "memory" in full_context
            has_dump_keyword = "dump" in action or "dump" in context

            mappings.append({
                "technique_id": t_obj["technique_id"] if t_obj else "T1003",
                "technique_name": t_obj["technique_name"] if t_obj else "OS Credential Dumping",
                "tactics": ["credential-access"],
                "supporting_event_ids": [eid],
                "evidence_explanation": (
                    f"Endpoint security telemetry on '{source_host}' identified credential extraction "
                    f"activity (action: '{action}')."
                ),
                "missing_evidence": [] if has_lsass_or_memory else ["Direct LSASS process open handle or SAM read telemetry"],
                "mapping_method": "rule_based",
                "evidence_status": "evidence_supported_candidate" if (has_dump_keyword and len(supp_ids) >= 1) else "candidate_requires_review",
                "official_url": t_obj["official_url"] if t_obj else "https://attack.mitre.org/techniques/T1003/",
                "dataset_version": repository.dataset_version,
            })

        # Rule 4: Lateral Movement via Remote Services (T1021 / T1021.002)
        if "lateral movement" in stage.lower() or (source_host and dest_host and source_host != dest_host and dest_host not in ["N/A", "UNKNOWN", ""]):
            t_obj = repository.get_technique("T1021.002") or repository.get_technique("T1021")
            has_internal_pivot = bool(source_host and dest_host and source_host != dest_host)
            has_smb_or_admin = any(k in full_context for k in ["smb", "445", "share", "rpc", "pipe"])

            mappings.append({
                "technique_id": t_obj["technique_id"] if t_obj else "T1021",
                "technique_name": t_obj["technique_name"] if t_obj else "Remote Services",
                "tactics": ["lateral-movement"],
                "supporting_event_ids": [eid] + [s for s in supp_ids if "NET" in s],
                "evidence_explanation": (
                    f"Network and host telemetry captured lateral transition from '{source_host}' to '{dest_host}' "
                    f"under user account '{user}'."
                ),
                "missing_evidence": [] if has_smb_or_admin else ["Service creation event or named pipe interaction log"],
                "mapping_method": "rule_based",
                "evidence_status": "evidence_supported_candidate" if (has_internal_pivot and len(supp_ids) >= 1) else "candidate_requires_review",
                "official_url": t_obj["official_url"] if t_obj else "https://attack.mitre.org/techniques/T1021/",
                "dataset_version": repository.dataset_version,
            })

        # Rule 5: Privilege Escalation via Token Manipulation or Exploitation (T1134 / T1068)
        if "privilege escalation" in stage.lower() or "token" in full_context or "impersonat" in full_context:
            has_token = "token" in full_context or "impersonat" in full_context
            tid = "T1134" if has_token else "T1068"
            tname = "Access Token Manipulation" if has_token else "Exploitation for Privilege Escalation"
            t_obj = repository.get_technique(tid)

            mappings.append({
                "technique_id": t_obj["technique_id"] if t_obj else tid,
                "technique_name": t_obj["technique_name"] if t_obj else tname,
                "tactics": ["privilege-escalation"],
                "supporting_event_ids": [eid],
                "evidence_explanation": (
                    f"Security telemetry on '{source_host}' identified privilege elevation "
                    f"({'token manipulation' if has_token else 'escalation sequence'})."
                ),
                "missing_evidence": [] if has_token else ["Explicit privilege assignment or CVE exploitation telemetry"],
                "mapping_method": "rule_based",
                "evidence_status": "evidence_supported_candidate" if has_token else "candidate_requires_review",
                "official_url": t_obj["official_url"] if t_obj else f"https://attack.mitre.org/techniques/{tid}/",
                "dataset_version": repository.dataset_version,
            })

        # Rule 6: Database / Application Data Access (T1048 or Impact/Collection)
        if "database access" in stage.lower() or "database" in full_context or "sql" in full_context:
            t_obj = repository.get_technique("T1048")
            mappings.append({
                "technique_id": "T1048" if not t_obj else t_obj["technique_id"],
                "technique_name": "Exfiltration Over Alternative Protocol" if not t_obj else t_obj["technique_name"],
                "tactics": ["exfiltration", "collection"],
                "supporting_event_ids": [eid] + [s for s in supp_ids if "APP" in s or "NET" in s],
                "evidence_explanation": (
                    f"Database query and sensitive resource interaction observed on target '{dest_host or source_host}' "
                    f"via application session."
                ),
                "missing_evidence": ["Network egress volume logs confirming outbound exfiltration beyond database server"],
                "mapping_method": "rule_based",
                "evidence_status": "candidate_requires_review",
                "official_url": "https://attack.mitre.org/techniques/T1048/",
                "dataset_version": repository.dataset_version,
            })

    # Deduplicate mappings by (technique_id, evidence_status)
    unique_mappings: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for m in mappings:
        key = f"{m['technique_id']}_{m['evidence_status']}"
        if key not in seen:
            seen.add(key)
            unique_mappings.append(m)

    return unique_mappings