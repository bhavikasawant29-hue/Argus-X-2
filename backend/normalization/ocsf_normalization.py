"""
ARGUS-X OCSF Normalizer.
Aligned with OCSF (Open Cybersecurity Schema Framework) v1.1.0 specification.

Supported Telemetry Sources:
- Endpoint (Class 1007: Process Activity, Class 1001: File Activity)
- Network (Class 4001: Network Activity)
- Authentication (Class 3002: Authentication)
- Application (Class 6002: Application Activity)

OCSF Version: 1.1.0
Categories:
- 1: System Activity
- 3: Identity & Access Management
- 4: Network Activity
- 6: Application Activity

Preserves original raw events, event IDs, and unmapped fields for strict evidence traceability.
"""

from datetime import datetime, timezone
from typing import Any, Optional, Tuple, Dict, List


OCSF_VERSION = "1.1.0"

# OCSF v1.1.0 Event Class IDs
OCSF_CLASSES = {
    "process_activity": 1007,
    "file_activity": 1001,
    "authentication": 3002,
    "network_activity": 4001,
    "application_activity": 6002,
}

# OCSF v1.1.0 Category UIDs
CATEGORY_UIDS = {
    "process_activity": 1,
    "file_activity": 1,
    "authentication": 3,
    "network_activity": 4,
    "application_activity": 6,
}

# OCSF v1.1.0 Category Names
CATEGORY_NAMES = {
    "process_activity": "System Activity",
    "file_activity": "System Activity",
    "authentication": "Identity & Access Management",
    "network_activity": "Network Activity",
    "application_activity": "Application Activity",
}

SOURCE_TYPES = {
    "endpoint",
    "network",
    "authentication",
    "application",
}

SOURCE_ALIASES = {
    "edr": "endpoint",
    "host": "endpoint",
    "firewall": "network",
    "ids": "network",
    "auth": "authentication",
    "identity": "authentication",
    "app": "application",
}


def first_value(event: dict, *keys: str, default=None):
    """Return the first value that is present and not empty."""
    for key in keys:
        value = event.get(key)
        if value is not None and value != "":
            return value
    return default


def parse_timestamp(value: Any) -> Tuple[Optional[str], Optional[str]]:
    """Convert a timestamp to an ISO-8601 UTC string when possible.

    Returns:
        (normalized_iso_str, error_message_if_any)
    """
    if value is None:
        return None, "Missing timestamp"

    if isinstance(value, (int, float)):
        try:
            timestamp = value / 1000 if value > 10_000_000_000 else value
            dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
            return dt.isoformat(), None
        except (ValueError, OverflowError, OSError) as exc:
            return str(value), f"Numeric timestamp overflow/invalid: {exc}"

    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None, "Empty timestamp string"
        try:
            dt = datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
        except ValueError:
            # Preserve original value for evidence audit trail
            return cleaned, f"Malformed ISO timestamp: {cleaned}"
    else:
        return str(value), f"Unknown timestamp type: {type(value).__name__}"

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    return dt.astimezone(timezone.utc).isoformat(), None


def normalize_severity(value: Any) -> Tuple[Optional[int], Optional[str]]:
    """Map severity labels to official OCSF v1.1.0 severity IDs.

    OCSF Severity:
    0 = Unknown
    1 = Informational
    2 = Low
    3 = Medium
    4 = High
    5 = Critical
    6 = Fatal
    """
    if value is None:
        return None, None

    if isinstance(value, (int, float)):
        severity = int(value)
        if 0 <= severity <= 6:
            names = ["Unknown", "Informational", "Low", "Medium", "High", "Critical", "Fatal"]
            return severity, names[severity]
        return 0, "Unknown"

    s_str = str(value).strip().lower()
    severity_map = {
        "unknown": (0, "Unknown"),
        "informational": (1, "Informational"),
        "info": (1, "Informational"),
        "low": (2, "Low"),
        "medium": (3, "Medium"),
        "moderate": (3, "Medium"),
        "high": (4, "High"),
        "critical": (5, "Critical"),
        "fatal": (6, "Fatal"),
    }

    if s_str in severity_map:
        return severity_map[s_str]

    return 0, f"Unrecognized severity: {value}"


def infer_class(source: str, event: dict) -> str:
    """Select standard OCSF event class based on source and event type."""
    if source == "authentication":
        return "authentication"

    if source == "network":
        return "network_activity"

    if source == "application":
        return "application_activity"

    event_type = str(
        first_value(
            event,
            "event_type",
            "event_name",
            "type",
            "action",
            default="",
        )
    ).lower()

    if any(word in event_type for word in ("file", "file_created", "file_deleted", "file_access")):
        return "file_activity"

    return "process_activity"


def infer_activity(event_class: str, event_type: str, action: Optional[str]) -> Tuple[int, str]:
    """Map event type and action to official OCSF v1.1.0 Activity IDs and Names.

    Standard OCSF Activity definitions:
    - Process Activity (1007): 1=Launch, 2=Terminate, 99=Other
    - File Activity (1001): 1=Create, 2=Read, 3=Modify, 4=Delete, 99=Other
    - Authentication (3002): 1=Logon, 2=Logoff, 99=Other
    - Network Activity (4001): 1=Open, 2=Close, 99=Other
    - Application Activity (6002): 1=Access, 99=Other
    """
    et = (event_type or "").lower()
    act = (action or "").lower()

    if event_class == "process_activity":
        if any(w in et or w in act for w in ("start", "exec", "launch", "run", "powershell", "svchost", "chrome", "backup")):
            return 1, "Launch"
        if any(w in et or w in act for w in ("exit", "terminate", "kill", "stop")):
            return 2, "Terminate"
        return 99, "Other"

    if event_class == "file_activity":
        if "create" in et or "create" in act:
            return 1, "Create"
        if "access" in et or "read" in act:
            return 2, "Read"
        if "delete" in et or "delete" in act:
            return 4, "Delete"
        return 99, "Other"

    if event_class == "authentication":
        if "logout" in et or "logoff" in et or "logout" in act:
            return 2, "Logoff"
        if any(w in et for w in ("login", "logon", "interactive_login", "auth")):
            return 1, "Logon"
        return 99, "Other"

    if event_class == "network_activity":
        if "close" in et or "disconnect" in et:
            return 2, "Close"
        if any(w in et or w in act for w in ("connection", "connect", "outbound", "lateral", "http", "dns", "ssh", "allowed")):
            return 1, "Open"
        return 99, "Other"

    if event_class == "application_activity":
        if any(w in et or w in act for w in ("access", "query", "request", "read", "write", "upload")):
            return 1, "Access"
        return 99, "Other"

    return 99, "Other"


def infer_status(event_type: str, action: Optional[str]) -> Tuple[int, str, str]:
    """Map outcome to OCSF status_id (0=Unknown, 1=Success, 2=Failure) and status strings."""
    combined = f"{event_type or ''} {action or ''}".lower()

    if any(w in combined for w in ("failed", "failure", "blocked", "denied", "error", "rejected", "timeout")):
        return 2, "Failure", "Event execution or connection was blocked, timed out, or failed"

    if any(w in combined for w in (
        "success", "allowed", "started", "opened", "created", "executed", "execution",
        "connected", "connection", "query", "request", "upload", "access", "escalat",
        "movement", "dump", "powershell", "svchost", "chrome", "backup", "explorer",
        "logout", "logoff", "change", "update", "exit"
    )):
        return 1, "Success", "Event executed, connected, or recorded successfully"

    return 0, "Unknown", "Status could not be reliably determined from telemetry"



def infer_disposition(event_type: str, action: Optional[str]) -> Tuple[int, str]:
    """Map network or security controls to OCSF disposition_id (1=Allowed, 2=Blocked, 0=Unknown)."""
    combined = f"{event_type or ''} {action or ''}".lower()
    if any(w in combined for w in ("blocked", "denied", "rejected", "dropped")):
        return 2, "Blocked"
    if any(w in combined for w in ("allowed", "permitted", "success")):
        return 1, "Allowed"
    return 0, "Unknown"


def normalize_event(
    raw_event: Any,
    source_type: str | None = None,
) -> dict:
    """Normalize one raw event or SecurityEvent into official OCSF v1.1.0 event representation."""
    normalization_errors: List[str] = []
    missing_fields: List[str] = []

    # Support SecurityEvent pydantic objects as well as raw dictionaries
    if hasattr(raw_event, "model_dump"):
        event_dict = raw_event.model_dump(exclude_none=False)
    elif hasattr(raw_event, "dict"):
        event_dict = raw_event.dict(exclude_none=False)
    elif isinstance(raw_event, dict):
        event_dict = raw_event
    else:
        raise TypeError(f"raw_event must be a dictionary or SecurityEvent, got {type(raw_event).__name__}")

    source = str(
        source_type
        or first_value(
            event_dict,
            "source_type",
            "log_source",
            "source",
            default="",
        )
    ).strip().lower()

    source = SOURCE_ALIASES.get(source, source)

    if source not in SOURCE_TYPES:
        raise ValueError(
            f"Unsupported source_type '{source}'. "
            f"Expected one of: {', '.join(sorted(SOURCE_TYPES))}"
        )

    event_class = infer_class(source, event_dict)
    class_uid = OCSF_CLASSES[event_class]
    category_uid = CATEGORY_UIDS[event_class]
    category_name = CATEGORY_NAMES[event_class]

    timestamp_raw = first_value(
        event_dict,
        "time",
        "timestamp",
        "event_time",
        "@timestamp",
        "created_at",
    )
    timestamp, ts_error = parse_timestamp(timestamp_raw)
    if ts_error:
        normalization_errors.append(ts_error)
    if timestamp_raw is None:
        missing_fields.append("time")

    event_id = first_value(
        event_dict,
        "event_id",
        "id",
        "record_id",
        "log_id",
    )
    if event_id is None:
        missing_fields.append("original_event_id")

    hostname = first_value(
        event_dict,
        "hostname",
        "host",
        "host_name",
        "computer",
        "device_name",
        "source_host",
    )

    username = first_value(
        event_dict,
        "username",
        "user",
        "user_name",
        "account",
        "principal",
    )

    source_ip = first_value(
        event_dict,
        "source_ip",
        "src_ip",
        "src",
        "client_ip",
    )

    destination_ip = first_value(
        event_dict,
        "destination_ip",
        "dest_ip",
        "dst_ip",
        "dst",
        "server_ip",
    )

    source_port = first_value(event_dict, "source_port", "src_port")
    destination_port = first_value(
        event_dict, "destination_port", "dest_port", "dst_port"
    )

    destination_host = first_value(
        event_dict, "destination_host", "dest_host"
    )

    process_name = first_value(
        event_dict, "process_name", "process", "image"
    )
    process_id = first_value(event_dict, "process_id", "pid")

    event_type = first_value(
        event_dict,
        "event_type",
        "event_name",
        "type",
        "action",
        default="unknown",
    )

    action = first_value(event_dict, "action")
    description = first_value(
        event_dict, "description", "message", "details"
    )

    severity_raw = first_value(
        event_dict, "severity", "level", "severity_name"
    )
    severity_id, severity_name = normalize_severity(severity_raw)

    activity_id, activity_name = infer_activity(event_class, str(event_type), action)
    type_uid = class_uid * 100 + activity_id
    status_id, status_name, status_detail = infer_status(str(event_type), action)
    disposition_id, disposition_name = infer_disposition(str(event_type), action)

    is_valid = (timestamp is not None and len(missing_fields) == 0 and len(normalization_errors) == 0)

    return {
        "class_uid": class_uid,
        "class_name": event_class,
        "category_uid": category_uid,
        "category_name": category_name,
        "activity_id": activity_id,
        "activity_name": str(event_type),
        "ocsf_activity_name": activity_name,
        "type_uid": type_uid,
        "time": timestamp,
        "severity_id": severity_id,
        "severity": severity_name,
        "status_id": status_id,
        "status": status_name,
        "status_detail": status_detail,
        "disposition_id": disposition_id,
        "disposition": disposition_name,
        "metadata": {
            "version": OCSF_VERSION,
            "product": {
                "name": "ARGUS-X",
                "vendor_name": "ARGUS-X",
                "version": "2.4.0",
            },
            "profiles": ["security_control"],
            "source_type": source,
            "original_event_id": event_id,
            "normalizer": "argus_x_ocsf_v1_1_0_normalizer",
        },
        "message": description or f"{event_class}: {event_type} on {hostname or 'unknown-host'}",
        "actor": {
            "user": {"name": username} if username else None,
            "process": {
                "name": process_name,
                "pid": process_id,
            } if process_name is not None or process_id is not None else None,
        },
        "device": {
            "hostname": hostname,
            "type": "server" if hostname and hostname.startswith("SRV-") else ("database" if hostname and hostname.startswith("DB-") else "workstation"),
        } if hostname else None,
        "src_endpoint": {
            "ip": source_ip,
            "port": source_port,
            "hostname": hostname,
        } if (source_ip is not None or source_port is not None or hostname is not None) else None,
        "dst_endpoint": {
            "ip": destination_ip,
            "port": destination_port,
            "hostname": destination_host,
        } if (
            destination_ip is not None
            or destination_port is not None
            or destination_host is not None
        ) else None,
        "unmapped": {
            "original_event_id": event_id,
            "original_source": source,
            "action": action,
            "missing_fields": missing_fields,
            "normalization_errors": normalization_errors,
            "raw_event": event_dict,
        },
        "is_valid": is_valid,
    }


def normalize_events(
    events: list[dict],
    source_type: str | None = None,
    continue_on_error: bool = True,
) -> list[dict]:
    """Normalize multiple events, collecting diagnostics rather than discarding records."""
    normalized = []

    for index, event in enumerate(events):
        try:
            normalized.append(
                normalize_event(event, source_type=source_type)
            )
        except Exception as exc:
            if not continue_on_error:
                raise ValueError(
                    f"Failed to normalize event at index {index}: {exc}"
                ) from exc
            # Preserve failing event with diagnostic flag rather than silently discarding
            normalized.append({
                "class_uid": 0,
                "class_name": "unknown",
                "category_uid": 0,
                "category_name": "Unknown",
                "time": None,
                "severity_id": 0,
                "metadata": {
                    "version": OCSF_VERSION,
                    "product": {"name": "ARGUS-X"},
                    "source_type": source_type or "unknown",
                    "normalizer": "argus_x_ocsf_v1_1_0_normalizer",
                },
                "message": f"Normalization failed: {str(exc)}",
                "unmapped": {
                    "raw_event": event if isinstance(event, dict) else str(event),
                    "normalization_errors": [str(exc)],
                    "missing_fields": [],
                },
                "is_valid": False,
            })

    return normalized


