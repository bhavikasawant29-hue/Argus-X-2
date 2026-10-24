
"""CSV ingestion for ARGUS-X security telemetry."""

import io
from pathlib import Path

import pandas as pd

from models.event import SecurityEvent
from normalization.ocsf_normalization import normalize_event


# Project root / data / raw
DATA_DIR = Path(__file__).resolve().parents[2] / "data" / "raw"


def get_value(row, column):
    """Return a CSV cell as a string, or None if missing."""
    if column not in row.index or pd.isna(row[column]):
        return None
    return str(row[column])


def _row_to_event(row, index, source_type):
    """Convert one pandas row into the existing SecurityEvent model."""
    return SecurityEvent(
        event_id=f"{source_type.upper()}_{index + 1:04d}",
        timestamp=get_value(row, "timestamp"),
        source_type=source_type,
        event_type=get_value(row, "event_type"),
        user=get_value(row, "user"),
        source_ip=get_value(row, "source_ip"),
        source_host=get_value(row, "source_host"),
        destination_host=get_value(row, "destination_host"),
        action=get_value(row, "action"),
        severity=get_value(row, "severity"),
    )


def load_csv_from_bytes(file_bytes, source_type):
    """Load CSV data supplied as bytes."""
    if not file_bytes or len(file_bytes.strip()) == 0:
        return []

    df = pd.read_csv(io.BytesIO(file_bytes))

    return [
        _row_to_event(row, index, source_type)
        for index, (_, row) in enumerate(df.iterrows())
    ]


def load_csv(filename, source_type):
    """Load a CSV file from the raw data directory."""
    file_path = DATA_DIR / filename

    if not file_path.exists():
        raise FileNotFoundError(f"CSV file not found: {file_path}")

    df = pd.read_csv(file_path)

    return [
        _row_to_event(row, index, source_type)
        for index, (_, row) in enumerate(df.iterrows())
    ]


def load_all_events():
    """
    Load all four sources as SecurityEvent objects.

    This preserves the existing interface used by the ARGUS-X engine.
    """
    authentication = load_csv(
        "authentication_logs.csv",
        "authentication",
    )

    endpoint = load_csv(
        "endpoint_logs.csv",
        "endpoint",
    )

    network = load_csv(
        "network_logs.csv",
        "network",
    )

    application = load_csv(
        "application_logs.csv",
        "application",
    )

    all_events = authentication + endpoint + network + application

    # Keep events with missing timestamps at the end rather than crashing.
    return sorted(
        all_events,
        key=lambda event: event.timestamp or "",
    )


def normalize_security_event(event: SecurityEvent) -> dict:
    """Convert a SecurityEvent into the OCSF v1.1.0 normalized representation."""
    return normalize_event(
        event,
        source_type=event.source_type,
    )


def load_all_ocsf_events() -> list[dict]:
    """
    Load the four CSV sources and return OCSF v1.1.0 normalized event dictionaries.

    This preserves load_all_events() for existing correlation and attack-reconstruction code.
    """
    events = load_all_events()

    return [
        normalize_security_event(event)
        for event in events
    ]


def load_events_with_normalization() -> tuple[list[SecurityEvent], list[dict], dict]:
    """
    Load all events and return:
        (security_events, ocsf_events, diagnostics_report)

    Tracks total events, valid events, missing fields, and source distribution.
    """
    events = load_all_events()
    ocsf_events = [normalize_security_event(event) for event in events]

    valid_count = sum(1 for e in ocsf_events if e.get("is_valid", False))
    sources_count = {}
    classes_count = {}
    missing_fields_total = {}

    for e in ocsf_events:
        src = e.get("metadata", {}).get("source_type", "unknown")
        sources_count[src] = sources_count.get(src, 0) + 1

        cls_name = e.get("class_name", "unknown")
        classes_count[cls_name] = classes_count.get(cls_name, 0) + 1

        for mf in e.get("unmapped", {}).get("missing_fields", []):
            missing_fields_total[mf] = missing_fields_total.get(mf, 0) + 1

    report = {
        "ocsf_version": "1.1.0",
        "total_events": len(events),
        "valid_events": valid_count,
        "invalid_events": len(events) - valid_count,
        "sources": sources_count,
        "classes": classes_count,
        "missing_fields": missing_fields_total,
    }

    return events, ocsf_events, report

