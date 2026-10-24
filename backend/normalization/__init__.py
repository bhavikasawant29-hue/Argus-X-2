"""ARGUS-X Telemetry Normalization."""

from normalization.ocsf_normalization import (
    OCSF_VERSION,
    normalize_event,
    normalize_events,
)

__all__ = ["OCSF_VERSION", "normalize_event", "normalize_events"]

