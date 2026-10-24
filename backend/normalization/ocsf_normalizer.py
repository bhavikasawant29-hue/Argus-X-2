"""
ARGUS-X OCSF Normalizer Module.
Re-exports OCSF v1.1.0 normalization functions for compatibility.
"""

from normalization.ocsf_normalization import (
    OCSF_VERSION,
    OCSF_CLASSES,
    CATEGORY_UIDS,
    CATEGORY_NAMES,
    SOURCE_TYPES,
    SOURCE_ALIASES,
    normalize_event,
    normalize_events,
    parse_timestamp,
    normalize_severity,
    infer_class,
    infer_activity,
    infer_status,
    infer_disposition,
)

__all__ = [
    "OCSF_VERSION",
    "OCSF_CLASSES",
    "CATEGORY_UIDS",
    "CATEGORY_NAMES",
    "SOURCE_TYPES",
    "SOURCE_ALIASES",
    "normalize_event",
    "normalize_events",
    "parse_timestamp",
    "normalize_severity",
    "infer_class",
    "infer_activity",
    "infer_status",
    "infer_disposition",
]

