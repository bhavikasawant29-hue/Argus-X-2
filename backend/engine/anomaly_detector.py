"""
ARGUS-X Machine Learning Anomaly Detection Engine

Implements unsupervised anomaly detection for multi-source security telemetry
(Endpoint, Network, Authentication, Application) using scikit-learn Isolation Forest.

DISCLAIMER & SEMANTICS:
- Anomaly scores quantify statistical divergence from the trained baseline.
- An anomaly score IS NOT an attack probability or proof of compromise.
- Anomalous events require corroborating telemetry before drawing investigative conclusions.
"""

import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple, Union
import numpy as np
import joblib
from sklearn.ensemble import IsolationForest

MODEL_DIR = Path(__file__).resolve().parent.parent / "data" / "models"
DEFAULT_MODEL_FILE = MODEL_DIR / "isolation_forest_baseline.joblib"
MODEL_VERSION = "isolation_forest_v1.0"

SOURCE_MAP = {
    "authentication": 0,
    "endpoint": 1,
    "network": 2,
    "application": 3,
}

SEVERITY_MAP = {
    "informational": 1,
    "info": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
    "fatal": 5,
}

FEATURE_NAMES = [
    "source_type_code",
    "severity_num",
    "user_event_freq",
    "host_event_freq",
    "failed_auth_count",
    "time_delta_sec",
    "distinct_dest_hosts",
    "is_external_or_pivot",
    "is_elevated_action",
    "context_len",
]


def _safe_event_dict(event: Any) -> Dict[str, Any]:
    """Convert a SecurityEvent model or raw dict into a standardized dictionary."""
    if hasattr(event, "model_dump"):
        return event.model_dump()
    if hasattr(event, "dict"):
        return event.dict()
    if isinstance(event, dict):
        return event
    return {}


def _parse_timestamp(ts_val: Any) -> Optional[float]:
    """Safely parse various timestamp formats to Unix epoch seconds."""
    if not ts_val:
        return None
    if isinstance(ts_val, (int, float)):
        return float(ts_val)
    ts_str = str(ts_val).strip()
    if not ts_str:
        return None

    formats = [
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(ts_str.replace("Z", "+00:00") if "Z" in ts_str else ts_str, fmt)
            return dt.timestamp()
        except Exception:
            continue
    try:
        dt = datetime.fromisoformat(ts_str)
        return dt.timestamp()
    except Exception:
        return None


def extract_features(events: List[Any]) -> Tuple[np.ndarray, List[str], List[Dict[str, Any]]]:
    """
    Extract a structured feature matrix from multi-source security events.

    Safely handles missing fields, categorical variables, and malformed timestamps.
    Returns:
        (feature_matrix, event_ids, event_metadata)
    """
    if not events:
        return np.empty((0, len(FEATURE_NAMES)), dtype=np.float32), [], []

    raw_events = [_safe_event_dict(e) for e in events]
    event_ids = [e.get("event_id") or f"EVT_{idx:04d}" for idx, e in enumerate(raw_events)]

    # Compute global dataset context for frequency features
    user_counts: Dict[str, int] = {}
    host_counts: Dict[str, int] = {}
    user_dest_map: Dict[str, set] = {}
    failed_auth_by_user: Dict[str, int] = {}

    timestamps: List[Optional[float]] = []

    for e in raw_events:
        u = str(e.get("user") or "unknown").strip().lower()
        sh = str(e.get("source_host") or "unknown").strip().upper()
        dh = str(e.get("destination_host") or "").strip().upper()
        st = str(e.get("source_type") or "").strip().lower()
        act = str(e.get("action") or "").strip().lower()
        desc = str(e.get("context") or e.get("description") or "").strip().lower()

        user_counts[u] = user_counts.get(u, 0) + 1
        host_counts[sh] = host_counts.get(sh, 0) + 1

        if dh and dh != "N/A" and dh != "UNKNOWN":
            user_dest_map.setdefault(u, set()).add(dh)

        if st == "authentication" and ("fail" in act or "fail" in desc or "invalid" in act):
            failed_auth_by_user[u] = failed_auth_by_user.get(u, 0) + 1

        timestamps.append(_parse_timestamp(e.get("timestamp")))

    # Sort timestamps to calculate inter-arrival delta if available
    rows = []
    prev_ts = None

    for idx, e in enumerate(raw_events):
        u = str(e.get("user") or "unknown").strip().lower()
        sh = str(e.get("source_host") or "unknown").strip().upper()
        dh = str(e.get("destination_host") or "").strip().upper()
        st = str(e.get("source_type") or "").strip().lower()
        sev = str(e.get("severity") or "medium").strip().lower()
        act = str(e.get("action") or "").strip().lower()
        desc = str(e.get("context") or e.get("description") or "").strip().lower()

        # 1. Source type numeric encoding
        source_code = float(SOURCE_MAP.get(st, 0))

        # 2. Severity numeric
        severity_num = float(SEVERITY_MAP.get(sev, 3))

        # 3. User & Host event frequencies (log-scaled count)
        user_freq = float(np.log1p(user_counts.get(u, 1)))
        host_freq = float(np.log1p(host_counts.get(sh, 1)))

        # 4. Failed authentication count for user
        failed_auth = float(failed_auth_by_user.get(u, 0))

        # 5. Time delta from previous event (capped at 86400s)
        cur_ts = timestamps[idx]
        if cur_ts is not None and prev_ts is not None and cur_ts >= prev_ts:
            delta = min(cur_ts - prev_ts, 86400.0)
        else:
            delta = 60.0  # default 1 min
        if cur_ts is not None:
            prev_ts = cur_ts

        # 6. Distinct destinations contacted
        distinct_dests = float(len(user_dest_map.get(u, set())))

        # 7. External or lateral pivot indicator
        is_pivot = 1.0 if (dh and dh != sh and dh not in ["N/A", "UNKNOWN", ""]) else 0.0

        # 8. Elevated action keywords
        is_elevated = 1.0 if any(k in act or k in desc for k in [
            "admin", "root", "token", "dump", "powershell", "cmd.exe", "privilege", "bypass", "impersonat"
        ]) else 0.0

        # 9. Context length (indicates complex commandline or payload)
        context_len = min(float(len(desc)), 500.0)

        feature_vector = [
            source_code,
            severity_num,
            user_freq,
            host_freq,
            failed_auth,
            float(delta),
            distinct_dests,
            is_pivot,
            is_elevated,
            context_len,
        ]
        rows.append(feature_vector)

    X = np.array(rows, dtype=np.float32)
    return X, event_ids, raw_events


def train_anomaly_model(
    events: List[Any],
    contamination: float = 0.05,
    random_state: int = 42,
    model_path: Optional[Union[str, Path]] = None,
    is_demo_baseline: bool = True
) -> Dict[str, Any]:
    """
    Train an Isolation Forest anomaly detection model on event features.

    Parameters:
        events: List of security events.
        contamination: Expected proportion of outliers in the training set (0.001 to 0.5).
        random_state: Random seed for reproducibility.
        model_path: Optional file path to persist the trained model.
        is_demo_baseline: Flag indicating whether training dataset is an uncertified synthetic baseline.
    """
    if len(events) < 5:
        raise ValueError(f"Insufficient events for training: minimum 5 required, got {len(events)}")

    contamination = max(0.001, min(float(contamination), 0.5))
    X, event_ids, _ = extract_features(events)

    model = IsolationForest(
        contamination=contamination,
        random_state=random_state,
        n_estimators=100,
        max_samples="auto"
    )
    model.fit(X)

    bundle = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "model_version": MODEL_VERSION,
        "contamination": contamination,
        "random_state": random_state,
        "trained_events_count": len(events),
        "trained_at": datetime.utcnow().isoformat(),
        "is_demo_baseline": is_demo_baseline,
        "baseline_warning": (
            "Model trained on uncertified synthetic telemetry baseline. "
            "Anomalies indicate divergence from this baseline and do not represent verified attacks."
        ) if is_demo_baseline else None
    }

    target_path = Path(model_path) if model_path else DEFAULT_MODEL_FILE
    save_anomaly_model(bundle, target_path)

    return {
        "status": "trained",
        "model_version": MODEL_VERSION,
        "events_trained": len(events),
        "contamination": contamination,
        "model_path": str(target_path),
        "is_demo_baseline": is_demo_baseline,
    }


def save_anomaly_model(bundle: Dict[str, Any], model_path: Union[str, Path]) -> None:
    """Safely persist model bundle and metadata using joblib."""
    path = Path(model_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path)


def load_anomaly_model(model_path: Optional[Union[str, Path]] = None) -> Optional[Dict[str, Any]]:
    """Load model bundle from disk if present."""
    path = Path(model_path) if model_path else DEFAULT_MODEL_FILE
    if not path.exists():
        return None
    try:
        return joblib.load(path)
    except Exception:
        return None


def _derive_reason_codes(features: np.ndarray, event: Dict[str, Any]) -> List[str]:
    """Derive human-readable investigative reason codes explaining why an event stood out."""
    reasons = []
    # FEATURE_NAMES: [source_type, severity_num, user_freq, host_freq, failed_auth, time_delta, distinct_dests, is_pivot, is_elevated, context_len]
    if features[1] >= 4.0:
        reasons.append("HIGH_SEVERITY_LEVEL")
    if features[4] >= 1.0:
        reasons.append("REPEATED_AUTHENTICATION_FAILURES")
    if features[5] < 5.0 and features[5] >= 0.0:
        reasons.append("RAPID_BURST_EXECUTION")
    if features[6] >= 2.0:
        reasons.append("MULTI_DESTINATION_HOST_PIVOT")
    if features[7] == 1.0:
        reasons.append("LATERAL_INFRASTRUCTURE_TRAVERSAL")
    if features[8] == 1.0:
        reasons.append("PRIVILEGED_OR_SCRIPT_EXECUTION")
    if features[9] >= 80.0:
        reasons.append("UNUSUAL_PAYLOAD_OR_COMMAND_LENGTH")

    if not reasons:
        reasons.append("STATISTICAL_FEATURE_OUTLIER")

    return reasons


def predict_anomalies(
    events: List[Any],
    model_path: Optional[Union[str, Path]] = None,
    auto_train_if_missing: bool = True
) -> List[Dict[str, Any]]:
    """
    Score a batch of events using the Isolation Forest model.

    Returns:
        List of anomaly assessment dicts for each input event.
    """
    if not events:
        return []

    bundle = load_anomaly_model(model_path)
    if bundle is None:
        if auto_train_if_missing and len(events) >= 5:
            # Self-bootstrap demo baseline
            train_anomaly_model(events, model_path=model_path, is_demo_baseline=True)
            bundle = load_anomaly_model(model_path)
        else:
            # Fallback heuristic if insufficient data to fit
            return [
                {
                    "event_id": getattr(e, "event_id", None) or (e.get("event_id") if isinstance(e, dict) else f"EVT_{i:04d}"),
                    "is_anomaly": False,
                    "anomaly_score": 0.0,
                    "model_version": "none_insufficient_baseline",
                    "reason_codes": ["MODEL_NOT_AVAILABLE"],
                    "corroboration_warning": "Anomaly detection model not fitted. No anomaly predictions available."
                }
                for i, e in enumerate(events)
            ]

    model: IsolationForest = bundle["model"]
    X, event_ids, raw_events = extract_features(events)

    if X.shape[0] == 0:
        return []

    # IsolationForest: predict returns -1 for outlier, 1 for inlier
    raw_preds = model.predict(X)
    # score_samples returns opposite of anomaly score (lower is more anomalous)
    raw_scores = model.score_samples(X)

    # Normalize scores to [0.0, 1.0] where 1.0 is maximally anomalous
    # Typical score_samples range: [-0.8, -0.3]
    # Score transformation: score = max(0.0, min(1.0, (-raw_score - 0.3) / 0.5))
    transformed_scores = np.clip((-raw_scores - 0.3) / 0.5, 0.0, 1.0)

    results = []
    for idx, (eid, is_outlier, score) in enumerate(zip(event_ids, raw_preds, transformed_scores)):
        is_anom = bool(is_outlier == -1)
        reasons = _derive_reason_codes(X[idx], raw_events[idx]) if is_anom else []

        results.append({
            "event_id": eid,
            "is_anomaly": is_anom,
            "anomaly_score": round(float(score), 4),
            "model_version": bundle.get("model_version", MODEL_VERSION),
            "reason_codes": reasons,
            "corroboration_warning": (
                "Anomaly score represents statistical deviation from baseline, NOT attack probability. "
                "Corroborating telemetry is required."
            )
        })

    return results


def evaluate_anomaly_model(
    events: List[Any],
    ground_truth_attack_ids: List[str],
    model_path: Optional[Union[str, Path]] = None
) -> Dict[str, Any]:
    """
    Calculate precision, recall, F1, confusion matrix, and false-positive rate
    against known ground-truth attack event IDs.
    """
    if not events:
        return {"error": "No events provided for evaluation"}

    if not ground_truth_attack_ids:
        return {
            "status": "unsupervised",
            "message": "Ground-truth labels unavailable; supervised evaluation cannot be performed."
        }

    preds = predict_anomalies(events, model_path=model_path)
    pred_map = {p["event_id"]: p["is_anomaly"] for p in preds}

    target_set = set(ground_truth_attack_ids)

    tp = 0
    fp = 0
    fn = 0
    tn = 0

    for e in events:
        eid = getattr(e, "event_id", None) or (e.get("event_id") if isinstance(e, dict) else "")
        is_attack = eid in target_set
        is_pred_anom = pred_map.get(eid, False)

        if is_attack and is_pred_anom:
            tp += 1
        elif not is_attack and is_pred_anom:
            fp += 1
        elif is_attack and not is_pred_anom:
            fn += 1
        else:
            tn += 1

    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    return {
        "status": "evaluated",
        "total_events": len(events),
        "ground_truth_attacks": len(ground_truth_attack_ids),
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives": tn,
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "confusion_matrix": {
            "tp": tp, "fp": fp,
            "fn": fn, "tn": tn
        },
        "evaluation_note": (
            "Evaluated against known benchmark ground-truth attack sequence. "
            "High recall indicates the unsupervised model flags ground-truth stages as statistical outliers."
        )
    }
