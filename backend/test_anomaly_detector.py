"""
Unit tests for ARGUS-X ML Anomaly Detection Engine (Isolation Forest).
Tests feature extraction, missing values, timestamps, training, joblib persistence, inference, and evaluation.
"""

import sys
import tempfile
from pathlib import Path

backend_dir = Path(__file__).resolve().parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from engine.anomaly_detector import (
    extract_features,
    train_anomaly_model,
    predict_anomalies,
    save_anomaly_model,
    load_anomaly_model,
    evaluate_anomaly_model,
    FEATURE_NAMES,
)
from ingestion.loader import load_all_events


def test_empty_input():
    print("[1] Testing empty input...")
    X, ids, meta = extract_features([])
    assert X.shape == (0, len(FEATURE_NAMES)), f"Expected empty matrix with {len(FEATURE_NAMES)} cols, got {X.shape}"
    assert ids == []
    assert meta == []

    preds = predict_anomalies([])
    assert preds == []
    print("  PASS: Empty input handled safely")


def test_missing_fields_and_malformed_timestamps():
    print("[2] Testing missing fields and malformed timestamps...")
    malformed_events = [
        {"event_id": "EVT_001", "timestamp": "invalid_ts", "source_type": None},
        {"event_id": "EVT_002", "timestamp": None, "source_type": "endpoint", "user": None},
        {"event_id": "EVT_003", "timestamp": "2026-09-11T10:00:00Z", "action": "cmd.exe admin token"},
        {"event_id": "EVT_004", "timestamp": "2026-09-11 10:01:00", "severity": "CRITICAL"},
        {"event_id": "EVT_005", "timestamp": 1726050000, "source_host": "PC-01", "destination_host": "SRV-02"},
    ]
    X, ids, meta = extract_features(malformed_events)
    assert X.shape == (5, len(FEATURE_NAMES))
    assert ids == ["EVT_001", "EVT_002", "EVT_003", "EVT_004", "EVT_005"]
    # Check that no NaNs or Infs exist in feature matrix
    import numpy as np
    assert not np.isnan(X).any(), "Feature matrix contains NaN values"
    assert not np.isinf(X).any(), "Feature matrix contains Inf values"
    print("  PASS: Missing fields and malformed timestamps parsed without NaN/Inf")


def test_train_save_load_persistence():
    print("[3] Testing model training and persistence...")
    events = load_all_events()
    assert len(events) >= 800, f"Expected 800+ benchmark events, got {len(events)}"

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_model = Path(tmp_dir) / "test_iso_forest.joblib"

        train_res = train_anomaly_model(
            events,
            contamination=0.08,
            random_state=42,
            model_path=tmp_model,
            is_demo_baseline=True
        )
        assert train_res["status"] == "trained"
        assert train_res["events_trained"] == len(events)
        assert tmp_model.exists(), "Model file was not created on disk"

        # Load back
        bundle = load_anomaly_model(tmp_model)
        assert bundle is not None
        assert bundle["model_version"] == "isolation_forest_v1.0"
        assert bundle["contamination"] == 0.08
        assert bundle["is_demo_baseline"] is True

        # Inference using persisted model
        preds = predict_anomalies(events[:20], model_path=tmp_model)
        assert len(preds) == 20
        for p in preds:
            assert "event_id" in p
            assert "is_anomaly" in p
            assert isinstance(p["is_anomaly"], bool)
            assert "anomaly_score" in p
            assert 0.0 <= p["anomaly_score"] <= 1.0
            assert "reason_codes" in p
            assert "corroboration_warning" in p

    print("  PASS: Model trained, persisted, loaded, and inferred accurately")


def test_supervised_evaluation():
    print("[4] Testing supervised evaluation against ground truth...")
    events = load_all_events()
    ground_truth_attack_ids = [
        "AUTHENTICATION_0001",
        "AUTHENTICATION_0002",
        "ENDPOINT_0001",
        "ENDPOINT_0002",
        "NETWORK_0002",
        "ENDPOINT_0003",
        "NETWORK_0006",
        "APPLICATION_0004",
    ]

    metrics = evaluate_anomaly_model(events, ground_truth_attack_ids)
    assert metrics["status"] == "evaluated"
    assert metrics["total_events"] == len(events)
    assert metrics["ground_truth_attacks"] == 8
    assert "precision" in metrics
    assert "recall" in metrics
    assert "f1_score" in metrics
    assert "false_positive_rate" in metrics
    assert "confusion_matrix" in metrics
    print(f"  Recall on ground-truth attacks: {metrics['recall'] * 100:.1f}%")
    print(f"  Precision: {metrics['precision']:.3f}, F1: {metrics['f1_score']:.3f}")
    print("  PASS: Supervised evaluation metrics computed successfully")


def test_insufficient_training_data_error():
    print("[5] Testing insufficient training data validation...")
    try:
        train_anomaly_model([{"event_id": "EVT_1"}])
        assert False, "Should have raised ValueError on < 5 events"
    except ValueError:
        pass
    print("  PASS: Proper ValueError on insufficient training data")


if __name__ == "__main__":
    print("Running ARGUS-X ML Anomaly Detector Test Suite...")
    test_empty_input()
    test_missing_fields_and_malformed_timestamps()
    test_train_save_load_persistence()
    test_supervised_evaluation()
    test_insufficient_training_data_error()
    print("\nALL ANOMALY DETECTOR TESTS PASSED SUCCESSFULLY!")
