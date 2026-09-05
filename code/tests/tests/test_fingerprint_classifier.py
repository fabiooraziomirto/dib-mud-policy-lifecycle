from __future__ import annotations

from datetime import datetime, timezone

from dib.experiments.fingerprint_classifier import (
    FlowSample,
    GaussianNaiveBayesClassifier,
    chronological_split,
    classification_report,
    confusion_matrix,
    leave_one_class_out_predictions,
    temporal_stability,
)


def _sample(device_type: str, device_id: str, day: int, feature: float) -> FlowSample:
    return FlowSample(
        device_type=device_type,
        device_id=device_id,
        timestamp=datetime(2026, 1, day, tzinfo=timezone.utc),
        features=(feature, feature * 2.0),
    )


def _separable_dataset() -> list[FlowSample]:
    # Two trivially separable clusters: "camera" near (0, 0), "plug" near (100, 200).
    samples = []
    for day in range(1, 11):
        samples.append(_sample("camera", "dev-camera", day, 0.0 + (day % 3) * 0.1))
        samples.append(_sample("plug", "dev-plug", day, 100.0 + (day % 3) * 0.1))
    return samples


def test_chronological_split_keeps_each_device_train_then_test_in_time_order() -> None:
    samples = _separable_dataset()
    train, test = chronological_split(samples, train_fraction=0.7)

    assert len(train) + len(test) == len(samples)
    for device_id in {"dev-camera", "dev-plug"}:
        train_days = [s.timestamp.day for s in train if s.device_id == device_id]
        test_days = [s.timestamp.day for s in test if s.device_id == device_id]
        assert max(train_days) < min(test_days)


def test_gaussian_nb_separates_distinct_clusters() -> None:
    samples = _separable_dataset()
    train, test = chronological_split(samples, train_fraction=0.7)

    classifier = GaussianNaiveBayesClassifier().fit(train)
    predictions = classifier.predict_batch(test)

    assert predictions == [s.device_type for s in test]


def test_predict_single_matches_predict_batch() -> None:
    samples = _separable_dataset()
    classifier = GaussianNaiveBayesClassifier().fit(samples)

    single = classifier.predict((0.05, 0.1))
    batch = classifier.predict_batch([_sample("camera", "dev-camera", 1, 0.05)])

    assert single == batch[0]


def test_predict_confidence_is_between_zero_and_one() -> None:
    samples = _separable_dataset()
    classifier = GaussianNaiveBayesClassifier().fit(samples)

    label, confidence = classifier.predict_confidence((0.05, 0.1))

    assert label == "camera"
    assert 0.0 <= confidence <= 1.0


def test_confusion_matrix_counts_correct_and_incorrect_predictions() -> None:
    samples = [_sample("camera", "dev-camera", 1, 0.0), _sample("plug", "dev-plug", 1, 100.0)]
    predictions = ["camera", "camera"]

    matrix = confusion_matrix(samples, predictions, ["camera", "plug"])

    assert matrix[("camera", "camera")] == 1
    assert matrix[("plug", "camera")] == 1
    assert matrix[("plug", "plug")] == 0


def test_classification_report_computes_precision_recall_f1() -> None:
    samples = [_sample("camera", "dev-camera", 1, 0.0), _sample("plug", "dev-plug", 1, 100.0)]
    predictions = ["camera", "camera"]

    report = {row["device_type"]: row for row in classification_report(samples, predictions, ["camera", "plug"])}

    assert report["camera"]["precision"] == 0.5
    assert report["camera"]["recall"] == 1.0
    assert report["plug"]["recall"] == 0.0


def test_temporal_stability_reports_zero_flip_rate_for_constant_predictions() -> None:
    samples = [_sample("camera", "dev-camera", day, 0.0) for day in range(1, 5)]
    predictions = ["camera"] * 4

    rows = temporal_stability(samples, predictions)

    assert rows == [{"device_id": "dev-camera", "flow_count": 4, "flip_rate": 0.0}]


def test_temporal_stability_detects_flips() -> None:
    samples = [_sample("camera", "dev-camera", day, 0.0) for day in range(1, 5)]
    predictions = ["camera", "plug", "camera", "plug"]

    rows = temporal_stability(samples, predictions)

    assert rows[0]["flip_rate"] == 1.0


def test_leave_one_class_out_reports_a_misclassification_for_the_held_out_class() -> None:
    samples = _separable_dataset()
    labels = sorted({s.device_type for s in samples})

    rows = leave_one_class_out_predictions(samples, labels)

    by_label = {row["held_out_device_type"]: row for row in rows}
    assert set(by_label) == set(labels)
    for row in by_label.values():
        assert row["most_common_misclassification"] in labels
        assert row["flow_count"] > 0
        assert 0.0 <= row["mean_confidence"] <= 1.0
