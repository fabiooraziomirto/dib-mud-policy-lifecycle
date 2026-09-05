from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# Feature set follows the published traffic-characteristics methodology of
# Sivanathan et al., "Classifying IoT Devices in Smart Environments Using
# Network Traffic Characteristics" (IEEE TMC, 2018), which was developed on
# the same UNSW IoT testbed lineage as this project's primary dataset:
# per-flow packet counts, payload-size statistics, flow duration, and
# inter-arrival-time statistics, deliberately excluding IP/MAC address so the
# classifier cannot trivially memorize device identity rather than behavior.
FEATURE_COLUMNS = (
    "srcNumPackets",
    "dstNumPackets",
    "srcPayloadSize",
    "dstPayloadSize",
    "srcAvgPayloadSize",
    "dstAvgPayloadSize",
    "srcMaxPayloadSize",
    "dstMaxPayloadSize",
    "srcStdDevPayloadSize",
    "dstStdDevPayloadSize",
    "flowDuration",
    "srcAvgInterarrivalTime",
    "dstAvgInterarrivalTime",
    "avgInterarrivalTime",
    "srcStdDevInterarrivalTime",
    "dstStdDevInterarrivalTime",
    "stdDevInterarrivalTime",
    "dstPort",
)


@dataclass(frozen=True, slots=True)
class FlowSample:
    device_type: str
    device_id: str
    timestamp: datetime
    features: tuple[float, ...]


def load_flow_dataset(flows_dir: Path, max_rows_per_file: int | None = None) -> list[FlowSample]:
    """Load per-flow feature vectors directly from raw UNSW IoTraffic flow CSVs.

    Label is the device type encoded in the filename, which is independently
    recorded ground truth from the testbed, not derived from these features.
    """
    samples: list[FlowSample] = []
    for path in sorted(flows_dir.glob("*_flows.csv")):
        stem = path.name.removesuffix("_flows.csv")
        device_type, _, device_id = stem.rpartition("_")
        if not device_type:
            device_type, device_id = stem, stem
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            for index, row in enumerate(reader):
                if max_rows_per_file is not None and index >= max_rows_per_file:
                    break
                features = _extract_features(row)
                if features is None:
                    continue
                samples.append(
                    FlowSample(
                        device_type=device_type,
                        device_id=device_id,
                        timestamp=_parse_time(row["time"]),
                        features=features,
                    )
                )
    return samples


def _extract_features(row: dict[str, str]) -> tuple[float, ...] | None:
    values = []
    for column in FEATURE_COLUMNS:
        raw = row.get(column, "")
        try:
            values.append(float(raw))
        except (TypeError, ValueError):
            return None
    return tuple(values)


def _parse_time(value: str) -> datetime:
    # Must match dib.adapters.unsw_iotraffic.parse_unsw_timestamp's tz-aware UTC output
    # exactly, since callers join FlowSample and Observation records on (device_id,
    # timestamp); a naive/aware mismatch makes every lookup silently fail (`==` on
    # mixed naive/aware datetimes is just always False, no exception).
    return datetime.strptime(value.strip(), "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=timezone.utc)


def chronological_split(
    samples: list[FlowSample], train_fraction: float = 0.7
) -> tuple[list[FlowSample], list[FlowSample]]:
    """Per-device chronological holdout: train on each device's earliest flows,
    test on its later flows. Avoids both random-shuffle leakage and the need
    for a held-out device instance, which this dataset does not have (one
    physical unit per device type).
    """
    if not 0.0 < train_fraction < 1.0:
        raise ValueError("train_fraction must be in (0, 1)")
    by_device: dict[str, list[FlowSample]] = {}
    for sample in samples:
        by_device.setdefault(sample.device_id, []).append(sample)
    train: list[FlowSample] = []
    test: list[FlowSample] = []
    for device_samples in by_device.values():
        ordered = sorted(device_samples, key=lambda s: s.timestamp)
        cut = max(1, int(len(ordered) * train_fraction))
        train.extend(ordered[:cut])
        test.extend(ordered[cut:])
    return train, test


class SklearnFlowClassifier:
    """Adapter exposing the same ``fit``/``predict_batch``/``predict_confidence_batch``
    interface as :class:`GaussianNaiveBayesClassifier`, backed by a scikit-learn
    estimator so the rest of the experiment (DIB feed-through, confusion matrix,
    temporal stability) is reused unchanged.

    Tree ensembles are scale-invariant, so features are fed raw rather than
    standardized; non-finite values (inf/NaN that can arise from zero-duration
    or single-packet flows) are clipped to finite values, since the GNB path
    silently tolerated them via standardization but trees reject them.
    """

    def __init__(self, kind: str = "random_forest", **estimator_kwargs) -> None:
        self.kind = kind
        self.estimator_kwargs = estimator_kwargs
        self.classes_: list[str] = []
        self._estimator = None

    def _build_estimator(self):
        if self.kind == "random_forest":
            from sklearn.ensemble import RandomForestClassifier

            params = dict(n_estimators=100, n_jobs=-1, random_state=42, class_weight="balanced_subsample")
            params.update(self.estimator_kwargs)
            return RandomForestClassifier(**params)
        if self.kind == "gradient_boosting":
            from sklearn.ensemble import HistGradientBoostingClassifier

            params = dict(random_state=42)
            params.update(self.estimator_kwargs)
            return HistGradientBoostingClassifier(**params)
        raise ValueError(f"unknown classifier kind: {self.kind!r}")

    @staticmethod
    def _matrix(samples: list[FlowSample]) -> "np.ndarray":
        import numpy as np

        X = np.asarray([s.features for s in samples], dtype=np.float64)
        # Clip non-finite entries to the float range so tree estimators accept them.
        return np.nan_to_num(X, nan=0.0, posinf=1e12, neginf=-1e12)

    def fit(self, samples: list[FlowSample]) -> "SklearnFlowClassifier":
        import numpy as np

        X = self._matrix(samples)
        y = np.asarray([s.device_type for s in samples])
        self._estimator = self._build_estimator()
        self._estimator.fit(X, y)
        self.classes_ = list(self._estimator.classes_)
        return self

    def predict_batch(self, samples: list[FlowSample]) -> list[str]:
        return [str(label) for label in self._estimator.predict(self._matrix(samples))]

    def predict_confidence_batch(self, samples: list[FlowSample]) -> list[tuple[str, float]]:
        import numpy as np

        probabilities = self._estimator.predict_proba(self._matrix(samples))
        best = np.argmax(probabilities, axis=1)
        classes = self._estimator.classes_
        return [(str(classes[best[i]]), float(probabilities[i, best[i]])) for i in range(len(samples))]

    def predict(self, features: tuple[float, ...]) -> str:
        return self.predict_batch([FlowSample("", "", _EPOCH, features)])[0]

    def predict_confidence(self, features: tuple[float, ...]) -> tuple[str, float]:
        return self.predict_confidence_batch([FlowSample("", "", _EPOCH, features)])[0]


class GaussianNaiveBayesClassifier:
    """Gaussian Naive Bayes, fit/predict over labeled FlowSamples.

    Vectorized with numpy (already an installed transitive dependency of this
    project): the real dataset is several million flows and leave-one-class-out
    evaluation refits the model once per device type, so a pure-Python
    per-row loop is not practical here. The model itself is the textbook
    Gaussian Naive Bayes formulation, not a numerically opaque library call.
    """

    def __init__(self, var_smoothing: float = 1e-9) -> None:
        self.var_smoothing = var_smoothing
        self.classes_: list[str] = []
        self._log_priors: "np.ndarray" = None
        self._means: "np.ndarray" = None  # (n_classes, n_features)
        self._vars: "np.ndarray" = None  # (n_classes, n_features)
        # Feature scale (payload bytes vs. microsecond timers vs. port numbers) spans
        # many orders of magnitude. Without standardizing first, the highest-variance
        # raw feature numerically swamps the per-class Gaussian likelihood and the
        # model collapses to predicting whichever class has the most diffuse variance
        # for everything, regardless of input -- verified empirically: unstandardized
        # fit on the real flow data gave 8% accuracy with one class absorbing nearly
        # every prediction. Standardize using train-set statistics only.
        self._scale_mean: "np.ndarray" = None
        self._scale_std: "np.ndarray" = None

    def _standardize(self, X: "np.ndarray") -> "np.ndarray":
        return (X - self._scale_mean) / self._scale_std

    def fit(self, samples: list[FlowSample]) -> "GaussianNaiveBayesClassifier":
        import numpy as np

        if not samples:
            raise ValueError("cannot fit on an empty sample set")
        raw_X = np.asarray([s.features for s in samples], dtype=np.float64)
        self._scale_mean = raw_X.mean(axis=0)
        self._scale_std = raw_X.std(axis=0)
        self._scale_std[self._scale_std == 0] = 1.0
        X = self._standardize(raw_X)
        y = np.asarray([s.device_type for s in samples])
        self.classes_ = sorted(set(y.tolist()))
        n_classes, n_features = len(self.classes_), X.shape[1]
        means = np.zeros((n_classes, n_features))
        variances = np.zeros((n_classes, n_features))
        priors = np.zeros(n_classes)
        global_var = X.var(axis=0)
        epsilon = self.var_smoothing * max(global_var.max(), 1e-9)
        for index, label in enumerate(self.classes_):
            mask = y == label
            rows = X[mask]
            means[index] = rows.mean(axis=0)
            variances[index] = rows.var(axis=0) + epsilon
            priors[index] = mask.sum() / len(samples)
        self._means = means
        self._vars = variances
        self._log_priors = np.log(priors)
        return self

    def _log_likelihood_matrix(self, X: "np.ndarray") -> "np.ndarray":
        import numpy as np

        # X: (n_samples, n_features) -> result: (n_samples, n_classes)
        result = np.empty((X.shape[0], len(self.classes_)))
        for index in range(len(self.classes_)):
            mean = self._means[index]
            variance = self._vars[index]
            log_prob = -0.5 * np.sum(np.log(2.0 * np.pi * variance))
            log_prob -= 0.5 * np.sum((X - mean) ** 2 / variance, axis=1)
            result[:, index] = log_prob + self._log_priors[index]
        return result

    def predict_batch(self, samples: list[FlowSample]) -> list[str]:
        import numpy as np

        X = self._standardize(np.asarray([s.features for s in samples], dtype=np.float64))
        scores = self._log_likelihood_matrix(X)
        best = np.argmax(scores, axis=1)
        return [self.classes_[index] for index in best]

    def predict(self, features: tuple[float, ...]) -> str:
        return self.predict_batch([FlowSample("", "", _EPOCH, features)])[0]

    def predict_confidence_batch(self, samples: list[FlowSample]) -> list[tuple[str, float]]:
        import numpy as np

        X = self._standardize(np.asarray([s.features for s in samples], dtype=np.float64))
        scores = self._log_likelihood_matrix(X)
        best = np.argmax(scores, axis=1)
        max_scores = scores[np.arange(len(scores)), best]
        confidences = 1.0 / np.sum(np.exp(scores - max_scores[:, None]), axis=1)
        return [(self.classes_[best[i]], float(confidences[i])) for i in range(len(samples))]

    def predict_confidence(self, features: tuple[float, ...]) -> tuple[str, float]:
        return self.predict_confidence_batch([FlowSample("", "", _EPOCH, features)])[0]


def confusion_matrix(samples: list[FlowSample], predictions: list[str], labels: list[str]) -> dict[tuple[str, str], int]:
    matrix: dict[tuple[str, str], int] = {(a, b): 0 for a in labels for b in labels}
    for sample, predicted in zip(samples, predictions):
        key = (sample.device_type, predicted)
        if key in matrix:
            matrix[key] += 1
    return matrix


def classification_report(samples: list[FlowSample], predictions: list[str], labels: list[str]) -> list[dict[str, object]]:
    rows = []
    for label in labels:
        tp = sum(1 for s, p in zip(samples, predictions) if s.device_type == label and p == label)
        fp = sum(1 for s, p in zip(samples, predictions) if s.device_type != label and p == label)
        fn = sum(1 for s, p in zip(samples, predictions) if s.device_type == label and p != label)
        support = sum(1 for s in samples if s.device_type == label)
        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        rows.append(
            {
                "device_type": label,
                "support": support,
                "precision": round(precision, 6),
                "recall": round(recall, 6),
                "f1": round(f1, 6),
            }
        )
    return rows


def temporal_stability(samples: list[FlowSample], predictions: list[str]) -> list[dict[str, object]]:
    """Fraction of consecutive same-device predictions that flip label, ordered
    by time. Ground truth never flips by construction (one label per device);
    a high flip rate means the registry key derived from this classifier would
    be unstable even though the device itself did not change.
    """
    by_device: dict[str, list[tuple[datetime, str]]] = {}
    for sample, predicted in zip(samples, predictions):
        by_device.setdefault(sample.device_id, []).append((sample.timestamp, predicted))
    rows = []
    for device_id, items in sorted(by_device.items()):
        ordered = [label for _, label in sorted(items, key=lambda pair: pair[0])]
        if len(ordered) < 2:
            flip_rate = 0.0
        else:
            flips = sum(1 for a, b in zip(ordered, ordered[1:]) if a != b)
            flip_rate = flips / (len(ordered) - 1)
        rows.append({"device_id": device_id, "flow_count": len(ordered), "flip_rate": round(flip_rate, 6)})
    return rows


def leave_one_class_out_predictions(
    samples: list[FlowSample], labels: list[str]
) -> list[dict[str, object]]:
    """For each device type, train on every other type and classify its flows
    as a proxy for unknown-device handling. This dataset has no genuine
    unseen-device-type traffic, so this measures confusion/confidence against
    known classes, not true open-set rejection.
    """
    rows = []
    for held_out in labels:
        train_samples = [s for s in samples if s.device_type != held_out]
        test_samples = [s for s in samples if s.device_type == held_out]
        if not train_samples or not test_samples:
            continue
        classifier = GaussianNaiveBayesClassifier().fit(train_samples)
        predicted_labels: dict[str, int] = {}
        confidences = []
        for label, confidence in classifier.predict_confidence_batch(test_samples):
            predicted_labels[label] = predicted_labels.get(label, 0) + 1
            confidences.append(confidence)
        top_label = max(predicted_labels, key=predicted_labels.get)
        rows.append(
            {
                "held_out_device_type": held_out,
                "flow_count": len(test_samples),
                "most_common_misclassification": top_label,
                "most_common_misclassification_share": round(predicted_labels[top_label] / len(test_samples), 6),
                "mean_confidence": round(sum(confidences) / len(confidences), 6),
            }
        )
    return rows
