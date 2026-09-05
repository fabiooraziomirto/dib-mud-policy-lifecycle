from __future__ import annotations


def precision(predicted: set[object], truth: set[object]) -> float:
    if not predicted:
        return 0.0
    return len(predicted & truth) / len(predicted)


def recall(predicted: set[object], truth: set[object]) -> float:
    if not truth:
        return 0.0
    return len(predicted & truth) / len(truth)


def f1_score(predicted: set[object], truth: set[object]) -> float:
    p = precision(predicted, truth)
    r = recall(predicted, truth)
    if p + r == 0:
        return 0.0
    return 2 * p * r / (p + r)


def jaccard(predicted: set[object], truth: set[object]) -> float:
    union = predicted | truth
    if not union:
        return 1.0
    return len(predicted & truth) / len(union)
