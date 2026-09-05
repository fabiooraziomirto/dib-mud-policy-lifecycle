from __future__ import annotations

import random
from dataclasses import dataclass
from math import sqrt

import math

from scipy import stats
from scipy.optimize import brentq


def _two_tailed_power(t_crit: float, df: int, ncp: float) -> float:
    """P(|T| > t_crit) under noncentral t(df, ncp). scipy's nct.cdf underflows to NaN for
    the (negligible) lower tail at large |ncp|; treat that contribution as 0 rather than
    propagating NaN.
    """
    lower = stats.nct.cdf(-t_crit, df, ncp)
    upper = stats.nct.sf(t_crit, df, ncp)
    if math.isnan(lower):
        lower = 0.0
    if math.isnan(upper):
        upper = 0.0
    return float(lower + upper)


@dataclass(frozen=True, slots=True)
class PairedComparison:
    method_a: str
    method_b: str
    n: int
    mean_diff: float
    t_statistic: float
    t_pvalue: float
    wilcoxon_statistic: float
    wilcoxon_pvalue: float
    cohens_d: float
    ci_low: float
    ci_high: float

    def to_dict(self) -> dict[str, object]:
        return {
            "method_a": self.method_a,
            "method_b": self.method_b,
            "n": self.n,
            "mean_diff": round(self.mean_diff, 6),
            "t_statistic": round(self.t_statistic, 6),
            "t_pvalue": round(self.t_pvalue, 6),
            "wilcoxon_statistic": round(self.wilcoxon_statistic, 6),
            "wilcoxon_pvalue": round(self.wilcoxon_pvalue, 6),
            "cohens_d": round(self.cohens_d, 6),
            "ci_95_low": round(self.ci_low, 6),
            "ci_95_high": round(self.ci_high, 6),
        }


def confidence_interval(values: list[float], confidence: float = 0.95) -> tuple[float, float]:
    n = len(values)
    if n < 2:
        return (0.0, 0.0)
    mean = sum(values) / n
    variance = sum((v - mean) ** 2 for v in values) / (n - 1)
    std_err = sqrt(variance / n)
    t_crit = stats.t.ppf((1 + confidence) / 2, df=n - 1)
    margin = t_crit * std_err
    return (mean - margin, mean + margin)


def cohens_d_paired(a: list[float], b: list[float]) -> float:
    diffs = [x - y for x, y in zip(a, b)]
    n = len(diffs)
    if n < 2:
        return 0.0
    mean = sum(diffs) / n
    variance = sum((d - mean) ** 2 for d in diffs) / (n - 1)
    std = sqrt(variance)
    return mean / std if std > 0 else 0.0


def holm_bonferroni(pvalues: list[float]) -> list[float]:
    """Holm step-down adjustment. Controls family-wise error rate at least as
    tightly as plain Bonferroni while being uniformly more powerful.

    Returns adjusted p-values in the same order as the input.
    """
    m = len(pvalues)
    if m == 0:
        return []
    order = sorted(range(m), key=lambda i: pvalues[i])
    adjusted = [0.0] * m
    running_max = 0.0
    for rank, idx in enumerate(order):
        candidate = (m - rank) * pvalues[idx]
        running_max = max(running_max, candidate)
        adjusted[idx] = min(running_max, 1.0)
    return adjusted


def bootstrap_ci_diff(
    values_a: list[float],
    values_b: list[float],
    confidence: float = 0.95,
    n_resamples: int = 10000,
    seed: int = 0,
) -> tuple[float, float]:
    """Percentile bootstrap CI on the paired mean difference (a - b).

    Resamples pairs (not a and b independently) with replacement, since the
    per-device F1 values are paired observations.
    """
    diffs = [a - b for a, b in zip(values_a, values_b)]
    n = len(diffs)
    if n < 2:
        return (0.0, 0.0)
    rng = random.Random(seed)
    means = []
    for _ in range(n_resamples):
        sample = [diffs[rng.randrange(n)] for _ in range(n)]
        means.append(sum(sample) / n)
    means.sort()
    alpha = 1 - confidence
    lo_idx = int((alpha / 2) * n_resamples)
    hi_idx = int((1 - alpha / 2) * n_resamples) - 1
    return (means[max(lo_idx, 0)], means[min(hi_idx, n_resamples - 1)])


def observed_power(values_a: list[float], values_b: list[float], alpha: float = 0.05) -> float:
    """Post-hoc power of the paired two-tailed t-test for the effect actually measured
    (the observed mean difference and its sample standard deviation), via the noncentral
    t distribution rather than a normal approximation.
    """
    diffs = [a - b for a, b in zip(values_a, values_b)]
    n = len(diffs)
    if n < 2:
        return 0.0
    mean = sum(diffs) / n
    variance = sum((d - mean) ** 2 for d in diffs) / (n - 1)
    std = sqrt(variance)
    if std == 0:
        return 1.0 if mean != 0 else 0.0
    df = n - 1
    ncp = mean / (std / sqrt(n))
    t_crit = stats.t.ppf(1 - alpha / 2, df)
    return _two_tailed_power(t_crit, df, ncp)


def minimum_detectable_effect(n: int, std: float, alpha: float = 0.05, power: float = 0.8) -> float:
    """Smallest paired mean difference that a two-tailed t-test with the given sample size
    `n`, standard deviation of paired differences `std`, and significance level `alpha`
    would detect with the target `power`. Solved against the noncentral t distribution
    (no normal approximation), since n is small (28 device types in the UNSW comparison).
    """
    if n < 2 or std <= 0:
        return 0.0
    df = n - 1
    t_crit = stats.t.ppf(1 - alpha / 2, df)

    def power_at(delta: float) -> float:
        ncp = delta / (std / sqrt(n))
        return _two_tailed_power(t_crit, df, ncp)

    lo, hi = 0.0, 10.0 * std
    for _ in range(50):
        if power_at(hi) >= power:
            break
        hi *= 2
    return float(brentq(lambda delta: power_at(delta) - power, lo, hi))


def compare_paired(method_a: str, values_a: list[float], method_b: str, values_b: list[float]) -> PairedComparison:
    """Paired t-test (when assumptions hold) with Wilcoxon signed-rank as a non-parametric fallback."""
    if len(values_a) != len(values_b):
        raise ValueError("paired comparison requires equal-length aligned samples")
    n = len(values_a)
    diffs = [a - b for a, b in zip(values_a, values_b)]
    mean_diff = sum(diffs) / n if n else 0.0
    if n >= 2 and any(d != diffs[0] for d in diffs):
        t_stat, t_p = stats.ttest_rel(values_a, values_b)
        try:
            w_stat, w_p = stats.wilcoxon(values_a, values_b)
        except ValueError:
            w_stat, w_p = 0.0, 1.0
    else:
        t_stat, t_p = 0.0, 1.0
        w_stat, w_p = 0.0, 1.0
    ci_low, ci_high = confidence_interval(diffs)
    return PairedComparison(
        method_a=method_a,
        method_b=method_b,
        n=n,
        mean_diff=mean_diff,
        t_statistic=float(t_stat),
        t_pvalue=float(t_p),
        wilcoxon_statistic=float(w_stat),
        wilcoxon_pvalue=float(w_p),
        cohens_d=cohens_d_paired(values_a, values_b),
        ci_low=ci_low,
        ci_high=ci_high,
    )
