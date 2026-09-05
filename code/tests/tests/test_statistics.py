from __future__ import annotations

from dib.evaluation.statistics import (
    bootstrap_ci_diff,
    compare_paired,
    holm_bonferroni,
    minimum_detectable_effect,
    observed_power,
)


def test_holm_bonferroni_matches_bonferroni_on_smallest_pvalue() -> None:
    pvalues = [0.01, 0.04, 0.03, 0.20]
    adjusted = holm_bonferroni(pvalues)
    # smallest p-value gets multiplied by m (same as plain Bonferroni)
    assert adjusted[0] == 0.04


def test_holm_bonferroni_is_monotonic_and_bounded() -> None:
    pvalues = [0.001, 0.01, 0.02, 0.03, 0.5]
    adjusted = holm_bonferroni(pvalues)
    assert all(0.0 <= p <= 1.0 for p in adjusted)
    # Holm-adjusted p-values for sorted inputs must be non-decreasing
    sorted_adjusted = [adjusted[i] for i in sorted(range(len(pvalues)), key=lambda i: pvalues[i])]
    assert sorted_adjusted == sorted(sorted_adjusted)


def test_holm_bonferroni_empty() -> None:
    assert holm_bonferroni([]) == []


def test_holm_bonferroni_single_value_equals_itself() -> None:
    assert holm_bonferroni([0.03]) == [0.03]


def test_bootstrap_ci_diff_contains_observed_mean_diff() -> None:
    a = [0.5, 0.6, 0.4, 0.55, 0.45]
    b = [0.3, 0.35, 0.25, 0.4, 0.3]
    lo, hi = bootstrap_ci_diff(a, b, n_resamples=2000, seed=1)
    observed_mean_diff = sum(x - y for x, y in zip(a, b)) / len(a)
    assert lo <= observed_mean_diff <= hi


def test_bootstrap_ci_diff_is_deterministic_given_seed() -> None:
    a = [0.5, 0.6, 0.4, 0.55, 0.45]
    b = [0.3, 0.35, 0.25, 0.4, 0.3]
    first = bootstrap_ci_diff(a, b, n_resamples=1000, seed=42)
    second = bootstrap_ci_diff(a, b, n_resamples=1000, seed=42)
    assert first == second


def test_bootstrap_ci_diff_degenerate_n_below_two() -> None:
    assert bootstrap_ci_diff([0.5], [0.3]) == (0.0, 0.0)


def test_compare_paired_identical_samples_gives_zero_diff_and_pvalue_one() -> None:
    values = [0.1, 0.2, 0.3, 0.4]
    comparison = compare_paired("a", values, "b", values)
    assert comparison.mean_diff == 0.0
    assert comparison.t_pvalue == 1.0


def test_compare_paired_rejects_mismatched_lengths() -> None:
    try:
        compare_paired("a", [0.1, 0.2], "b", [0.1])
    except ValueError:
        return
    raise AssertionError("expected ValueError for mismatched lengths")


def test_observed_power_is_low_for_small_noisy_effect() -> None:
    a = [0.3, 0.32, 0.28, 0.35, 0.25, 0.31]
    b = [0.31, 0.3, 0.29, 0.3, 0.32, 0.3]
    power = observed_power(a, b)
    assert 0.0 <= power <= 1.0
    assert power < 0.5


def test_observed_power_is_high_for_large_consistent_effect() -> None:
    a = [0.9, 0.88, 0.91, 0.89, 0.92, 0.87, 0.9, 0.91]
    b = [0.3, 0.31, 0.29, 0.32, 0.28, 0.3, 0.29, 0.31]
    power = observed_power(a, b)
    assert power > 0.95


def test_observed_power_degenerate_n_below_two() -> None:
    assert observed_power([0.5], [0.3]) == 0.0


def test_minimum_detectable_effect_increases_with_noise() -> None:
    low_noise = minimum_detectable_effect(n=28, std=0.05)
    high_noise = minimum_detectable_effect(n=28, std=0.2)
    assert 0.0 < low_noise < high_noise


def test_minimum_detectable_effect_decreases_with_sample_size() -> None:
    small_n = minimum_detectable_effect(n=10, std=0.1)
    large_n = minimum_detectable_effect(n=100, std=0.1)
    assert large_n < small_n


def test_minimum_detectable_effect_degenerate_inputs() -> None:
    assert minimum_detectable_effect(n=1, std=0.1) == 0.0
    assert minimum_detectable_effect(n=28, std=0.0) == 0.0


def test_minimum_detectable_effect_increases_with_target_power() -> None:
    lenient = minimum_detectable_effect(n=28, std=0.1, power=0.5)
    strict = minimum_detectable_effect(n=28, std=0.1, power=0.95)
    assert lenient < strict
