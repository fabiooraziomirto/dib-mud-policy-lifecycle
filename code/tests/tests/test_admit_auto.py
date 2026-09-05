from __future__ import annotations

from dib.evaluation.dib import admit_auto


def test_eligible_class_above_theta_is_admitted() -> None:
    assert admit_auto(score=0.70, theta=0.65, endpoint_class="update") is True


def test_eligible_class_below_theta_is_not_admitted() -> None:
    assert admit_auto(score=0.50, theta=0.65, endpoint_class="vendor-cloud") is False


def test_ineligible_class_above_theta_is_not_admitted() -> None:
    # The case that did not exist before Fase 2.3(a): dib.py used to admit this.
    assert admit_auto(score=0.90, theta=0.65, endpoint_class="other") is False


def test_open_dispute_blocks_admission_even_if_eligible_and_above_theta() -> None:
    assert admit_auto(score=0.90, theta=0.65, endpoint_class="dns", open_dispute=True) is False
