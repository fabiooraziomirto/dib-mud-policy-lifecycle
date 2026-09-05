# Review cost of candidate queues (derived)

Derived experiment: **no new pipeline run**. It re-aggregates
`experiments/33_v28_matched_ablation/per_device.csv` (the matched
three-deployment cold-start ablation behind Table `tab:threelab`) to express the
same four filter configurations as an *operator cost* rather than only as a
candidate count.

```sh
python3 code/scripts/review_cost_curve.py     # from the repository root
```

## Why

The paper reports raw candidate counts and macro agreement F1. Raw counts are
declared a review-burden proxy, but they are never converted into a cost, so
the reduction has no stated benefit. Macro F1 alone makes pooled union look
preferable for two of three receivers. Both views omit that the configurations
are *nested subsets of one queue*, which lets the same numbers be read as an
operating-point curve: how many queue entries an operator inspects, and how
many receiver-observed endpoints that inspection confirms.

## Definitions

- `confirmed` = `matched` in `per_device.csv`: candidates that agree with an
  endpoint the receiver actually observed. Traffic agreement, **not** benignity
  and not functional necessity.
- `micro_precision` = sum(matched)/sum(candidates) over the six aligned device
  types (macro values in `tab:threelab` average per device instead).
- `reviews_per_confirmed` = sum(candidates)/sum(matched): queue entries an
  operator inspects per confirmed endpoint.
- `extra_reviews_per_extra_confirmed` = (N_stage - N_DIB)/(M_stage - M_DIB):
  marginal review cost of each additional confirmed endpoint that a weaker
  filter recovers relative to full DIB.
- `expected_confirmed_at_budget`: yield when only `budget` entries can be
  reviewed. The budget is set to that receiver's full-DIB queue size, so every
  configuration is compared at equal operator effort.

## Results

Review cost per confirmed endpoint (`review_cost.csv`):

| Receiver | union | Q | QS | DIB |
|---|---|---|---|---|
| US | 5.46 | 1.02 | 1.03 | 1.03 |
| UK | 4.31 | 1.17 | 1.17 | 1.16 |
| YT | 28.31 | 4.32 | 3.56 | 2.89 |

Equal-budget yield (`fixed_budget.csv`), budget = full-DIB queue size:

| Receiver | Budget | union | Q | QS | DIB |
|---|---|---|---|---|---|
| US | 36 | 6.6 | 35.1 | 35.1 | 35.0 |
| UK | 43 | 10.0 | 36.7 | 36.7 | 37.0 |
| YT | 107 | 3.8 | 24.8 | 30.0 | 37.0 |

Marginal cost of pooled union over full DIB (`marginal_cost.csv`): 6.5 (US),
5.1 (UK), 106.7 (YT) extra queue entries per extra confirmed endpoint.

## Honest scope

- Burden is counted in **queue entries**, not operator minutes. No user study
  is performed; per-entry review time is assumed uniform and is not measured.
- The union row of `fixed_budget.csv` assumes an **arbitrary (uniformly random)
  review order**. Pooled union defines no ranking; any ranking an operator
  imposes is itself an admission filter, which is the object under test. A
  deployment that ranked union by an oracle would do better than this row.
- Six aligned device types only, the same scope and limitation as
  `tab:threelab` and `experiments/30_three_lab_loo`.
- Between quorum-only and full DIB the equal-budget yields are close for US
  (35.1 vs 35.0) and UK (36.7 vs 37.0); the separation appears only at YT
  (24.8 vs 37.0). This is consistent with, and does not overturn, the paper's
  statement that quorum supplies most of the reduction.
