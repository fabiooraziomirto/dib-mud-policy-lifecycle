# Score-ranked pooled union at a fixed review budget (derived)

Derived experiment: **no change to the admission pipeline**. It re-scores the
pooled-union queue of `experiments/33_v28_matched_ablation` to test the single
strongest objection to Table `tab:reviewcost`.

```sh
python3 code/scripts/union_ranked_budget.py     # from the repository root
```

## Why

`experiments/36_review_cost/fixed_budget.csv` compares the filtered DIB queue
against pooled union reviewed in **arbitrary order**, because pooled union
defines no ranking. The paper answers the obvious objection — rank the union
queue — by arguing that any ranking is itself an admission filter, i.e. the
mechanism under evaluation. That argument was never measured. This experiment
measures it: it hands the union queue DIB's own admission score as a *ranking*
(threshold, quorum and class gate all removed) and asks how many confirmed
endpoints the top-N entries yield, with N set to that receiver's full-DIB queue
size.

## Validation

`_score_map()` in `code/scripts/union_ranked_budget.py` is the score expression
of `score_keys()` in `code/scripts/moniotr_cross_lab.py` with the accept/reject
decisions removed. The script asserts that re-applying θ=0.65, the two-site
quorum and the class gate to that score map rebuilds the full-DIB candidate set
exactly, for all three receivers. Scores are computed over the source
deployments only; the receiver is excluded, as in `tab:threelab`.

Ties are handled explicitly: the script reports the expected yield under a
uniformly random order *within* each tied score group, plus the best- and
worst-case tie-breakings. At every budget below, expected = best = worst, so no
result here depends on a tie-breaking choice.

## Result — the objection survives

`union_ranked_budget.csv`, budget = full-DIB queue size:

| Receiver | Budget | DIB confirmed | Ranked union | Arbitrary union |
|---|---|---|---|---|
| US | 36 | 35 | 35.0 | 6.6 |
| UK | 43 | 37 | 39.0 | 10.0 |
| YT | 107 | 37 | 40.0 | 3.8 |

**DIB does not beat the score-ranked union at equal budget.** It ties at US and
loses by 2 (UK) and 3 (YT) confirmed endpoints. The equal-budget advantage
reported in `experiments/36_review_cost` holds against an *unranked* union only.

Queue depth the ranked union needs to reach DIB's own confirmed count
(`ranked_union_depth_for_dib_yield`): 36 (US), 41 (UK), 85 (YT), against DIB
queues of 36, 43 and 107. So at equal yield the two queues are also nearly the
same size — +0, +2 and +22 entries for DIB.

## Why a threshold, if a ranking already works

`ranked_prefix_composition.csv` opens the ranked prefix and asks what is
actually in it:

| Receiver | Budget | Admitted by DIB | Fails class gate | Fails quorum | Below theta |
|---|---|---|---|---|---|
| US | 36 | 32 (88.9%) | 4 | 0 | 0 |
| UK | 43 | 39 (90.7%) | 4 | 0 | 0 |
| YT | 107 | 93 (86.9%) | 14 | 0 | 0 |

The ranked prefix is not a different queue: **87--91% of it is exactly what DIB
admits**, and every remaining entry is one the class gate removes. Nothing in
any prefix scores below theta, and nothing is supported by a single deployment.
The ranking's 2--3 extra confirmed endpoints come entirely from class-gate
rejects, not from anything the threshold or the quorum discards.

Two consequences:

- The threshold costs almost no yield here, because at these budgets the
  ranking and the admission rule select nearly the same objects. The quorum in
  particular is redundant *with* the ranking, since breadth carries 60% of the
  score and multi-reporter facts sort to the top on their own.
- A ranking has **no rejection region**. Criterion 1 bounds the score of
  adversary-only evidence below theta; that bound only does work if something
  compares a score against theta. Ranked review has nothing to compare against,
  so an adversary-only fact is not rejected, only sorted --- and whether it is
  inspected depends on where the operator stops. This is the property the
  threshold buys, and it is not visible in any yield-per-entry number.

`ranked_marginal_return.csv` shows the stopping point sits above a real knee:

| Receiver | Confirmed/entry in prefix | In the next equal block | Drop | Whole queue |
|---|---|---|---|---|
| US | 0.97 | 0.69 | 1.4x | 0.18 |
| UK | 0.91 | 0.65 | 1.4x | 0.23 |
| YT | 0.37 | 0.056 | **6.7x** | 0.035 |

Doubling the budget past DIB's cut buys entries worth 1.4x less at US and UK and
6.7x less at YT.

## What this does and does not show

- The **score carries the value**, and it is measured here: ranked by that
  score, the top 36/43/107 union entries confirm 35/39/40 endpoints, against
  6.6/10.0/3.8 in arbitrary order — a 3.9–10.6× concentration.
- The **threshold and class gate add no yield** on top of the ranking. Their
  role is to be a *stopping rule*: they cut the queue at a point the operator
  did not have to choose, landing within 0–22 entries of the smallest ranked
  prefix that achieves the same yield. The class gate is where DIB gives up the
  most (YT: 107 entries for 37 confirmed, against 85 ranked).
- The ranking signal is **DIB's own admission score**. Pooled union does not
  supply it; this row is an upper bound on what a pooled queue could achieve if
  granted the mechanism under evaluation, not a property of pooled union.
- Burden is counted in queue entries, not operator time.
- Six aligned device types only (`label_mapping_v16.csv`); same scope as
  Table `tab:threelab` and `experiments/30_three_lab_loo`.

`ranked_union_curve.csv` extends the comparison to 1×, 2×, 5× the budget and to
queue exhaustion, for readers who want the full operating-point curve.
