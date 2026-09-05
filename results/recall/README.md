# Experiment 21 — Reference-coverage funnel

Closes the reviewer TODOs on `main_v5.0.tex:100`, `:546` and `:550`: the recall
funnel in Table `tab:recall-funnel` previously had **no generating script**, so
its "observed in the capture" (12.5%) and "staged by DIB" (7.8%) rows could not
be reproduced or audited.

## Command

```bash
cd reproducibility/code
python3 scripts/recall_funnel.py
```

Runtime 82 s, peak RSS 1.66 GiB (no graph term: the selected configuration has
`graph_enabled: false`, so the `O(E^2)` co-occurrence graph that OOM-killed
Experiment 11 is never built).

## Result

| Stage | Scope | ACEs | Micro | Macro |
|---|---|---|---|---|
| All reference ACEs | reference | 564/564 | 100.0% | 100.0% |
| Direction compatible with from-device adapters | reference | 503/564 | 89.18% | 83.39% |
| Endpoint class eligible for staging | reference | 559/564 | 99.11% | 99.41% |
| Observed in the capture (before address filtering) | capture | 77/564 | 13.65% | 18.75% |
| Observed in the capture (after `--exclude-non-global-ips`) | capture | 55/564 | 9.75% | **12.45%** |
| Staged by DIB at the frozen operating point | pipeline | 36/564 | 6.38% | **7.86%** |
| Same, with strict (non-wildcard) matching | pipeline | 36/564 | 6.38% | 7.86% |

Retained share of the capture-observable ceiling: **63.1% macro**
(7.86/12.45), 65.5% micro.

## Wildcard-matching sensitivity (TODO `main_v5.0.tex:458`)

150 of the 564 reference ACEs carry port 0 or protocol `unknown`, which the
ground-truth matcher treats as wildcards. Re-scoring the staged set with a
strict matcher — such an ACE matches only a prediction with the identical
literal port and protocol — yields **exactly the same 36 matched ACEs**. None
of the reported overlap depends on wildcard expansion, so the concern that it
"can materially inflate overlap" does not apply to these results.

## What this settles

1. **The published 12.5% and 7.8% are macro figures** and are reproduced here
   (12.4485% and 7.8633%). They were never micro shares, which is why they
   could not be reconciled against pooled counts. The caption's
   "macro-averaged" claim is correct for these two rows.
2. **The 89.2% direction row is micro, not macro.** The macro equivalent is
   83.4%. A single table cannot be labelled macro throughout while mixing the
   two, so `main_v5.1.tex` reports both columns.
3. **The published 62.4% ratio is slightly stale**: the measured value is
   **63.1%**.
4. **The published "99.8% of reference ACEs are class-eligible" is not
   reproduced**: the measured value is 99.4% macro / 99.1% micro (5 of 564 ACEs
   fall in the residual `other` class). Class breakdown of the reference:
   `vendor-cloud` 476, `ntp` 38, `dns` 37, `update` 8, `other` 5.
5. **"Direction compatible with from-device adapters" is now operationally
   defined**: an ACE counts if it lives under a `from-device-policy` ACL
   container (`profiles._acl_direction_map`). Every shipped adapter emits
   device-initiated flows only (`profiles.PREDICTED_DIRECTION`), so the 61
   `to-device` ACEs are structurally unreachable rather than merely unobserved.
6. The address-scope filter itself costs 22 reference ACEs (77 → 55 micro),
   which the previous funnel did not disclose at all.

`recall_funnel_by_device.csv` gives the per-device breakdown. `chromecast-ultra`
is the reference profile with **no observations at all** (105 of the 564 ACEs,
18.6% of the denominator) and contributes an exact zero to every macro stage.

## Provenance

`manifest.json` records `input_sha256` of `observations_enriched.csv`, the
frozen operating point (0.6, 0.4, 0.0, θ=0.65, m=2, trust-weighted), seed 42,
site count 10, and the pipeline order. The accepted-fact count (349) matches
the Table II reference-seed row in
`16_combined_bugfix_rerun/03_table2_multiseed/raw_per_seed.csv`.
