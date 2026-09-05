# Clustering-threshold (Jaccard) sensitivity (v16 revision)

The paper's independence-aware clustering mitigation (Sec. IV-C) merges
sites into one effective source when their endpoint-set Jaccard similarity
is at least 0.8 -- a design choice, not a derived constant. This sweeps
that threshold over `{0.6, 0.7, 0.8, 0.9, 0.95}`, crossed with the same
diversified-Sybil padding grid (`0, 0.1, 0.25, 0.5` of the real endpoint
pool) already used for the extreme cell (3,200 identities, 400 days,
AugustDoorBell) in `28_sybil_padding_gridpoints/AugustDoorBell_extreme`.
Reuses `code/scripts/sybil_padding_sweep.py`, extended in this revision
with a `--thresholds` argument that crosses padding fractions with
similarity thresholds instead of using the single locked value.

## Result

| Padding | 0.6 | 0.7 | 0.8 (locked) | 0.9 | 0.95 |
|---|---|---|---|---|---|
| 0 (undiversified) | reject (0.455) | reject (0.390) | reject (0.390) | reject (0.390) | reject (0.390) |
| 0.1 (2 endpoints) | **admit (0.922)** | **admit (0.905)** | **admit (0.905)** | **admit (0.905)** | **admit (0.905)** |
| 0.25 (5 endpoints) | reject (0.454) | reject (0.389) | **admit (0.932)** | **admit (0.932)** | **admit (0.932)** |
| 0.5 (10 endpoints) | reject (0.454) | **admit (0.926)** | **admit (0.926)** | **admit (0.932)** | **admit (0.932)** |

("admit"/"reject" = whether the fabricated endpoint clears theta=0.65 under
independence-aware clustering; score in parentheses.)

## Interpretation

No single threshold in `[0.6, 0.95]` resists the fabrication at every
tested padding level: 0.6-0.7 fail only at padding 0.1, while the locked
0.8 (and 0.9, 0.95) fail at padding 0.1, 0.25, *and* 0.5 -- three out of
four tested padding levels. At padding 0, threshold choice is immaterial
(identical Sybils always cluster into one component regardless). This is
independent evidence, alongside the closed-form argument in Sec. IV-C,
that Criterion 1's guarantee does not transfer to the clustering variant:
the clustering threshold cannot be tuned to a single safe value from this
grid, and it is DIB's non-escalation property -- not the score -- that
keeps a defeated threshold from becoming enforced access rather than a
false review candidate.

## How to reproduce

```bash
python3 code/scripts/sybil_padding_sweep.py \
  --observations /path/to/observations_enriched.csv \
  --calibration-observations experiments/16_combined_bugfix_rerun/governance_bootstrap/calibration_observations.csv \
  --config configs/graph_free_selected.yaml \
  --seed 42 --site-count 10 --sybil-count 3200 --spread-days 400 \
  --target-device-type AugustDoorBell \
  --padding-fractions 0,0.1,0.25,0.5 \
  --thresholds 0.6,0.7,0.8,0.9,0.95 \
  --output-dir outputs/jaccard_threshold_sensitivity
```
