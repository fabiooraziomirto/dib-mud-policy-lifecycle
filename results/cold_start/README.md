# 20-seed CI for the day-0-DIB-vs-30-day-local-only comparison (v16 revision)

Extends `24_cold_start_detail` (single seed=42) to the same 20-seed
convention (seeds 0-19, `exclude_non_global_ips`, `site_count=10`,
`partition_strategy=random`) used by `ablation_multiseed.py` and
`cold_start_multiseed.py` elsewhere in the paper. Computed by
`code/scripts/cold_start_local_vs_registry_multiseed.py`, which reuses
`cold_start_rows()` unmodified.

## Result

| Quantity | Mean | Std |
|---|---|---|
| DIB day-0 macro F1 | 0.112 | 0.002 |
| Local-only 30-day macro F1 | 0.022 | 0.005 |
| DIB day-0 + 30-day local macro F1 | 0.114 | 0.002 |
| Per-seed ratio (DIB day-0 / local-only 30-day) | 5.46 | 1.54 |

Ratio of means: 0.112 / 0.022 ~= 5.1x. The per-seed ratio's mean (5.46) is
higher and noisier than the ratio of means because 30-day local-only F1
varies much more across partitions (std/mean ~23%) than DIB's day-0 seed
does (std/mean ~2%) -- a partition with an unusually low local-only
denominator inflates that seed's ratio (e.g. seed 16: local-only F1
0.0109, ratio 10.4). The paper reports the ratio of means as the primary
number and notes the per-seed ratio's spread as a caveat.

The original single-seed (42) point estimate is not directly one of these
20 seeds (this script uses seeds 0-19), but is consistent with the
distribution: `24_cold_start_detail`'s seed=42 values (day-0 F1 ~0.114,
30-day local-only F1 ~0.025) fall well within the range observed here.

## How to reproduce

```bash
python3 code/scripts/cold_start_local_vs_registry_multiseed.py \
  --observations /path/to/observations_enriched.csv \
  --ground-truth-dir /path/to/unsw/profiles/normalized \
  --output-dir outputs/cold_start_local_vs_registry_multiseed
```
