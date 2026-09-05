# Site-count × quorum sensitivity

`site_quorum_sensitivity.csv` crosses pseudo-site count `N={2,3,5,10}`
with feasible quorum values `m={1,2,3,5}` at seed 42, using the selected
graph-free configuration. The same frozen endpoint scores are thresholded for
each `m`, because quorum affects only the final admission predicate.

Regeneration requires the separately licensed UNSW observations and references:

```bash
python code/scripts/site_quorum_sensitivity.py \
  --observations /path/to/observations_enriched.csv \
  --ground-truth-dir /path/to/profiles/normalized
```

The rows characterize sensitivity to experimental partitions. They do not
establish transfer among independently administered sites.
