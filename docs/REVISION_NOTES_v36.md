# v36.0 release note

This local pre-submission artifact accompanies `paper/main.pdf` (v36.0). It
preserves the v31 material under its original paths and adds the evidence used
by the v36 paper revision.

## Added evidence

- `results/restore_ablation/results.json`: 18 deterministic sequential API
  cases (three restoration policies × three veto timings × delivered/offline
  peer). The policy adapters are explicitly experimental and are not claims
  about any cited system.
- `results/lifecycle_v35/api_campaign.json`: the two suspension thresholds.
- `results/lifecycle_v35/regression.log`: current focused registry and
  rescoring tests.
- Current TLA+ models/logs and six current mutation controls.
- `results/dispute_flood/dispute_flood_summary.json`: availability measurement
  reported separately from the in-process campaigns.
- `docs/RELATED_WORK_SCOPE.md`: source-checked positioning boundaries.

## Consistency checks

`python3 scripts/verify_artifact.py` runs 166 assertions over indexed evidence.
The result file stores SHA-256 values of the exact distributed service and
ablation script packaged here; the verifier recomputes them. The full unit
suite is optional via `--with-tests`.

The paper PDF remains 10 pages and keeps all seven biography/photo blocks.
Author names, biographical content, photos, DOI and repository archival URL
remain intentionally unresolved submission metadata; fill them only in the
final authoring/submission workflow and recompile the paper afterward.
