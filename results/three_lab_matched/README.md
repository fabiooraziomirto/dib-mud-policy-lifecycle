# Matched cold-start ablation for v28

Run from the repository root:

```sh
python code/scripts/v28_matched_ablation.py
```

The script reuses `moniotr_cross_lab.py` to load the same Mon(IoT)r and
YourThings inputs and the fixed six-device label mapping from experiment 30.
It evaluates union, two-source quorum, quorum plus score, and full DIB on
exactly the same six device types and source/receiver splits. The receiver is
excluded from all source evidence. Scoring uses raw breadth, not trust weights.
No parameters or label mappings were tuned for this comparison.

`matched_ablation.csv` reports candidate counts, reduction relative to union,
device coverage, and macro precision/recall/F1. `per_device.csv` contains the
matched and reference counts behind those metrics. Agreement is measured
against receiver-observed endpoints; it is not a benignity or functionality
label. Empty predictions contribute zero precision/recall/F1, consistently
with the original evaluator.

Validation performed by the script:

- full DIB reproduces the three original candidate counts and all macro metrics;
- candidate sets are nested across the four filters;
- reloading each source pair with the receiver physically excluded reproduces
  the full DIB candidates (not just excluding it from the final metric).

The manifest records hashes of inputs, mapping, script and reused evaluator.
The input hashes match experiment 30. The comparison supports a smaller queue
at a coverage cost, not uniform superiority: quorum supplies most of the
reduction, the class gate lowers recall for all receivers, and full DIB does
not maximize agreement F1.
