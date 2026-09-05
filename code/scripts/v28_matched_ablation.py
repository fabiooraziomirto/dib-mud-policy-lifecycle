"""Matched raw-breadth ablation using the existing three-site evaluator.

Run from the repository root. Outputs are separate from the v27 artifact.
"""
from pathlib import Path
import csv
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from moniotr_cross_lab import (
    collapse_site_three, load, load_label_mapping, score_keys,
    per_device_metrics, set_metrics, mean, write_csv, sha256,
)


def main():
    root = Path(__file__).resolve().parents[2]
    inputs = [root / "code/data/processed/moniotr_full_observations.csv",
              root / "code/data/processed/yourthings_observations.csv"]
    mapping = root / "experiments/30_three_lab_loo/label_mapping_v16.csv"
    out = root / "experiments/33_v28_matched_ablation"
    out.mkdir(parents=True, exist_ok=True)
    data = load(inputs[0], extra_paths=inputs[1:], collapse_fn=collapse_site_three,
                label_map=load_label_mapping(mapping))
    rows, detail = [], []
    sites = ("US", "UK", "YT")
    with (root / "experiments/30_three_lab_loo/leave_one_out_three_lab.csv").open() as f:
        reference = {r["receiving_deployment"]: r for r in csv.DictReader(f)}
    for receiver in sites:
        sources = set(sites) - {receiver}
        devices, locked, locked_metrics = per_device_metrics(data, sites, receiver)
        assert len(devices) == 6
        source_union = {k for k, reporters in data.endpoints.items()
                        if k[0] in devices and reporters & sources}
        quorum = {k for k in source_union if len(data.endpoints[k] & sources) >= 2}
        scored, _ = score_keys(data, sources, gate=False, quorum=True)
        stages = {"union": source_union, "quorum": quorum,
                  "quorum_score": scored & source_union, "DIB": locked}
        assert locked <= stages["quorum_score"] <= quorum <= source_union
        assert len(locked) == int(reference[receiver]["admitted_candidates"])
        for metric in ("precision", "recall", "f1"):
            assert abs(mean(locked_metrics, metric) - float(reference[receiver][metric + "_macro"])) < 1e-12
        # Receiver observations affect only evaluation, not source scoring.
        source_data = load(inputs[0], extra_paths=inputs[1:],
            collapse_fn=lambda site: (lambda s: s if s in sources else None)(collapse_site_three(site)),
            label_map=load_label_mapping(mapping))
        source_only, _ = score_keys(source_data, sources, gate=True, quorum=True)
        assert locked == {k for k in source_only if k[0] in devices}
        for stage, candidates in stages.items():
            metrics = []
            for device in devices:
                predicted = {k for k in candidates if k[0] == device}
                observed = data.profiles[receiver][device]
                metric = set_metrics(predicted, observed)
                metrics.append(metric)
                detail.append(dict(receiver=receiver, stage=stage, device=device,
                    candidates=len(predicted), reference=len(observed),
                    matched=len(predicted & observed), **metric))
            rows.append(dict(receiver=receiver, sources="+".join(sorted(sources)), stage=stage,
                candidates=len(candidates), reduction=1-len(candidates)/len(source_union),
                coverage=sum(any(k[0] == d for k in candidates) for d in devices)/len(devices),
                precision=mean(metrics,"precision"), recall=mean(metrics,"recall"), f1=mean(metrics,"f1")))
    write_csv(out / "matched_ablation.csv", rows)
    write_csv(out / "per_device.csv", detail)
    files = inputs + [mapping, Path(__file__), Path(__file__).with_name("moniotr_cross_lab.py")]
    (out / "manifest.json").write_text(json.dumps(dict(
        command="python code/scripts/v28_matched_ablation.py", scoring="raw breadth",
        parameters=dict(alpha=.6, beta=.4, theta=.65, quorum=2),
        scope="same six aligned device types for every stage; receiving site excluded from evidence",
        metrics="macro per-device agreement with receiver-observed endpoints; not benignity",
        validations=["exact reproduction of three published receiver rows", "nested candidate sets",
                     "receiver-deletion invariance of full DIB candidates"],
        sha256={str(p.relative_to(root)): sha256(p) for p in files}), indent=2) + "\n")
    for row in rows:
        print(row, flush=True)


if __name__ == "__main__":
    main()
