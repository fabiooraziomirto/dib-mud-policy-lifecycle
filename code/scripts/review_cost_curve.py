"""Review-cost derivation for the matched three-deployment cold-start ablation.

Derives, per receiver and per admission stage, the operator-side cost of a
candidate queue: micro precision, candidates reviewed per confirmed endpoint,
the marginal review cost of each additional confirmed endpoint recovered by a
weaker filter, and the yield of a fixed review budget.

Input:  experiments/33_v28_matched_ablation/per_device.csv  (not regenerated here)
Output: experiments/36_review_cost/{review_cost.csv,marginal_cost.csv,
        fixed_budget.csv,manifest.json}

Run from the repository root:  python3 code/scripts/review_cost_curve.py
"""
from pathlib import Path
import csv
import hashlib
import json

STAGES = ("union", "quorum", "quorum_score", "DIB")
RECEIVERS = ("US", "UK", "YT")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def write_csv(path, fieldnames, rows):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def main():
    root = Path(__file__).resolve().parents[2]
    src = root / "experiments/33_v28_matched_ablation/per_device.csv"
    out = root / "experiments/36_review_cost"
    out.mkdir(parents=True, exist_ok=True)

    agg = {}
    with src.open() as f:
        for r in csv.DictReader(f):
            key = (r["receiver"], r["stage"])
            a = agg.setdefault(key, {"candidates": 0, "reference": 0, "matched": 0})
            a["candidates"] += int(r["candidates"])
            a["reference"] += int(r["reference"])
            a["matched"] += int(r["matched"])

    cost_rows = []
    for rec in RECEIVERS:
        for st in STAGES:
            a = agg[(rec, st)]
            n, m, ref = a["candidates"], a["matched"], a["reference"]
            cost_rows.append({
                "receiver": rec, "stage": st, "candidates": n,
                "confirmed": m, "reference": ref,
                "micro_precision": round(m / n, 6) if n else 0.0,
                "micro_recall": round(m / ref, 6) if ref else 0.0,
                "reviews_per_confirmed": round(n / m, 4) if m else "",
            })
    write_csv(out / "review_cost.csv",
              ["receiver", "stage", "candidates", "confirmed", "reference",
               "micro_precision", "micro_recall", "reviews_per_confirmed"], cost_rows)

    marg_rows = []
    for rec in RECEIVERS:
        base = agg[(rec, "DIB")]
        for st in STAGES:
            if st == "DIB":
                continue
            a = agg[(rec, st)]
            dn = a["candidates"] - base["candidates"]
            dm = a["matched"] - base["matched"]
            marg_rows.append({
                "receiver": rec, "stage": st, "baseline": "DIB",
                "extra_candidates": dn, "extra_confirmed": dm,
                "extra_reviews_per_extra_confirmed": round(dn / dm, 3) if dm > 0 else "",
            })
    write_csv(out / "marginal_cost.csv",
              ["receiver", "stage", "baseline", "extra_candidates", "extra_confirmed",
               "extra_reviews_per_extra_confirmed"], marg_rows)

    # Fixed review budget: budget = the DIB queue size for that receiver.
    # Union carries no admission signal, so its expected yield under an
    # arbitrary (uniformly random) review order is budget * micro precision.
    budget_rows = []
    for rec in RECEIVERS:
        dib = agg[(rec, "DIB")]
        budget = dib["candidates"]
        for st in STAGES:
            a = agg[(rec, st)]
            n, m = a["candidates"], a["matched"]
            served = min(budget, n)
            expected = m * served / n if n else 0.0
            budget_rows.append({
                "receiver": rec, "stage": st, "budget_candidates": budget,
                "queue_size": n, "reviewed": served,
                "expected_confirmed_at_budget": round(expected, 3),
                "queue_fully_reviewed": "yes" if n <= budget else "no",
            })
    write_csv(out / "fixed_budget.csv",
              ["receiver", "stage", "budget_candidates", "queue_size", "reviewed",
               "expected_confirmed_at_budget", "queue_fully_reviewed"], budget_rows)

    manifest = {
        "command": "python3 code/scripts/review_cost_curve.py",
        "experiment": "review_cost_of_candidate_queues",
        "derivation": "aggregation only; no re-run of the admission pipeline",
        "source_experiment": "experiments/33_v28_matched_ablation",
        "definitions": {
            "confirmed": "candidates matching a receiver-observed endpoint (per_device.csv 'matched'); traffic agreement, not benignity",
            "micro_precision": "sum(matched)/sum(candidates) over the six aligned device types",
            "reviews_per_confirmed": "sum(candidates)/sum(matched): queue entries an operator inspects per confirmed endpoint",
            "extra_reviews_per_extra_confirmed": "(N_stage-N_DIB)/(M_stage-M_DIB): marginal review cost of each additional confirmed endpoint a weaker filter recovers",
            "expected_confirmed_at_budget": "yield when only 'budget' entries can be reviewed, assuming uniformly random review order within an unranked queue"
        },
        "caveats": [
            "Review burden is measured in queue entries, not operator time; no user study is performed.",
            "The fixed-budget row for union assumes arbitrary review order; union defines no ranking. Any ranking an operator applies is itself an admission filter.",
            "Six aligned device types only (label_mapping_v16.csv); same scope as Table tab:threelab."
        ],
        "parameters": {"alpha": 0.6, "beta": 0.4, "theta": 0.65, "quorum": 2},
        "sha256": {
            "experiments/33_v28_matched_ablation/per_device.csv": sha256(src),
            "code/scripts/review_cost_curve.py": sha256(Path(__file__).resolve()),
        },
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    for r in cost_rows:
        print(r)
    print()
    for r in marg_rows:
        print(r)
    print()
    for r in budget_rows:
        print(r)


if __name__ == "__main__":
    main()
