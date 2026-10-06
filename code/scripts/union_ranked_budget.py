"""Score-ranked pooled-union baseline at a fixed review budget.

Table `tab:reviewcost` compares the filtered DIB queue against the pooled union
queue reviewed in *arbitrary* order, because pooled union defines no ranking.
The strongest available objection is that an operator could instead rank the
union queue by DIB's own admission score and inspect only the top entries. This
script measures that variant: it hands the union queue DIB's score as a ranking
signal (no quorum, no class gate, no threshold) and asks how many confirmed
endpoints the top-N entries yield, where N is that receiver's full-DIB queue
size.

Scores are recomputed with the same arithmetic as `score_keys()` in
`moniotr_cross_lab.py` (alpha=0.6, beta=0.4 over the source deployments only),
using `_score_map`, which is that function's score expression with the
threshold, quorum and class-gate decisions removed.

Ties: many union entries share a score, so a strict sort is not well defined.
We report the expected yield under a uniformly random order *within* each tied
score group (the same expectation convention as `review_cost_curve.py`), plus
the best- and worst-case tie-breakings as bounds.

Run from the repository root:  python3 code/scripts/union_ranked_budget.py
"""
from pathlib import Path
import csv
import hashlib
import json
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from moniotr_cross_lab import (  # noqa: E402
    collapse_site_three, load, load_label_mapping, per_device_metrics, write_csv,
)
from moniotr_cross_lab import classify_core, ELIGIBLE  # noqa: E402,F401

SITES = ("US", "UK", "YT")
ALPHA, BETA = 0.6, 0.4


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _score_map(data, sites):
    """Admission score for every endpoint fact, as computed by score_keys().

    Same expression as moniotr_cross_lab.score_keys(); the threshold, quorum and
    class-gate decisions are omitted so that the score can be used as a ranking
    over the unfiltered union queue.
    """
    scores, supports = {}, {}
    for key, supporters_all in data.endpoints.items():
        supporters = supporters_all & sites
        device, endpoint, protocol, port = key
        eligible = data.device_sites[device] & sites
        if not supporters or not eligible:
            continue
        site_conf = len(supporters) / len(eligible)
        endpoint_days = {d for s in sites for d in data.site_endpoint_days[(s, key)]}
        device_days = {d for s in sites for d in data.site_device_days[(s, device)]}
        endpoint_count = sum(data.site_endpoint_date_counts[(s, key, d)]
                             for s in sites for d in data.site_endpoint_days[(s, key)])
        device_count = sum(data.site_device_date_counts[(s, device, d)]
                           for s in sites for d in data.site_device_days[(s, device)])
        temporal = min(1.0, 0.7 * len(endpoint_days) / max(len(device_days), 1)
                       + 0.3 * endpoint_count / max(device_count, 1))
        scores[key] = ALPHA * site_conf + BETA * temporal
        supports[key] = len(supporters)
    return scores, supports


def budget_yield(ranked, confirmed_set, budget):
    """Expected/best/worst confirmed endpoints in the top `budget` of `ranked`.

    `ranked` is a list of (score, key) sorted by score descending. Within a tied
    score group the review order is arbitrary, so the expectation is taken over
    a uniformly random order inside the group; best/worst place that group's
    confirmed entries first/last.
    """
    remaining = budget
    exp = best = worst = 0.0
    i = 0
    while i < len(ranked) and remaining > 0:
        j = i
        while j < len(ranked) and ranked[j][0] == ranked[i][0]:
            j += 1
        group = [k for _, k in ranked[i:j]]
        hits = sum(1 for k in group if k in confirmed_set)
        take = min(remaining, len(group))
        exp += hits * take / len(group)
        best += min(hits, take)
        worst += max(0, take - (len(group) - hits))
        remaining -= take
        i = j
    return exp, best, worst


def main():
    root = Path(__file__).resolve().parents[2]
    inputs = [root / "code/data/processed/moniotr_full_observations.csv",
              root / "code/data/processed/yourthings_observations.csv"]
    mapping = root / "experiments/30_three_lab_loo/label_mapping_v16.csv"
    out = root / "experiments/38_union_ranked_budget"
    out.mkdir(parents=True, exist_ok=True)

    label_map = load_label_mapping(mapping)
    data = load(inputs[0], extra_paths=inputs[1:], collapse_fn=collapse_site_three,
                label_map=label_map)

    rows, curve_rows, comp_rows, marg_rows = [], [], [], []
    for receiver in SITES:
        sources = set(SITES) - {receiver}
        devices, locked, _ = per_device_metrics(data, SITES, receiver)
        assert len(devices) == 6
        source_union = {k for k, reporters in data.endpoints.items()
                        if k[0] in devices and reporters & sources}
        observed = set()
        for device in devices:
            observed |= data.profiles[receiver][device]
        confirmed_set = source_union & observed

        scores, supports = _score_map(data, sources)
        missing = [k for k in source_union if k not in scores]
        assert not missing, missing[:3]
        # The score map must reproduce score_keys() exactly: re-applying the
        # threshold, quorum and class gate to it must rebuild the DIB queue.
        rebuilt = {k for k in scores
                   if scores[k] >= 0.65 and supports[k] >= 2
                   and classify_core(k[1], k[2], k[3]) in ELIGIBLE
                   and k[0] in devices}
        assert rebuilt == locked, (len(rebuilt), len(locked))
        ranked = sorted(((scores[k], k) for k in source_union),
                        key=lambda t: (-t[0], str(t[1])))

        budget = len(locked)
        dib_confirmed = len(locked & observed)
        exp, best, worst = budget_yield(ranked, confirmed_set, budget)

        # Queue depth the ranked union must reach for DIB's confirmed count.
        depth, got = None, 0
        for n, (_, k) in enumerate(ranked, start=1):
            if k in confirmed_set:
                got += 1
                if got >= dib_confirmed:
                    depth = n
                    break

        # Composition of the ranked prefix: what an operator using the ranking
        # alone would be inspecting, and which DIB stage would have removed it.
        def stage_of(k):
            if k in locked:
                return "admitted by DIB"
            if scores[k] < 0.65:
                return "below threshold"
            if supports[k] < 2:
                return "fails quorum"
            return "fails class gate"
        prefix = [k for _, k in ranked[:budget]]
        by_stage = {}
        for k in prefix:
            e = by_stage.setdefault(stage_of(k), {"entries": 0, "confirmed": 0})
            e["entries"] += 1
            e["confirmed"] += k in confirmed_set
        for stage in ("admitted by DIB", "below threshold", "fails quorum", "fails class gate"):
            e = by_stage.get(stage, {"entries": 0, "confirmed": 0})
            comp_rows.append(dict(receiver=receiver, budget=budget, stage=stage,
                                  entries=e["entries"], confirmed=e["confirmed"],
                                  share_of_prefix=round(e["entries"] / budget, 4)))
        single = [k for k in prefix if supports[k] < 2]
        comp_rows.append(dict(receiver=receiver, budget=budget,
                              stage="single-reporter (subset)", entries=len(single),
                              confirmed=sum(k in confirmed_set for k in single),
                              share_of_prefix=round(len(single) / budget, 4)))

        # Marginal return around DIB's stopping point: the budget-sized prefix
        # against the next equally sized block of the ranked queue.
        e1, _, _ = budget_yield(ranked, confirmed_set, budget)
        e2, _, _ = budget_yield(ranked, confirmed_set, min(2 * budget, len(source_union)))
        nxt = min(2 * budget, len(source_union)) - budget
        marg_rows.append(dict(
            receiver=receiver, budget=budget,
            confirmed_per_entry_in_prefix=round(e1 / budget, 4),
            confirmed_per_entry_in_next_block=round((e2 - e1) / nxt, 4) if nxt else "",
            marginal_drop_factor=round((e1 / budget) / ((e2 - e1) / nxt), 2) if nxt and e2 > e1 else "",
            confirmed_per_entry_whole_queue=round(len(confirmed_set) / len(source_union), 4)))

        rows.append(dict(
            receiver=receiver, budget=budget,
            union_queue=len(source_union), union_confirmed_total=len(confirmed_set),
            dib_queue=len(locked), dib_confirmed=dib_confirmed,
            union_ranked_expected=round(exp, 3),
            union_ranked_best=int(best), union_ranked_worst=int(worst),
            union_arbitrary_expected=round(len(confirmed_set) * budget / len(source_union), 3),
            dib_minus_ranked_expected=round(dib_confirmed - exp, 3),
            ranked_union_depth_for_dib_yield=depth if depth is not None else "",
            ranked_reviews_per_confirmed=round(budget / exp, 3) if exp else "",
            dib_reviews_per_confirmed=round(len(locked) / dib_confirmed, 3) if dib_confirmed else "",
            dib_queue_minus_ranked_depth=(len(locked) - depth) if depth is not None else "",
        ))
        grid = sorted({min(int(round(f * budget)), len(source_union))
                       for f in (0.25, 0.5, 0.75, 1, 1.5, 2, 3, 5, 8, 12)}
                      | {len(source_union)})
        for n in grid:
            if n < 1:
                continue
            e, b, w = budget_yield(ranked, confirmed_set, n)
            curve_rows.append(dict(receiver=receiver, reviewed=n,
                                   ranked_expected=round(e, 3),
                                   ranked_best=int(b), ranked_worst=int(w),
                                   arbitrary_expected=round(len(confirmed_set) * n / len(source_union), 3)))

    write_csv(out / "union_ranked_budget.csv", rows)
    write_csv(out / "ranked_union_curve.csv", curve_rows)
    write_csv(out / "ranked_prefix_composition.csv", comp_rows)
    write_csv(out / "ranked_marginal_return.csv", marg_rows)

    files = inputs + [mapping, Path(__file__).resolve(),
                      root / "code/scripts/moniotr_cross_lab.py"]
    (out / "manifest.json").write_text(json.dumps(dict(
        experiment="score_ranked_union_at_fixed_review_budget",
        command="python3 code/scripts/union_ranked_budget.py",
        derivation="re-scores the pooled union queue of experiments/33_v28_matched_ablation; no change to the admission pipeline",
        source_experiment="experiments/33_v28_matched_ablation",
        parameters=dict(alpha=ALPHA, beta=BETA, theta="not applied (ranking only)",
                        quorum="not applied (ranking only)", class_gate="not applied (ranking only)"),
        scope="same six aligned device types and same source/receiver split as Table tab:threelab",
        definitions=dict(
            confirmed="union candidate matching a receiver-observed endpoint; traffic agreement, not benignity",
            union_ranked_expected="expected confirmed endpoints in the top-`budget` entries of the union queue ranked by admission score, averaging over a uniformly random order within each tied score group",
            union_ranked_best="upper bound over tie-breakings",
            union_ranked_worst="lower bound over tie-breakings",
            union_arbitrary_expected="the unranked convention used in experiments/36_review_cost/fixed_budget.csv",
            ranked_union_depth_for_dib_yield="entries the ranked union queue must expose before it has revealed as many confirmed endpoints as full DIB",
            ranked_prefix_composition="for the top-`budget` entries of the ranked union queue, how many DIB would admit and, for the rest, which DIB stage removes them; 'single-reporter' is the subset supported by one source deployment",
            marginal_drop_factor="confirmed per entry inside the budget-sized prefix divided by confirmed per entry in the next equally sized block",
        ),
        caveats=[
            "Ranking the union queue by DIB's admission score gives the baseline the benefit of the mechanism under evaluation; it is an upper bound on what an unranked pooled queue can achieve with this signal, not a property of pooled union itself.",
            "Burden is counted in queue entries, not operator time.",
            "A ranking has no rejection region, so Criterion 1's bound on adversary-only evidence does not apply to it: the composition table reports what a budget-limited operator would inspect under ranking alone, it does not measure an attack.",
            "Six aligned device types only (label_mapping_v16.csv); same scope as Table tab:threelab.",
        ],
        sha256={str(p.relative_to(root)): sha256(p) for p in files}), indent=2, sort_keys=True) + "\n")
    for r in rows:
        print(r, flush=True)
    print()
    for r in curve_rows:
        print(r, flush=True)


if __name__ == "__main__":
    main()
