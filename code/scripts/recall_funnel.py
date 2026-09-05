"""Reference-coverage funnel: how much of the complete manufacturer policy
survives each stage, with an explicit denominator at every step.

Sec. VI's recall funnel previously reported four cumulative percentages with
no generating script, so the "observed in the capture" and "staged by DIB"
rows could not be reproduced.  This script measures every stage from the same
artifacts the rest of the evaluation uses, and reports micro (pooled over all
reference ACEs) and macro (mean over device types) figures side by side --
they differ materially, and the paper's caption claims macro.

Stages, all against the same fixed denominator (the complete reference):
  1. all_reference_aces          -- every ACE in the released profiles
  2. direction_from_device       -- ACEs under a from-device-policy ACL; every
                                    shipped adapter emits device-initiated
                                    flows only (profiles.PREDICTED_DIRECTION),
                                    so to-device ACEs are structurally
                                    unreachable, not merely unobserved
  3. class_eligible              -- ACEs whose endpoint would pass the typed
                                    cross-site eligibility filter
                                    (intent_overlap.classify_core)
  4. observed_in_capture_raw     -- ACEs satisfied by at least one endpoint key
                                    present in the trace before address filtering
  5. observed_in_capture         -- same, after --exclude-non-global-ips (the
                                    population every scoring experiment uses)
  6. staged_by_dib               -- ACEs satisfied by the accepted (staged)
                                    fact set at the frozen operating point

Stages 2 and 3 are properties of the reference profiles alone; 4-6 are
cumulative over the pipeline.  They are deliberately NOT multiplied together:
each is an independent share of the same denominator.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import yaml

from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig
from dib.evaluation.intent_overlap import classify_core
from dib.evaluation.profiles import (
    PREDICTED_DIRECTION,
    TO_DEVICE,
    canonical_device_name,
    endpoint_satisfies_rule,
    load_profile_dir,
    normalize_profile_protocol,
)
from dib.evaluation.trust import calibrate_reference_breadth
from dib.simulator.sites import partition_observations

# Same four classes the admission predicate accepts (evaluation/dib.py:
# ELIGIBLE_CLASSES).  Imported by value rather than by reference so a change
# there shows up as a diff here instead of silently altering this funnel.
ELIGIBLE_CLASSES = {"dns", "ntp", "update", "vendor-cloud"}

FIELDS = [
    "stage",
    "scope",
    "matched_aces",
    "total_aces",
    "micro_share",
    "macro_share",
    "devices_with_any_match",
    "total_devices",
]


def rss_gib() -> float:
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / (1024 * 1024)


def sha256_of(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def predicted_key(device: str, endpoint: str, protocol: str, port: int) -> tuple[str, str, str, str, int]:
    """Build the same five-field predicted key the ground-truth matcher uses
    in ablation_multiseed.mean_f1, so every stage is scored identically."""
    device = canonical_device_name(device)
    return (device, PREDICTED_DIRECTION, endpoint.lower(), normalize_profile_protocol(protocol, port), port)


def strict_satisfies(predicted, rule) -> bool:
    """Strict variant of profiles.endpoint_satisfies_rule: a reference ACE with
    port 0 or protocol "unknown" matches only a prediction with the same
    literal value, instead of acting as a wildcard. Used to bound how much of
    the reported overlap depends on wildcard expansion."""
    pred_device, pred_direction, pred_endpoint, pred_protocol, pred_port = predicted
    rule_device, rule_direction, rule_endpoint, rule_protocol, rule_port = rule
    if pred_device != rule_device or pred_direction != rule_direction:
        return False
    if rule_protocol != pred_protocol or rule_port != pred_port:
        return False
    return endpoint_satisfies_rule(predicted, rule)


def matched_rules_strict(predicted: set, rules: set) -> set:
    return {rule for rule in rules if any(strict_satisfies(p, rule) for p in predicted)}


def matched_rules(predicted: set, rules: set) -> set:
    """The reference ACEs satisfied by at least one predicted key -- the recall
    numerator of profiles.semantic_match_metrics, kept per rule so stages can
    be compared and differenced rather than only counted."""
    return {rule for rule in rules if any(endpoint_satisfies_rule(p, rule) for p in predicted)}


def summarize(stage: str, scope: str, per_device_matched: dict[str, set], truth: dict[str, set]) -> dict[str, object]:
    total = sum(len(rules) for rules in truth.values())
    matched = sum(len(per_device_matched.get(device, set())) for device in truth)
    # Macro weights every device type equally, including reference profiles
    # with no observed traffic at all, which contribute an exact zero (the
    # same convention as the macro-F1 in ablation_multiseed.py).
    shares = [len(per_device_matched.get(device, set())) / len(rules) for device, rules in truth.items() if rules]
    return {
        "stage": stage,
        "scope": scope,
        "matched_aces": matched,
        "total_aces": total,
        "micro_share": round(matched / total, 6) if total else 0.0,
        "macro_share": round(sum(shares) / len(shares), 6) if shares else 0.0,
        "devices_with_any_match": sum(1 for device in truth if per_device_matched.get(device)),
        "total_devices": len(truth),
    }


def observed_stage(observations, truth: dict[str, set]) -> dict[str, set]:
    """Reference ACEs reachable from the raw endpoint keys in a population,
    with no scoring, quorum, or eligibility filter applied."""
    by_device: dict[str, set] = {}
    for obs in observations:
        endpoint = obs.fqdn or obs.remote_ip
        if not endpoint:
            continue
        device = canonical_device_name(obs.device_type)
        by_device.setdefault(device, set()).add(predicted_key(device, endpoint, obs.protocol, obs.port))
    return {device: matched_rules(by_device.get(device, set()), rules) for device, rules in truth.items()}


def staged_stage(scores, truth: dict[str, set], strict: bool = False) -> dict[str, set]:
    by_device: dict[str, set] = {}
    for score in scores:
        if not score.accepted:
            continue
        device = canonical_device_name(score.device_type)
        by_device.setdefault(device, set()).add(predicted_key(device, score.endpoint, score.protocol, score.port))
    match = matched_rules_strict if strict else matched_rules
    return {device: match(by_device.get(device, set()), rules) for device, rules in truth.items()}


def direction_stage(truth: dict[str, set]) -> dict[str, set]:
    return {device: {r for r in rules if r[1] != TO_DEVICE} for device, rules in truth.items()}


def class_eligible_stage(truth: dict[str, set]) -> tuple[dict[str, set], dict[str, int]]:
    """Class of each reference ACE under the deployed heuristic.  Reference
    endpoints are not always literal hosts (MUD controller abstractions,
    CIDRs), so the class breakdown is reported alongside the share rather than
    only as a single percentage."""
    per_device: dict[str, set] = {}
    breakdown: dict[str, int] = {}
    for device, rules in truth.items():
        keep = set()
        for rule in rules:
            _, _, endpoint, protocol, port = rule
            label = classify_core(endpoint, protocol, port)
            breakdown[label] = breakdown.get(label, 0) + 1
            if label in ELIGIBLE_CLASSES:
                keep.add(rule)
        per_device[device] = keep
    return per_device, breakdown


def scoring_config(path: Path, observations) -> ScoringConfig:
    config = yaml.safe_load(path.read_text(encoding="utf-8"))["scoring"]
    trust = bool(config.get("trust_weighted", False))
    return ScoringConfig(
        alpha=float(config["alpha"]),
        beta=float(config["beta"]),
        gamma=float(config["gamma"]),
        theta=float(config["theta"]),
        min_reporting_sites=int(config["min_reporting_sites"]),
        graph_enabled=bool(config.get("graph_enabled", True)),
        graph_max_endpoints_per_device=config.get("graph_max_endpoints_per_device"),
        trust_weighted=trust,
        trust_reference_breadth=calibrate_reference_breadth(observations) if trust else 0.0,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--ground-truth-dir", default="data/unsw/profiles/normalized")
    parser.add_argument("--config", default=str(ROOT.parent / "configs" / "graph_free_selected.yaml"))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--site-count", type=int, default=10)
    parser.add_argument("--output-dir", default=str(ROOT.parent / "experiments" / "21_recall_funnel"))
    args = parser.parse_args(argv)

    started = time.monotonic()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)
    observations_path = ROOT / args.observations
    truth = load_profile_dir(ROOT / args.ground_truth_dir)

    rows: list[dict[str, object]] = []
    rows.append(summarize("all_reference_aces", "reference", {d: set(r) for d, r in truth.items()}, truth))

    rows.append(summarize("direction_from_device", "reference", direction_stage(truth), truth))
    eligible, breakdown = class_eligible_stage(truth)
    rows.append(summarize("class_eligible", "reference", eligible, truth))

    raw = read_observations_csv(observations_path)
    rows.append(summarize("observed_in_capture_raw", "capture", observed_stage(raw, truth), truth))

    filtered = list(filter_observations(raw, exclude_non_global_ips=True))
    del raw
    rows.append(summarize("observed_in_capture", "capture", observed_stage(filtered, truth), truth))

    sites = partition_observations(filtered, args.site_count, strategy="random", seed=args.seed)
    del filtered
    partitioned = [obs for site in sites for obs in site.observations]
    del sites
    config = scoring_config(Path(args.config), partitioned)
    scores = DIBScorer(config).score(partitioned)
    del partitioned
    staged = staged_stage(scores, truth)
    rows.append(summarize("staged_by_dib", "pipeline", staged, truth))
    # Sensitivity: how much of the staged overlap survives if port 0 and
    # protocol "unknown" in a reference ACE stop acting as wildcards.
    rows.append(summarize("staged_by_dib_strict_match", "pipeline", staged_stage(scores, truth, strict=True), truth))
    wildcard_aces = sum(1 for rules in truth.values() for r in rules if r[4] == 0 or r[3] == "unknown")
    print(f"reference ACEs with port 0 or unknown protocol: {wildcard_aces}", flush=True)

    write_csv(output / "recall_funnel.csv", rows, FIELDS)

    per_device = []
    observed_rows = {r["stage"]: r for r in rows}
    for device, rules in sorted(truth.items()):
        per_device.append({
            "device_type": device,
            "reference_aces": len(rules),
            "from_device_aces": len({r for r in rules if r[1] != TO_DEVICE}),
            "class_eligible_aces": len(eligible.get(device, set())),
            "staged_matched_aces": len(staged.get(device, set())),
        })
    write_csv(output / "recall_funnel_by_device.csv", per_device,
              ["device_type", "reference_aces", "from_device_aces", "class_eligible_aces", "staged_matched_aces"])

    accepted = sum(1 for s in scores if s.accepted)
    manifest = {
        "experiment": "recall_funnel",
        "config": {
            "scoring_config_file": str(Path(args.config)),
            "alpha": config.alpha, "beta": config.beta, "gamma": config.gamma,
            "theta": config.theta, "min_reporting_sites": config.min_reporting_sites,
            "trust_weighted": config.trust_weighted,
            "seed": args.seed, "site_count": args.site_count,
            "exclude_non_global_ips": True,
            "pipeline_order": "read_observations_csv -> filter_observations -> partition_observations -> DIBScorer.score",
        },
        "inputs": {
            "observations": args.observations,
            "input_sha256": sha256_of(observations_path),
            "ground_truth": args.ground_truth_dir,
        },
        "commands": [["python3", "scripts/recall_funnel.py"]],
        "metrics": {
            "accepted_facts": accepted,
            "reference_class_breakdown": breakdown,
            "wall_seconds": round(time.monotonic() - started, 1),
            "peak_rss_gib": round(rss_gib(), 3),
        },
    }
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    for row in rows:
        print(f"{row['stage']:<26} micro={row['micro_share']:.4f} macro={row['macro_share']:.4f} "
              f"({row['matched_aces']}/{row['total_aces']})", flush=True)
    print(f"accepted facts={accepted}  peak RSS={rss_gib():.2f} GiB  {time.monotonic() - started:.1f}s", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
