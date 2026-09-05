from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import replace as dataclass_replace
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import DIBScorer, ScoringConfig, accepted_endpoint_keys
from dib.evaluation.trust import calibrate_reference_breadth
from dib.experiments.poisoning import inject_adaptive_sybil_endpoint
from dib.simulator.sites import partition_observations

# Tenure-based quarantine (Sec. VI-D's actual proposal: probation by
# registration age, not breadth), tested at successive maturity points of a
# single ongoing 140-day Sybil campaign, to see whether the defense holds
# while the campaign is young and whether it decays as the campaign (and
# every Sybil's tenure) ages past N -- an attacker "waiting it out" rather
# than padding breadth.
#
# inject_adaptive_sybil_endpoint anchors day 0 to an existing real
# observation's own historical timestamp, not "now" -- on this corpus that
# lands BEFORE the genuine population's own trailing max date, which would
# silently contaminate a tenure calculation (every Sybil would already look
# "aged" via the genuine population's own late dates, unrelated to the
# actual attack timeline). We re-anchor day 0 to one day after the genuine
# corpus's true max date so "as_of" in DIBScorer.score() is unambiguously
# driven by the attack's own real progress.


def _load_config(path: str) -> dict:
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml

        return yaml.safe_load(text)
    except ImportError:
        return json.loads(text)


def _scoring_config(config_path: str, tenure_days: int | None, trust_reference_breadth: float) -> ScoringConfig:
    scoring = _load_config(config_path)["scoring"]
    return ScoringConfig(
        alpha=float(scoring["alpha"]),
        beta=float(scoring["beta"]),
        gamma=float(scoring["gamma"]),
        theta=float(scoring["theta"]),
        min_reporting_sites=int(scoring["min_reporting_sites"]),
        graph_enabled=bool(scoring.get("graph_enabled", True)),
        graph_max_endpoints_per_device=scoring.get("graph_max_endpoints_per_device"),
        trust_weighted=True,
        trust_reference_breadth=trust_reference_breadth,
        temporal_quarantine=tenure_days is not None,
        temporal_quarantine_tenure_days=tenure_days,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Tenure-based temporal quarantine, tested at successive maturity points of one ongoing campaign."
    )
    parser.add_argument("--observations", default="data/processed/observations_enriched.csv")
    parser.add_argument("--output", default="results/tenure_quarantine_sweep.csv")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--site-count", type=int, default=10)
    parser.add_argument("--sybil-site-count", type=int, default=1600)
    parser.add_argument("--campaign-days", type=int, default=140)
    parser.add_argument("--tenure-days", default="7,14,30,60")
    parser.add_argument("--maturity-days", default="1,5,10,20,30,45,60,90,140")
    parser.add_argument(
        "--config", action="append", required=True, metavar="LABEL=PATH",
        help="e.g. --config MEAS=configs/default_hyperparams.yaml --config REF=configs/ref_trust_hyperparams.yaml",
    )
    parser.add_argument("--exclude-non-global-ips", action="store_true", default=False)
    args = parser.parse_args(argv)

    observations = read_observations_csv(Path(args.observations))
    if args.exclude_non_global_ips:
        observations = list(filter_observations(observations, exclude_non_global_ips=True))
        print(f"exclude_non_global_ips=True: filtered to {len(observations)} observations", flush=True)
    sites = partition_observations(observations, args.site_count, strategy="random", seed=args.seed)
    observations = [o for s in sites for o in s.observations]
    target_device_type = Counter(o.device_type for o in observations).most_common(1)[0][0]

    trust_ref = calibrate_reference_breadth(observations)
    genuine_max_date = max(o.timestamp.date() for o in observations)
    print(
        f"loaded {len(observations)} observations; target={target_device_type}; "
        f"trust_reference_breadth={trust_ref}; genuine_max_date={genuine_max_date}",
        flush=True,
    )

    full_campaign = inject_adaptive_sybil_endpoint(
        observations, args.sybil_site_count, target_device_type, args.campaign_days, seed=args.seed
    )
    sybil_obs = [o for o in full_campaign if o.site_id.startswith("sybil")]
    original_day0 = min(o.timestamp.date() for o in sybil_obs)
    reanchor_offset = (genuine_max_date - original_day0).days + 1  # so new day 0 = genuine_max_date + 1
    reanchored_sybils = [
        dataclass_replace(o, timestamp=o.timestamp + timedelta(days=reanchor_offset))
        for o in sybil_obs
    ]
    print(f"re-anchored Sybil day 0 from {original_day0} to {genuine_max_date + timedelta(days=1)}", flush=True)

    tenure_values = [int(v) for v in args.tenure_days.split(",") if v.strip()]
    maturity_values = [int(v) for v in args.maturity_days.split(",") if v.strip()]

    rows: list[dict] = []
    for spec in args.config:
        base_label, _, config_path = spec.partition("=")
        for maturity in maturity_values:
            cutoff = genuine_max_date + timedelta(days=maturity)  # keep Sybil days 0..maturity-1
            truncated_sybils = [o for o in reanchored_sybils if o.timestamp.date() <= cutoff]
            poisoned_at_t = observations + truncated_sybils

            for tenure_days in [None] + tenure_values:
                label = f"{base_label}-notenure" if tenure_days is None else f"{base_label}-tenure{tenure_days}"
                cfg = _scoring_config(config_path, tenure_days, trust_ref)

                clean_scores = DIBScorer(cfg).score(observations, target_device_type=target_device_type)
                atk_scores = DIBScorer(cfg).score(poisoned_at_t, target_device_type=target_device_type)

                clean_accepted = {s.endpoint_key for s in clean_scores if s.accepted and s.endpoint != "evil-c2.net"}
                atk_accepted = {s.endpoint_key for s in atk_scores if s.accepted and s.endpoint != "evil-c2.net"}
                fake_accepted = any(s.accepted for s in atk_scores if s.endpoint == "evil-c2.net")

                clean_ct = {s.endpoint_key: s.temporal_confidence for s in clean_scores if s.endpoint != "evil-c2.net"}
                atk_ct = {s.endpoint_key: s.temporal_confidence for s in atk_scores if s.endpoint != "evil-c2.net"}
                shared = [k for k in clean_ct if k in atk_ct and clean_ct[k] > 0]
                mean_ct_ratio = sum(atk_ct[k] / clean_ct[k] for k in shared) / len(shared) if shared else float("nan")

                row = {
                    "config": label,
                    "campaign_maturity_days": maturity,
                    "tenure_days": tenure_days if tenure_days is not None else "",
                    "clean_accepted": len(clean_accepted),
                    "attacked_accepted": len(atk_accepted),
                    "fake_accepted": fake_accepted,
                    "mean_ct_ratio": round(mean_ct_ratio, 4),
                }
                rows.append(row)
                print(
                    f"[{label}] maturity={maturity}d: target {len(clean_accepted)}->{len(atk_accepted)} "
                    f"fake_accepted={fake_accepted} mean_Ct_ratio={mean_ct_ratio:.4f}",
                    flush=True,
                )

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    write_csv(
        output_path, rows,
        ["config", "campaign_maturity_days", "tenure_days", "clean_accepted", "attacked_accepted", "fake_accepted", "mean_ct_ratio"],
    )
    print(f"wrote {len(rows)} rows to {output_path}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
