"""Corrected admission/exception figure: graph-augmented vs. graph-free (the
two configurations main_reframed.tex actually compares in Sec. Admission),
instead of the original script's three site-confidence variants (vanilla /
trust-weighted / independence-aware) all taken at the graph-augmented point,
which plot on top of each other and do not correspond to what the reframed
text discusses.

graph-augmented: (alpha, beta, gamma, theta) = (0.5, 0.3, 0.2, 0.65),
    configs/default_hyperparams.yaml, vanilla site confidence.
graph-free: (alpha, beta, gamma, theta) = (0.6, 0.4, 0.0, 0.65),
    configs/ref_trust_hyperparams.yaml, trust-weighted site confidence --
    matching main_reframed.tex line ~651 ("The renormalized graph-free point
    (0.6,0.4,0,0.65), paired with trust-weighted site confidence").

Usage:
    python3 scripts/admission_exception_tradeoff_v2.py
"""
from __future__ import annotations

import csv
import sys
from dataclasses import replace as dataclass_replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from dib.adapters.unsw_attack_2018 import MAC_TO_DEVICE, load_malicious_endpoints
from dib.core.io import filter_observations, read_observations_csv, write_csv
from dib.evaluation.dib import ScoringConfig
from dib.evaluation.trust import calibrate_reference_breadth
from dib.experiments.compromised_baseline import admission_exception_curve, dib_scores_at_k, rwv_scores_at_k, rwv_admission_exception_curve
from dib.simulator.sites import partition_observations

DEVICE_TYPES = sorted({device_type for device_type, _ip in MAC_TO_DEVICE.values()})
BASELINES = ("local_only", "pooled_union", "majority_registry", "frequency_filtered_registry")
LOW_ADMISSION_THRESHOLD = 0.05
REFERENCE_K = 3
THETAS = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75]

import os

OBSERVATIONS = "data/processed/observations_enriched.csv"
CALIBRATION_OBSERVATIONS = None
ATTACK_DIR = "data/unsw_attack_2018/annotations"
SWEEP_CSV = os.environ.get("DIB_SWEEP_CSV", "outputs/compromised_baseline/compromised_baseline_sweep.csv")
OUTPUT_DIR = Path(os.environ.get("DIB_OUTPUT_DIR", "outputs/admission_exception_tradeoff_v2"))
SEED = 42
SITE_COUNT = 10
EXCLUDE_NON_GLOBAL_IPS = os.environ.get("DIB_EXCLUDE_NON_GLOBAL_IPS", "1") == "1"

C = {
    "blue": "#2a78d6", "aqua": "#1baf7a", "yellow": "#eda100", "green": "#008300",
    "violet": "#4a3aa7", "red": "#e34948", "magenta": "#e87ba4", "orange": "#eb6834",
    "ink": "#0b0b0b", "ink2": "#52514e", "muted": "#898781", "grid": "#e1e0d9", "axis": "#c3c2b7",
}
BASELINE_COLOR = {
    "local_only": C["yellow"], "pooled_union": C["red"], "majority_registry": C["orange"],
    "frequency_filtered_registry": C["magenta"],
}
CONFIG_COLOR = {"graph_augmented": C["blue"], "graph_free": C["aqua"]}
CONFIG_LABEL = {"graph_augmented": "DIB graph-augmented", "graph_free": "DIB graph-free (trust-weighted)"}


def _read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    sweep_rows = _read_csv(Path(SWEEP_CSV))
    baseline_points: dict[str, dict[str, float]] = {}
    for strategy in BASELINES:
        cells = [r for r in sweep_rows if r["strategy"] == strategy and int(r["k"]) == REFERENCE_K]
        admission = sum(float(r["malicious_admission_rate"]) for r in cells) / len(cells)
        exceptions = sum(float(r["benign_exceptions_per_site"]) for r in cells) / len(cells)
        baseline_points[strategy] = {"malicious_admission_rate": admission, "benign_exceptions_per_site": exceptions}
        print(f"baseline {strategy}: exceptions={exceptions:.2f}, admission={admission:.3f}")

    observations = read_observations_csv(Path(OBSERVATIONS))
    if EXCLUDE_NON_GLOBAL_IPS:
        observations = list(filter_observations(observations, exclude_non_global_ips=True))
        print(f"EXCLUDE_NON_GLOBAL_IPS=1: filtered to {len(observations)} observations")
    sites = partition_observations(observations, SITE_COUNT, strategy="random", seed=SEED)
    clean_observations = [o for site in sites for o in site.observations]
    malicious_endpoints = load_malicious_endpoints(Path(ATTACK_DIR))
    attack_device_types = sorted({item.device_type for item in malicious_endpoints})
    calibration_observations = clean_observations if CALIBRATION_OBSERVATIONS is None else read_observations_csv(Path(CALIBRATION_OBSERVATIONS))

    # min_reporting_sites=2 mirrors configs/graph_augmented.yaml and
    # configs/graph_free_selected.yaml (Sec. IV-B corroboration quorum,
    # review fix 2026-07-24) -- these two configs are inlined here rather
    # than loaded from YAML, so the value must be kept in sync by hand.
    graph_augmented_config = ScoringConfig(alpha=0.5, beta=0.3, gamma=0.2, theta=0.65, min_reporting_sites=2, graph_enabled=True)
    graph_free_config = ScoringConfig(
        alpha=0.6, beta=0.4, gamma=0.0, theta=0.65, min_reporting_sites=2, graph_enabled=False,
        trust_weighted=True,
        trust_reference_breadth=calibrate_reference_breadth(clean_observations),
    )
    configs = {"graph_augmented": graph_augmented_config, "graph_free": graph_free_config}
    rwv_curve_rows = []
    for device_type in attack_device_types:
        scores, malicious_keys, benign_local_profile = rwv_scores_at_k(
            clean_observations, malicious_endpoints, device_type, REFERENCE_K, seed=SEED,
            calibration_observations=calibration_observations,
        )
        for row in rwv_admission_exception_curve(scores, malicious_keys, benign_local_profile, THETAS):
            rwv_curve_rows.append({"strategy": "rwv", "device_type": device_type, **row})

    curve_rows: list[dict[str, object]] = []
    for name, config in configs.items():
        for device_type in attack_device_types:
            scores, malicious_keys, benign_local_profile = dib_scores_at_k(
                clean_observations, malicious_endpoints, device_type, REFERENCE_K, config, seed=SEED
            )
            for row in admission_exception_curve(
                scores, malicious_keys, benign_local_profile, THETAS,
                min_reporting_sites=config.min_reporting_sites,
            ):
                curve_rows.append({"strategy": name, "device_type": device_type, **row})
        print(f"  {name}: scored {len(attack_device_types)} device types")

    curve_mean: dict[str, list[dict[str, float]]] = {name: [] for name in configs}
    for name in configs:
        for theta in THETAS:
            cells = [r for r in curve_rows if r["strategy"] == name and r["theta"] == theta]
            admission = sum(c["malicious_admission_rate"] for c in cells) / len(cells)
            exceptions = sum(c["benign_exceptions_per_site"] for c in cells) / len(cells)
            curve_mean[name].append(
                {"theta": theta, "malicious_admission_rate": admission, "benign_exceptions_per_site": exceptions}
            )
            print(f"  {name} theta={theta}: admission={admission:.4f} exceptions={exceptions:.4f}")
    rwv_mean = []
    for theta in THETAS:
        cells = [r for r in rwv_curve_rows if r["theta"] == theta]
        rwv_mean.append({"theta": theta, "malicious_admission_rate": sum(r["malicious_admission_rate"] for r in cells)/len(cells), "benign_exceptions_per_site": sum(r["benign_exceptions_per_site"] for r in cells)/len(cells)})
        print(f"  rwv theta={theta}: admission={rwv_mean[-1]['malicious_admission_rate']:.4f} exceptions={rwv_mean[-1]['benign_exceptions_per_site']:.4f}")

    write_csv(
        OUTPUT_DIR / "dib_curve_raw.csv", curve_rows,
        ["strategy", "device_type", "theta", "malicious_admission_rate", "benign_exceptions_per_site"],
    )
    mean_rows = [{"strategy": v, **row} for v in configs for row in curve_mean[v]] + [{"strategy": "rwv", **row} for row in rwv_mean]
    write_csv(
        OUTPUT_DIR / "dib_curve_mean.csv", mean_rows,
        ["strategy", "theta", "malicious_admission_rate", "benign_exceptions_per_site"],
    )
    write_csv(
        OUTPUT_DIR / "baseline_points.csv",
        [{"strategy": s, **p} for s, p in baseline_points.items()],
        ["strategy", "malicious_admission_rate", "benign_exceptions_per_site"],
    )

    fig, ax = plt.subplots(figsize=(5.2, 4.2))
    ax.axvspan(0, LOW_ADMISSION_THRESHOLD, color=C["grid"], alpha=0.6, zorder=0)
    ax.axvline(LOW_ADMISSION_THRESHOLD, color=C["axis"], lw=0.8, ls="--", zorder=1)
    ax.annotate("low-admission region", xy=(LOW_ADMISSION_THRESHOLD, 0.02), xytext=(LOW_ADMISSION_THRESHOLD + 0.03, 0.03),
                fontsize=8, color=C["ink2"])

    for strategy, point in baseline_points.items():
        ax.scatter(point["malicious_admission_rate"], point["benign_exceptions_per_site"],
                    s=90, color=BASELINE_COLOR[strategy], zorder=3, edgecolors="white", linewidths=0.6,
                    label=strategy.replace("_", " "))

    plotted_curves = {**curve_mean, "rwv": rwv_mean}
    CONFIG_COLOR["rwv"] = C["violet"]
    CONFIG_LABEL["rwv"] = "RWV (frozen reputation)"
    for name in plotted_curves:
        curve = sorted(plotted_curves[name], key=lambda r: r["theta"])
        xs = [r["malicious_admission_rate"] for r in curve]
        ys = [r["benign_exceptions_per_site"] for r in curve]
        ax.plot(xs, ys, color=CONFIG_COLOR[name], lw=1.6, marker="o", markersize=4, zorder=4,
                label=CONFIG_LABEL[name])
        for r in curve:
            if r["theta"] in (0.50, 0.65, 0.75):
                ax.annotate(f"{r['theta']:.2f}", (r["malicious_admission_rate"], r["benign_exceptions_per_site"]),
                            fontsize=6.5, color=CONFIG_COLOR[name], xytext=(3, 3), textcoords="offset points")

    ax.set_xlabel("Malicious admission rate (A1, real attack traffic, k=3/f=0.30)")
    ax.set_ylabel("Exception burden (legitimate endpoints denied per site)")
    ax.set_xlim(-0.03, 1.03)
    ax.legend(fontsize=7.5, loc="upper right", framealpha=0.92)
    fig.tight_layout()
    fig_path = OUTPUT_DIR / "admission_exception_tradeoff.pdf"
    fig.savefig(fig_path)
    plt.close(fig)
    print(f"\nwrote {fig_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
