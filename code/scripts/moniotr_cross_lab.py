"""Two-deployment Mon(IoT)r transfer and candidate-review workload.

US/US-VPN and UK/UK-VPN are repeated observations of the same populations.
They are collapsed before *all* support counts.  In particular, a directional
US->UK or UK->US fit contains one independent deployment, so DIB's locked
two-site quorum correctly admits no fact; the script reports that boundary
rather than counting VPN routing variants as independent contributors.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dib.evaluation.intent_overlap import classify_core


Key = tuple[str, str, str, int]
ELIGIBLE = {"dns", "ntp", "update", "vendor-cloud"}
REPRESENTABLE = {"tcp", "http", "https", "tls", "syslog", "mqtt", "udp", "dns", "dhcp", "ntp"}


@dataclass
class Aggregate:
    endpoints: dict[Key, set[str]] = field(default_factory=lambda: defaultdict(set))
    endpoint_days: dict[Key, set[date]] = field(default_factory=lambda: defaultdict(set))
    endpoint_counts: Counter[Key] = field(default_factory=Counter)
    site_endpoint_days: dict[tuple[str, Key], set[date]] = field(default_factory=lambda: defaultdict(set))
    site_endpoint_counts: Counter[tuple[str, Key]] = field(default_factory=Counter)
    site_endpoint_date_counts: Counter[tuple[str, Key, date]] = field(default_factory=Counter)
    device_sites: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    device_days: dict[str, set[date]] = field(default_factory=lambda: defaultdict(set))
    device_counts: Counter[str] = field(default_factory=Counter)
    site_device_days: dict[tuple[str, str], set[date]] = field(default_factory=lambda: defaultdict(set))
    site_device_counts: Counter[tuple[str, str]] = field(default_factory=Counter)
    site_device_date_counts: Counter[tuple[str, str, date]] = field(default_factory=Counter)
    profiles: dict[str, dict[str, set[Key]]] = field(
        default_factory=lambda: defaultdict(lambda: defaultdict(set))
    )
    first_seen: dict[tuple[str, Key], date] = field(default_factory=dict)
    rows_read: int = 0
    rows_kept: int = 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--observations", default="data/processed/moniotr_full_observations.csv")
    parser.add_argument("--output-dir", default="outputs/tnsm_baseline/moniotr_cross_lab")
    parser.add_argument(
        "--yourthings-observations", default=None,
        help="Optional third-organization observations (e.g. YourThings) to add as a 'YT' "
        "deployment for a non-trivial three-lab leave-one-out. When omitted, behavior is "
        "unchanged from the two-lab (US/UK) comparison.",
    )
    parser.add_argument(
        "--label-mapping", default=None,
        help="Optional CSV with columns canonical,yourthings_label,moniotr_label used to align "
        "device-type labels across organizations before the three-lab leave-one-out. Required "
        "if --yourthings-observations is given.",
    )
    args = parser.parse_args(argv)
    source = Path(args.observations)
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    aggregate = load(source)
    transfer_rows: list[dict[str, object]] = []
    for train, test in (("US", "UK"), ("UK", "US")):
        transfer_rows.extend(transfer(aggregate, train, test))
    write_csv(output / "cross_lab_transfer.csv", transfer_rows)
    write_csv(output / "leave_one_out.csv", leave_one_out(aggregate))

    workload_rows = workload(aggregate)
    write_csv(output / "candidate_review_load.csv", workload_rows)
    write_csv(
        output / "candidate_review_distribution.csv",
        workload_distribution(workload_rows),
    )
    write_csv(output / "candidate_review_load_by_window.csv", window_workload(aggregate))
    write_csv(output / "supporting_site_distribution.csv", support_distribution(aggregate))

    three_lab_manifest: dict[str, object] | None = None
    if args.yourthings_observations:
        if not args.label_mapping:
            raise SystemExit("--label-mapping is required when --yourthings-observations is given")
        label_map = load_label_mapping(Path(args.label_mapping))
        three_lab = load(
            source,
            extra_paths=[Path(args.yourthings_observations)],
            collapse_fn=collapse_site_three,
            label_map=label_map,
        )
        three_lab_rows = leave_one_out_generalized(three_lab, ("US", "UK", "YT"))
        write_csv(output / "leave_one_out_three_lab.csv", three_lab_rows)
        three_lab_manifest = {
            "sites": ["US", "UK", "YT"],
            "yourthings_observations": str(args.yourthings_observations),
            "yourthings_observations_sha256": sha256(Path(args.yourthings_observations)),
            "label_mapping": str(args.label_mapping),
            "label_mapping_sha256": sha256(Path(args.label_mapping)),
            "aligned_device_types": sorted(set(label_map.values())),
            "note": "Label mapping was frozen (Fase 6, plan step 2) before this experiment was run; "
            "it is a mechanical hyphen/case normalization plus three exact string matches, not a "
            "post-hoc fit to the result.",
        }

    manifest = {
        "experiment": "moniotr_cross_lab_and_candidate_load",
        "input": str(source),
        "input_sha256": sha256(source),
        "command": ["python3", "scripts/moniotr_cross_lab.py", "--observations", str(source), "--output-dir", str(output)],
        "seed": 0,
        "site_collapse": {"moniotr-us": "US", "moniotr-us-vpn": "US", "moniotr-uk": "UK", "moniotr-uk-vpn": "UK"},
        "config": {"alpha": 0.6, "beta": 0.4, "gamma": 0.0, "theta": 0.65, "min_reporting_sites": 2},
        "rows_read": aggregate.rows_read,
        "rows_kept": aggregate.rows_kept,
        "independent_deployments": sorted(aggregate.profiles),
        "interpretation": "cross-lab transfer; VPN trees are repeated observations, not independent sites",
        "leave_one_out": {
            "receiver_excluded_from": ["reporters", "eligible_population", "breadth_denominator", "temporal_days", "temporal_counts"],
            "result": "With only one independent source left after hold-out, the locked two-site quorum admits zero automatic candidates.",
            "cold_start_requirement": "A two-source quorum requires at least three independent deployments: two sources and one receiver.",
        },
        "workload_distribution": {
            "device_scope": "device types present in both collapsed deployments",
            "quartiles": "Tukey hinges",
            "p95": "nearest rank",
        },
    }
    if three_lab_manifest is not None:
        manifest["leave_one_out_three_lab"] = three_lab_manifest
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


def load(
    path: Path,
    *,
    extra_paths: list[Path] | None = None,
    collapse_fn=None,
    label_map: dict[str, str] | None = None,
    only_day: date | dict[str, date] | None = None,
) -> Aggregate:
    collapse = collapse_fn or collapse_site
    label_map = label_map or {}
    data = Aggregate()
    for source_path in [path, *(extra_paths or [])]:
        _load_one(source_path, data, collapse, label_map, only_day=only_day)
    return data


def _load_one(
    path: Path,
    data: Aggregate,
    collapse,
    label_map: dict[str, str],
    *,
    only_day: date | dict[str, date] | None = None,
) -> None:
    """``only_day`` restricts rows to a single UTC calendar day before
    aggregation. A single ``date`` applies the same cutoff day to every
    site (used for the literal "truncate everyone to YourThings' capture
    day" variant). A ``{site: date}`` dict instead gives each site its own
    single-day cutoff (used for the window-length-matched variant, since
    Mon(IoT)r's capture (2019-03-29..2019-05-08) shares no calendar date
    with YourThings' 2018-03-21 capture)."""
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            data.rows_read += 1
            site = collapse(row["site_id"])
            if site is None:
                continue
            endpoint = (row.get("fqdn") or row.get("remote_ip") or "").strip().lower()
            if not endpoint or excluded_non_global(row.get("fqdn"), row.get("remote_ip")):
                continue
            device = row["device_type"].strip()
            device = label_map.get(device, device)
            protocol = row["protocol"].strip().lower()
            port = int(row["port"])
            day = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00")).date()
            if only_day is not None:
                if isinstance(only_day, dict):
                    target_day = only_day.get(site)
                    if target_day is None or day != target_day:
                        continue
                elif day != only_day:
                    continue
            key = (device, endpoint, protocol, port)
            data.rows_kept += 1
            data.endpoints[key].add(site)
            data.endpoint_days[key].add(day)
            data.endpoint_counts[key] += 1
            data.site_endpoint_days[(site, key)].add(day)
            data.site_endpoint_counts[(site, key)] += 1
            data.site_endpoint_date_counts[(site, key, day)] += 1
            data.device_sites[device].add(site)
            data.device_days[device].add(day)
            data.device_counts[device] += 1
            data.site_device_days[(site, device)].add(day)
            data.site_device_counts[(site, device)] += 1
            data.site_device_date_counts[(site, device, day)] += 1
            data.profiles[site][device].add(key)
            first_key = (site, key)
            data.first_seen[first_key] = min(data.first_seen.get(first_key, day), day)


def collapse_site(site: str) -> str | None:
    if site in {"moniotr-us", "moniotr-us-vpn"}:
        return "US"
    if site in {"moniotr-uk", "moniotr-uk-vpn"}:
        return "UK"
    return None


def collapse_site_three(site: str) -> str | None:
    """collapse_site() plus a third independent organization (YourThings,
    Georgia Tech), used only for the three-lab leave-one-out (Sec. V-D).
    The two-lab collapse and all other outputs are unaffected."""
    base = collapse_site(site)
    if base is not None:
        return base
    if site.startswith("yourthings"):
        return "YT"
    return None


def load_label_mapping(path: Path) -> dict[str, str]:
    """Read a canonical,yourthings_label,moniotr_label CSV (frozen before the
    three-lab experiment runs, per Fase 6 step 2) and return a
    {source_label: canonical_label} dict covering both source columns."""
    mapping: dict[str, str] = {}
    with path.open(newline="", encoding="utf-8") as handle:
        for row in csv.DictReader(handle):
            canonical = row["canonical"].strip()
            for column in ("yourthings_label", "moniotr_label"):
                label = row[column].strip()
                if label:
                    mapping[label] = canonical
    return mapping


def per_device_metrics(
    data: Aggregate, sites: tuple[str, ...], receiver: str,
) -> tuple[list[str], set[Key], list[dict[str, float]]]:
    """Shared core of the N-site leave-one-out: the target device types, the
    admitted candidate keys, and the per-device precision/recall/F1 dicts
    (in ``target_devices`` order) for holding ``receiver`` out and pooling
    every other site in ``sites`` as a source. Factored out of
    ``leave_one_out_generalized`` so diagnostics (reference-set sizes,
    bootstrap CI, leave-one-device-out) can reuse the exact same scoring
    logic instead of reimplementing it."""
    sources = tuple(s for s in sites if s != receiver)
    source_device_sets = [set(data.profiles[s]) for s in sources]
    target_devices = sorted(set.intersection(*source_device_sets) & set(data.profiles[receiver])) if source_device_sets else []
    candidates, _ = score_keys(data, set(sources), gate=True, quorum=True)
    candidates = {key for key in candidates if key[0] in target_devices}
    metrics = [
        set_metrics({key for key in candidates if key[0] == device}, data.profiles[receiver][device])
        for device in target_devices
    ]
    return target_devices, candidates, metrics


def leave_one_out_generalized(data: Aggregate, sites: tuple[str, ...]) -> list[dict[str, object]]:
    """N-site leave-one-out: for each receiver, every *other* site is a
    source. With three or more sites this is a non-trivial test of the
    locked two-source quorum (unlike the two-site case in leave_one_out(),
    where holding one out always leaves exactly one source and the boundary
    is guaranteed rather than observed)."""
    rows: list[dict[str, object]] = []
    for receiver in sites:
        sources = tuple(s for s in sites if s != receiver)
        target_devices, candidates, metrics = per_device_metrics(data, sites, receiver)
        rows.append({
            "receiving_deployment": receiver,
            "source_deployments": "+".join(sources),
            "independent_source_deployments": len(sources),
            "min_reporting_sites": 2,
            "target_device_types": len(target_devices),
            "admitted_candidates": len(candidates),
            "target_device_coverage": sum(
                bool({key for key in candidates if key[0] == device}) for device in target_devices
            ) / len(target_devices) if target_devices else 0.0,
            "precision_macro": mean(metrics, "precision"),
            "recall_macro": mean(metrics, "recall"),
            "f1_macro": mean(metrics, "f1"),
            "metric_status": "not_applicable_no_admitted_candidates" if not candidates else "defined",
            "receiver_excluded_from_scoring": True,
        })
    return rows


def excluded_non_global(fqdn: str | None, remote_ip: str | None) -> bool:
    if fqdn and not is_ip(fqdn):
        return False
    if not remote_ip:
        return False
    try:
        return not ipaddress.ip_address(remote_ip).is_global
    except ValueError:
        return True


def is_ip(value: str) -> bool:
    head, sep, tail = value.rpartition(":")
    candidate = head if sep and tail.isdigit() else value
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


def score_keys(
    data: Aggregate,
    sites: set[str],
    *,
    gate: bool = True,
    quorum: bool = True,
    cutoff: date | None = None,
) -> tuple[set[Key], int]:
    predicted: set[Key] = set()
    gate_excluded = 0
    for key, supporters_all in data.endpoints.items():
        supporters = {
            site for site in supporters_all & sites
            if cutoff is None or any(day <= cutoff for day in data.site_endpoint_days[(site, key)])
        }
        device, endpoint, protocol, port = key
        eligible = {
            site for site in data.device_sites[device] & sites
            if cutoff is None or any(day <= cutoff for day in data.site_device_days[(site, device)])
        }
        if not supporters or not eligible:
            continue
        site_conf = len(supporters) / len(eligible)
        endpoint_days = {
            day for site in sites for day in data.site_endpoint_days[(site, key)]
            if cutoff is None or day <= cutoff
        }
        device_days = {
            day for site in sites for day in data.site_device_days[(site, device)]
            if cutoff is None or day <= cutoff
        }
        endpoint_count = sum(
            data.site_endpoint_date_counts[(site, key, day)]
            for site in sites for day in data.site_endpoint_days[(site, key)]
            if cutoff is None or day <= cutoff
        )
        device_count = sum(
            data.site_device_date_counts[(site, device, day)]
            for site in sites for day in data.site_device_days[(site, device)]
            if cutoff is None or day <= cutoff
        )
        active_day_ratio = len(endpoint_days) / max(len(device_days), 1)
        frequency_ratio = endpoint_count / max(device_count, 1)
        temporal = min(1.0, 0.7 * active_day_ratio + 0.3 * frequency_ratio)
        value = 0.6 * site_conf + 0.4 * temporal
        portable = classify_core(endpoint, protocol, port) in ELIGIBLE
        if value >= 0.65 and not portable:
            gate_excluded += 1
        if value >= 0.65 and (not gate or portable) and (not quorum or len(supporters) >= 2):
            predicted.add(key)
    return predicted, gate_excluded


def transfer(data: Aggregate, train: str, test: str) -> list[dict[str, object]]:
    train_union = {key for profile in data.profiles[train].values() for key in profile}
    dib, gate_excluded = score_keys(data, {train})
    dib_no_gate, _ = score_keys(data, {train}, gate=False)
    quorum_only = {key for key in train_union if len(data.endpoints[key] & {train}) >= 2}
    majority = set(train_union)  # one independent training deployment
    methods = {
        "dib": dib,
        "pooled_union": train_union,
        "quorum_only": quorum_only,
        "majority": majority,
        "dib_without_portability_gate": dib_no_gate,
    }
    rows = []
    devices = sorted(set(data.profiles[train]) & set(data.profiles[test]))
    for method, predicted in methods.items():
        metrics = [set_metrics({k for k in predicted if k[0] == device}, data.profiles[test][device]) for device in devices]
        rows.append({
            "train_deployment": train,
            "test_deployment": test,
            "method": method,
            "device_count": len(devices),
            "admitted_candidates": sum(1 for key in predicted if key[0] in devices),
            "precision_macro": mean(metrics, "precision"),
            "recall_macro": mean(metrics, "recall"),
            "f1_macro": mean(metrics, "f1"),
            "device_coverage": sum(bool({k for k in predicted if k[0] == device}) for device in devices) / len(devices) if devices else 0.0,
            "portability_gate_exclusions": gate_excluded if method == "dib" else 0,
            "independent_training_sites": 1,
        })
    return rows


def leave_one_out(data: Aggregate) -> list[dict[str, object]]:
    """Cold-start admission with the receiving deployment completely excluded.

    This is intentionally distinct from ``transfer``: it records the exact
    feasibility boundary of the locked two-source admission rule.  With only
    US and UK available, holding one out leaves one independent reporter, so
    no fact can satisfy ``m=2``.  Calling ``score_keys`` with only the source
    set guarantees the receiver contributes to neither scorer numerator nor
    denominator, days, counts, or eligible-device population.
    """
    rows: list[dict[str, object]] = []
    for source, receiver in (("US", "UK"), ("UK", "US")):
        target_devices = sorted(set(data.profiles[source]) & set(data.profiles[receiver]))
        candidates, _ = score_keys(data, {source}, gate=True, quorum=True)
        candidates = {key for key in candidates if key[0] in target_devices}
        metrics = [
            set_metrics({key for key in candidates if key[0] == device}, data.profiles[receiver][device])
            for device in target_devices
        ]
        rows.append({
            "source_deployment": source,
            "receiving_deployment": receiver,
            "independent_source_deployments": 1,
            "min_reporting_sites": 2,
            "target_device_types": len(target_devices),
            "admitted_candidates": len(candidates),
            "target_device_coverage": sum(
                bool({key for key in candidates if key[0] == device}) for device in target_devices
            ) / len(target_devices) if target_devices else 0.0,
            "precision_macro": mean(metrics, "precision"),
            "recall_macro": mean(metrics, "recall"),
            "f1_macro": mean(metrics, "f1"),
            "metric_status": "not_applicable_no_admitted_candidates" if not candidates else "defined",
            "receiver_excluded_from_scoring": True,
            "interpretation": "one source remains after hold-out; m=2 cannot admit an automatic candidate",
        })
    return rows


def workload(data: Aggregate) -> list[dict[str, object]]:
    methods = {
        "dib": score_keys(data, {"US", "UK"})[0],
        "pooled_union": set(data.endpoints),
        "quorum_only": {key for key, sites in data.endpoints.items() if len(sites) >= 2},
        "majority": {key for key, sites in data.endpoints.items() if len(sites) / len(data.device_sites[key[0]]) >= 0.5},
        "dib_without_portability_gate": score_keys(data, {"US", "UK"}, gate=False)[0],
    }
    rows = []
    for site in ("US", "UK"):
        for method, candidates in methods.items():
            for device in sorted(data.profiles[site]):
                selected = {key for key in candidates if key[0] == device}
                seen = selected & data.profiles[site][device]
                rows.append({
                    "site_id": site,
                    "device_type": device,
                    "method": method,
                    "monitor_only_queue": len(selected),
                    "new_candidates_window": len(selected),
                    "exportable_candidates": sum(representable(key) for key in selected),
                    "held_out_seen_count": len(seen),
                    "held_out_seen_fraction": len(seen) / len(selected) if selected else 0.0,
                    "supporting_sites_mean": sum(len(data.endpoints[key]) for key in selected) / len(selected) if selected else 0.0,
                    "review_flags_after_rescore": 0,
                    "churn_added": len(selected),
                    "churn_removed": 0,
                    "window": "full-capture",
                })
    return rows


def workload_distribution(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    """Summarize DIB's full-capture queue over device types shared by both sites.

    Quartiles use Tukey hinges and p95 uses the nearest-rank definition.  The
    raw per-device values remain available in ``candidate_review_load.csv``.
    """
    dib_rows = [
        row for row in rows
        if row["method"] == "dib" and row["window"] == "full-capture"
    ]
    by_site = {
        site: {str(row["device_type"]): int(row["monitor_only_queue"])
               for row in dib_rows if row["site_id"] == site}
        for site in ("US", "UK")
    }
    shared_devices = sorted(set(by_site["US"]) & set(by_site["UK"]))
    summaries: list[dict[str, object]] = []
    for site in ("US", "UK"):
        values = sorted(by_site[site][device] for device in shared_devices)
        lower = values[: len(values) // 2]
        upper = values[(len(values) + 1) // 2 :]
        summaries.append({
            "site_id": site,
            "method": "dib",
            "device_scope": "overlapping",
            "device_count": len(values),
            "queue_total": sum(values),
            "mean": sum(values) / len(values),
            "median": _median(values),
            "q1": _median(lower),
            "q3": _median(upper),
            "p95_nearest_rank": values[max(0, (95 * len(values) + 99) // 100 - 1)],
            "maximum": max(values),
        })
    return summaries


def _median(values: list[int]) -> float:
    midpoint = len(values) // 2
    if len(values) % 2:
        return float(values[midpoint])
    return (values[midpoint - 1] + values[midpoint]) / 2


def window_workload(data: Aggregate) -> list[dict[str, object]]:
    """Cumulative daily queue/churn; removed Active facts map to review flags."""
    days = sorted({day for values in data.device_days.values() for day in values})
    previous: dict[tuple[str, str, str], set[Key]] = defaultdict(set)
    endpoint_first = {key: min(values) for key, values in data.endpoint_days.items()}
    rows: list[dict[str, object]] = []
    for cutoff in days:
        observed = {key for key, first in endpoint_first.items() if first <= cutoff}
        methods = {
            "dib": score_keys(data, {"US", "UK"}, cutoff=cutoff)[0],
            "pooled_union": observed,
            "quorum_only": {
                key for key in observed
                if sum(data.first_seen.get((site, key), date.max) <= cutoff for site in ("US", "UK")) >= 2
            },
            "majority": observed,
            "dib_without_portability_gate": score_keys(data, {"US", "UK"}, gate=False, cutoff=cutoff)[0],
        }
        for site in ("US", "UK"):
            for method, keys in methods.items():
                for device in sorted(data.profiles[site]):
                    current = {key for key in keys if key[0] == device}
                    identity = (site, method, device)
                    before = previous[identity]
                    rows.append({
                        "window_end": cutoff.isoformat(), "site_id": site, "device_type": device,
                        "method": method, "monitor_only_queue": len(current),
                        "new_candidates_window": len(current - before),
                        "churn_removed": len(before - current),
                        "review_flags_if_previously_active": len(before - current),
                        "exportable_candidates": sum(representable(key) for key in current),
                    })
                    previous[identity] = current
    return rows


def support_distribution(data: Aggregate) -> list[dict[str, object]]:
    rows = []
    for method, keys in (
        ("all_observed", set(data.endpoints)),
        ("dib_admitted", score_keys(data, {"US", "UK"})[0]),
    ):
        counts = Counter(len(data.endpoints[key]) for key in keys)
        for support, count in sorted(counts.items()):
            rows.append({"method": method, "supporting_sites": support, "fact_count": count})
    return rows


def representable(key: Key) -> bool:
    _, endpoint, protocol, _ = key
    return not is_ip(endpoint) and protocol in REPRESENTABLE


def set_metrics(predicted: set[Key], observed: set[Key]) -> dict[str, float]:
    matched = len(predicted & observed)
    precision = matched / len(predicted) if predicted else 0.0
    recall = matched / len(observed) if observed else 0.0
    return {"precision": precision, "recall": recall, "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0}


def mean(rows: list[dict[str, float]], field: str) -> float:
    return sum(row[field] for row in rows) / len(rows) if rows else 0.0


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError(f"no rows for {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
