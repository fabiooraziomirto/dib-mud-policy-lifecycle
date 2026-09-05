from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import random

from dib.core.models import Observation


def inject_fake_endpoint(
    observations: list[Observation],
    malicious_fraction: float,
    fake_fqdn: str = "evil-c2.net",
    protocol: str = "https",
    port: int = 443,
    seed: int = 42,
) -> list[Observation]:
    """Add endpoint-level poisoned observations to a fraction of existing sites."""

    if not 0.0 <= malicious_fraction <= 1.0:
        raise ValueError("malicious_fraction must be in [0, 1]")
    rng = random.Random(seed)
    sites = sorted({obs.site_id for obs in observations})
    malicious_count = int(round(len(sites) * malicious_fraction))
    malicious_sites = set(rng.sample(sites, malicious_count)) if malicious_count else set()
    poisoned = list(observations)
    by_site_device: dict[tuple[str, str], Observation] = {}
    for obs in observations:
        by_site_device.setdefault((obs.site_id, obs.device_type), obs)
    for site_id in malicious_sites:
        for (candidate_site, _), template in sorted(by_site_device.items()):
            if candidate_site != site_id:
                continue
            poisoned.append(
                replace(
                    template,
                    fqdn=fake_fqdn,
                    remote_ip=None,
                    protocol=protocol,
                    port=port,
                    timestamp=template.timestamp + timedelta(seconds=1),
                    evidence_type="poisoned_endpoint",
                )
            )
    return poisoned


def inject_persistent_fake_endpoint(
    observations: list[Observation],
    malicious_fraction: float,
    spread_days: int,
    fake_fqdn: str = "evil-c2.net",
    protocol: str = "https",
    port: int = 443,
    seed: int = 42,
) -> list[Observation]:
    """Adaptive variant of ``inject_fake_endpoint``: each malicious site repeats its
    single fake observation across ``spread_days`` distinct days instead of once.

    ``inject_fake_endpoint`` gives each malicious site exactly one fake
    observation, so temporal_confidence for the fake is bounded mostly by how
    many distinct calendar days the malicious sites' own template
    observations happen to fall on -- not by a deliberate persistence choice.
    A bounded poisoner willing to sustain its fake endpoint, rather than
    submit it once, closes that gap directly, the same way
    ``inject_adaptive_sybil_endpoint`` does for the Sybil case. This still
    redistributes a single real template observation rather than fabricating
    new traffic; only the timestamp, per repetition, varies.
    """
    if not 0.0 <= malicious_fraction <= 1.0:
        raise ValueError("malicious_fraction must be in [0, 1]")
    if spread_days < 1:
        raise ValueError("spread_days must be >= 1")
    rng = random.Random(seed)
    sites = sorted({obs.site_id for obs in observations})
    malicious_count = int(round(len(sites) * malicious_fraction))
    malicious_sites = set(rng.sample(sites, malicious_count)) if malicious_count else set()
    poisoned = list(observations)
    by_site_device: dict[tuple[str, str], Observation] = {}
    for obs in observations:
        by_site_device.setdefault((obs.site_id, obs.device_type), obs)
    for site_id in malicious_sites:
        for (candidate_site, _), template in sorted(by_site_device.items()):
            if candidate_site != site_id:
                continue
            for day in range(spread_days):
                poisoned.append(
                    replace(
                        template,
                        fqdn=fake_fqdn,
                        remote_ip=None,
                        protocol=protocol,
                        port=port,
                        timestamp=template.timestamp + timedelta(days=day, seconds=1),
                        evidence_type="poisoned_endpoint_persistent",
                    )
                )
    return poisoned


def inject_sybil_endpoint(
    observations: list[Observation],
    sybil_site_count: int,
    target_device_type: str,
    fake_fqdn: str = "evil-c2.net",
    protocol: str = "https",
    port: int = 443,
    seed: int = 42,
) -> list[Observation]:
    """Coordinated poisoning variant: instead of compromising a fraction of
    *existing* sites (``inject_fake_endpoint``), the adversary registers
    brand-new site identities (Sybils) that exist only to corroborate the
    poisoned endpoint.

    This targets a gap in ``DIBScorer.score()``: site confidence is
    ``supporting_sites / eligible_sites`` with no per-site trust weighting,
    so a site only needs one observation of ``target_device_type`` to count
    toward both the numerator and denominator for the poisoned endpoint.
    Unlike a fraction of compromised real sites, the number of Sybils is not
    bounded by the real site population, so this adversary can in principle
    keep adding identities until the threshold is reached. No traffic is
    fabricated beyond the destination substitution already used by
    ``inject_fake_endpoint``: each Sybil's single observation is a copy of a
    real template for ``target_device_type`` with only the endpoint changed.
    """
    if sybil_site_count < 0:
        raise ValueError("sybil_site_count must be >= 0")
    template = next((obs for obs in observations if obs.device_type == target_device_type), None)
    if template is None:
        raise ValueError(f"no observations found for device_type={target_device_type!r}")
    rng = random.Random(seed)
    poisoned = list(observations)
    for i in range(sybil_site_count):
        poisoned.append(
            replace(
                template,
                site_id=f"sybil-{rng.randrange(10**9)}-{i}",
                fqdn=fake_fqdn,
                remote_ip=None,
                protocol=protocol,
                port=port,
                timestamp=template.timestamp + timedelta(seconds=i + 1),
                evidence_type="poisoned_endpoint_sybil",
            )
        )
    return poisoned


def inject_diversified_sybil_endpoint(
    observations: list[Observation],
    sybil_site_count: int,
    target_device_type: str,
    spread_days: int,
    padding_per_sybil: int,
    fake_fqdn: str = "evil-c2.net",
    protocol: str = "https",
    port: int = 443,
    seed: int = 42,
) -> list[Observation]:
    """Adversarial variant of ``inject_adaptive_sybil_endpoint`` that also pads
    each Sybil with ``padding_per_sybil`` distinct, real, benign-looking
    endpoints already observed for ``target_device_type`` at genuine sites,
    drawn as a different (deterministic) subset per Sybil.

    This targets two specific gaps the vanilla and single-mitigation
    experiments leave open: (1) ``independence_aware`` scoring clusters sites
    by Jaccard similarity of their *full* per-device endpoint set
    (dib/evaluation/independence.py); a templated Sybil whose only
    observation is the shared fake endpoint is identical to every other
    Sybil and they collapse into one cluster regardless of count. Giving each
    Sybil a different padding subset lowers pairwise Jaccard similarity
    without touching the shared poisoned endpoint, which is the actual
    anti-clustering lever an adaptive adversary has available without
    fabricating non-existent traffic. (2) ``trust_weighted`` scoring derives
    each site's weight from ``compute_site_breadth`` (dib/evaluation/trust.py),
    the count of distinct endpoints a site has ever contributed; padding
    raises a Sybil's breadth, and therefore its trust weight, directly.

    No traffic is fabricated beyond what ``inject_sybil_endpoint`` already
    does: padding endpoints are sampled from endpoints genuinely present in
    ``observations`` for ``target_device_type``, never invented.
    """
    if sybil_site_count < 0:
        raise ValueError("sybil_site_count must be >= 0")
    if spread_days < 1:
        raise ValueError("spread_days must be >= 1")
    if padding_per_sybil < 0:
        raise ValueError("padding_per_sybil must be >= 0")
    template = next((obs for obs in observations if obs.device_type == target_device_type), None)
    if template is None:
        raise ValueError(f"no observations found for device_type={target_device_type!r}")
    real_candidates = sorted(
        {
            (obs.fqdn, obs.protocol, obs.port)
            for obs in observations
            if obs.device_type == target_device_type and obs.fqdn and obs.fqdn != fake_fqdn
        }
    )
    rng = random.Random(seed)
    poisoned = list(observations)
    for i in range(sybil_site_count):
        site_id = f"sybil-{rng.randrange(10**9)}-{i}"
        for day in range(spread_days):
            poisoned.append(
                replace(
                    template,
                    site_id=site_id,
                    fqdn=fake_fqdn,
                    remote_ip=None,
                    protocol=protocol,
                    port=port,
                    timestamp=template.timestamp + timedelta(days=day, seconds=i + 1),
                    evidence_type="poisoned_endpoint_sybil_diversified",
                )
            )
        padding_sample = (
            rng.sample(real_candidates, min(padding_per_sybil, len(real_candidates)))
            if real_candidates
            else []
        )
        for j, (padding_fqdn, padding_protocol, padding_port) in enumerate(padding_sample):
            poisoned.append(
                replace(
                    template,
                    site_id=site_id,
                    fqdn=padding_fqdn,
                    remote_ip=None,
                    protocol=padding_protocol,
                    port=padding_port,
                    timestamp=template.timestamp + timedelta(days=0, seconds=10_000 + i * 100 + j),
                    evidence_type="sybil_padding_real_endpoint",
                )
            )
    return poisoned


def inject_overlap_controlled_sybil_endpoint(
    observations: list[Observation],
    sybil_site_count: int,
    target_device_type: str,
    spread_days: int,
    padding_per_sybil: int,
    shared_fraction: float,
    fake_fqdn: str = "evil-c2.net",
    protocol: str = "https",
    port: int = 443,
    seed: int = 42,
) -> tuple[list[Observation], float]:
    """Variant of ``inject_diversified_sybil_endpoint`` with a directly controllable
    diversification lever: instead of sampling each Sybil's padding independently
    (which only loosely controls pairwise similarity), a fixed ``shared_fraction`` of
    each Sybil's ``padding_per_sybil`` real endpoints comes from one common pool
    (identical across all Sybils) and the remainder comes from a per-Sybil rotating
    slice of the rest of the real candidate pool, so the *nominal* shared fraction
    is a direct experiment parameter rather than an indirect consequence of sample
    size. The realized pairwise Jaccard similarity is not guaranteed to equal
    ``shared_fraction`` exactly when the real endpoint pool for ``target_device_type``
    is small relative to ``sybil_site_count`` (rotating slices start repeating), so
    callers should measure achieved similarity from the output (e.g. via
    ``compute_site_endpoint_sets`` + ``jaccard_similarity``) rather than trust the
    nominal value. No traffic is fabricated: every padding endpoint is drawn from
    endpoints genuinely observed for ``target_device_type`` in ``observations``.

    Returns the poisoned observations and the achieved real-candidate-pool-limited
    padding count actually used per Sybil (<=, since the pool may be smaller than
    requested), so callers can report the realized attack budget honestly.
    """
    if sybil_site_count < 0:
        raise ValueError("sybil_site_count must be >= 0")
    if spread_days < 1:
        raise ValueError("spread_days must be >= 1")
    if padding_per_sybil < 0:
        raise ValueError("padding_per_sybil must be >= 0")
    if not 0.0 <= shared_fraction <= 1.0:
        raise ValueError("shared_fraction must be in [0, 1]")
    template = next((obs for obs in observations if obs.device_type == target_device_type), None)
    if template is None:
        raise ValueError(f"no observations found for device_type={target_device_type!r}")
    real_candidates = sorted(
        {
            (obs.fqdn, obs.protocol, obs.port)
            for obs in observations
            if obs.device_type == target_device_type and obs.fqdn and obs.fqdn != fake_fqdn
        }
    )
    rng = random.Random(seed)
    achieved_padding = min(padding_per_sybil, len(real_candidates))
    n_shared = min(round(achieved_padding * shared_fraction), achieved_padding)
    n_unique = achieved_padding - n_shared

    shared_pool = rng.sample(real_candidates, n_shared) if n_shared else []
    remaining_pool = [c for c in real_candidates if c not in set(shared_pool)]
    rng.shuffle(remaining_pool)

    poisoned = list(observations)
    for i in range(sybil_site_count):
        site_id = f"sybil-{rng.randrange(10**9)}-{i}"
        for day in range(spread_days):
            poisoned.append(
                replace(
                    template,
                    site_id=site_id,
                    fqdn=fake_fqdn,
                    remote_ip=None,
                    protocol=protocol,
                    port=port,
                    timestamp=template.timestamp + timedelta(days=day, seconds=i + 1),
                    evidence_type="poisoned_endpoint_sybil_overlap_controlled",
                )
            )
        if remaining_pool:
            start = (i * n_unique) % len(remaining_pool)
            unique_slice = [remaining_pool[(start + j) % len(remaining_pool)] for j in range(n_unique)]
        else:
            unique_slice = []
        for j, (padding_fqdn, padding_protocol, padding_port) in enumerate(shared_pool + unique_slice):
            poisoned.append(
                replace(
                    template,
                    site_id=site_id,
                    fqdn=padding_fqdn,
                    remote_ip=None,
                    protocol=padding_protocol,
                    port=padding_port,
                    timestamp=template.timestamp + timedelta(days=0, seconds=10_000 + i * 100 + j),
                    evidence_type="sybil_padding_real_endpoint",
                )
            )
    return poisoned, achieved_padding


def inject_adaptive_sybil_endpoint(
    observations: list[Observation],
    sybil_site_count: int,
    target_device_type: str,
    spread_days: int,
    fake_fqdn: str = "evil-c2.net",
    protocol: str = "https",
    port: int = 443,
    seed: int = 42,
) -> list[Observation]:
    """Adaptive variant of ``inject_sybil_endpoint``: each Sybil repeats its
    observation across ``spread_days`` distinct days instead of a single
    instant.

    A single-shot Sybil (one observation, one day) can inflate site
    confidence but leaves ``temporal_confidence`` near zero, since
    ``active_day_ratio`` in ``DIBScorer.score()`` is the number of distinct
    days the endpoint is seen divided by the device's total active days
    (commonly in the dozens for real devices). An adversary that adapts by
    sustaining a longer-running campaign closes that gap. This still
    redistributes a single real template observation rather than fabricating
    new traffic; only the timestamp and site identity vary per repetition.
    """
    if sybil_site_count < 0:
        raise ValueError("sybil_site_count must be >= 0")
    if spread_days < 1:
        raise ValueError("spread_days must be >= 1")
    template = next((obs for obs in observations if obs.device_type == target_device_type), None)
    if template is None:
        raise ValueError(f"no observations found for device_type={target_device_type!r}")
    rng = random.Random(seed)
    poisoned = list(observations)
    for i in range(sybil_site_count):
        site_id = f"sybil-{rng.randrange(10**9)}-{i}"
        for day in range(spread_days):
            poisoned.append(
                replace(
                    template,
                    site_id=site_id,
                    fqdn=fake_fqdn,
                    remote_ip=None,
                    protocol=protocol,
                    port=port,
                    timestamp=template.timestamp + timedelta(days=day, seconds=i + 1),
                    evidence_type="poisoned_endpoint_sybil_adaptive",
                )
            )
    return poisoned
