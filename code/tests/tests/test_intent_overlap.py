from __future__ import annotations

from datetime import datetime, timezone

from dib.core.models import Observation
from dib.evaluation.intent_overlap import (
    classify_core,
    endpoint_sets_by_org,
    etld1_of,
    jaccard,
    key_at_granularity,
    pairwise_org_overlap,
    pairwise_org_overlap_at_granularity,
)


def test_classify_core_dns_and_ntp_by_protocol_or_port() -> None:
    assert classify_core("resolver.example", "dns", 5353) == "dns"
    assert classify_core("8.8.8.8", "udp", 53) == "dns"
    assert classify_core("pool.ntp.org", "ntp", 999) == "ntp"
    assert classify_core("time.example", "udp", 123) == "ntp"


def test_classify_core_non_global_ip_veto_precedes_service_class() -> None:
    assert classify_core("192.168.1.1", "udp", 53) == "other"
    assert classify_core("192.0.2.1", "ntp", 123) == "other"
    assert classify_core("[fe80::1]:53", "dns", 53) == "other"


def test_classify_core_update_keyword() -> None:
    assert classify_core("fw-update.vendor.com", "https", 443) == "update"
    assert classify_core("ota.vendor.com", "https", 443) == "update"


def test_classify_core_vendor_cloud_vs_other() -> None:
    assert classify_core("api.vendor.com", "https", 443) == "vendor-cloud"
    assert classify_core("192.168.1.5", "ssdp", 1900) == "other"
    assert classify_core("1.2.3.4", "https", 443) == "other"


def test_jaccard_basic() -> None:
    assert jaccard(set(), set()) == 0.0
    assert jaccard({1, 2}, {1, 2}) == 1.0
    assert jaccard({1, 2}, {2, 3}) == 1 / 3


def _obs(site: str, endpoint: str, protocol: str, port: int) -> Observation:
    return Observation(
        site, "dev", "TestDevice", endpoint, None, protocol, port,
        datetime(2026, 1, 1, tzinfo=timezone.utc), "unit", "flow",
    )


def test_pairwise_org_overlap_core_vs_all() -> None:
    observations = [
        _obs("orgA", "shared-api.vendor.com", "https", 443),
        _obs("orgA", "region-a-cdn.vendor.com", "https", 443),
        _obs("orgB", "shared-api.vendor.com", "https", 443),
        _obs("orgB", "region-b-cdn.vendor.com", "https", 443),
    ]
    endpoint_sets = endpoint_sets_by_org(observations, "TestDevice")
    rows = pairwise_org_overlap(endpoint_sets, "TestDevice")
    assert len(rows) == 1
    row = rows[0]
    assert row.org_a_size == 2 and row.org_b_size == 2
    assert row.intersection_all == 1
    assert row.jaccard_all == round(1 / 3, 6)
    # both endpoints classify as vendor-cloud (FQDN, no dns/ntp/update match),
    # so core sets equal the full sets here -> core Jaccard matches all-Jaccard.
    assert row.jaccard_core == row.jaccard_all


def test_etld1_of_regional_subdomains_collapse_but_ip_literals_stay_distinct() -> None:
    assert etld1_of("www.meethue.com") == "meethue.com"
    assert etld1_of("eu.meethue.com") == "meethue.com"
    assert etld1_of("foo.s3.amazonaws.com") == "amazonaws.com"
    assert etld1_of("192.168.1.5") == "192.168.1.5"


def test_key_at_granularity_exact_is_noop() -> None:
    key = ("PhilipsHue", "www.meethue.com", "https", 443)
    assert key_at_granularity(key, "exact") == key


def test_key_at_granularity_etld1_collapses_regional_subdomains() -> None:
    a = ("PhilipsHue", "eu.meethue.com", "https", 443)
    b = ("PhilipsHue", "us.meethue.com", "https", 443)
    assert key_at_granularity(a, "etld1") == key_at_granularity(b, "etld1")


def test_key_at_granularity_service_class_drops_port_and_identity() -> None:
    a = ("PhilipsHue", "pool.ntp.org", "ntp", 123)
    b = ("PhilipsHue", "time.google.com", "udp", 123)
    assert key_at_granularity(a, "service_class") == key_at_granularity(b, "service_class")
    assert key_at_granularity(a, "service_class") == ("PhilipsHue", "ntp")


def test_pairwise_org_overlap_at_granularity_etld1_raises_overlap() -> None:
    observations = [
        _obs("orgA", "eu.meethue.com", "https", 443),
        _obs("orgB", "us.meethue.com", "https", 443),
    ]
    endpoint_sets = endpoint_sets_by_org(observations, "TestDevice")
    exact_rows = pairwise_org_overlap_at_granularity(endpoint_sets, "TestDevice", "exact")
    etld1_rows = pairwise_org_overlap_at_granularity(endpoint_sets, "TestDevice", "etld1")
    assert exact_rows[0].jaccard == 0.0
    assert etld1_rows[0].jaccard == 1.0
