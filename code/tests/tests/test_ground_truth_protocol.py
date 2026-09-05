from dib.evaluation.ground_truth_protocol import coverage_rows, protocol_summary


def test_protocol_summary_exposes_unobserved_reference_and_matching_rules() -> None:
    truth = {
        "camera": {("camera", "from-device", "api.example", "tcp", 443)},
        "chromecast": {("chromecast", "from-device", "192.0.2.0/24", "udp", 0)},
    }
    summary = protocol_summary(truth, {"camera"})
    assert summary["unobserved_reference_devices"] == ["chromecast"]
    assert summary["direction_available_in_observation_schema"] is True
    # rule_count_by_match_kind must classify the *endpoint* field (index 2),
    # not the direction field (index 1) -- regression for the indexing bug
    # this test caught when EndpointKey grew a direction field.
    assert summary["rule_count_by_match_kind"] == {"cidr": 1, "literal": 1}
    rows = coverage_rows(truth, {"camera"})
    chromecast = next(row for row in rows if row["device_type"] == "chromecast")
    assert chromecast["evaluation_prediction_policy"] == "empty"
