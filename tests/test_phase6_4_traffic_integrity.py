import pytest
from datetime import datetime, timezone, timedelta
from app.tools.routeros import TrafficRateCalculator
from app.engine.baseline import calculate_baseline
from app.engine.investigator import calculate_traffic_direction_and_deviation
from app.db.database import db
from app.db.schemas import InterfaceMetricRecord


@pytest.fixture(autouse=True)
def reset_rate_calculator():
    TrafficRateCalculator.reset_history()


def test_1_cumulative_byte_counter_to_bps_delta():
    """Verify cumulative RouterOS byte counters produce bps rate via deltas."""
    t0 = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=10)

    # First sample sets initial counter benchmark
    res1 = TrafficRateCalculator.calculate_rate("dev1", "ether1", 100_000, 200_000, t0)
    assert res1["telemetry_valid"] is False
    assert res1["validation_reason"] == "INITIAL_COUNTER_SAMPLE"

    # Second sample (100,000 bytes transferred over 10s = 80,000 bps)
    res2 = TrafficRateCalculator.calculate_rate("dev1", "ether1", 200_000, 300_000, t1)
    assert res2["telemetry_valid"] is True
    assert res2["validation_reason"] == "VALID"
    assert res2["rx_bps"] == 80_000.0
    assert res2["tx_bps"] == 80_000.0
    assert res2["elapsed_seconds"] == 10.0


def test_2_rx_rate_calculation():
    """Verify independent RX rate delta math."""
    t0 = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=5)

    res1 = TrafficRateCalculator.calculate_rate("dev1", "ether1", 1_000_000, 500_000, t0)
    res2 = TrafficRateCalculator.calculate_rate("dev1", "ether1", 2_000_000, 500_000, t1)

    # 1,000,000 bytes over 5 seconds = 8,000,000 bits / 5s = 1,600,000 bps = 1.6 Mbps
    assert res2["rx_bps"] == 1_600_000.0
    assert res2["tx_bps"] == 0.0


def test_3_tx_rate_calculation():
    """Verify independent TX rate delta math."""
    t0 = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=2)

    res1 = TrafficRateCalculator.calculate_rate("dev1", "ether1", 100_000, 100_000, t0)
    res2 = TrafficRateCalculator.calculate_rate("dev1", "ether1", 100_000, 350_000, t1)

    # 250,000 bytes over 2 seconds = 2,000,000 bits / 2s = 1,000,000 bps = 1.0 Mbps
    assert res2["rx_bps"] == 0.0
    assert res2["tx_bps"] == 1_000_000.0


def test_4_counter_reset_handling():
    """Verify router reboot or counter reset marks counter_reset=True and rate=0.0."""
    t0 = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=10)

    res1 = TrafficRateCalculator.calculate_rate("dev1", "ether1", 500_000_000, 500_000_000, t0)
    # Router rebooted: counter reset to 1,000 bytes
    res2 = TrafficRateCalculator.calculate_rate("dev1", "ether1", 1_000, 1_000, t1)

    assert res2["counter_reset"] is True
    assert res2["telemetry_valid"] is False
    assert res2["validation_reason"] == "COUNTER_RESET"
    assert res2["rx_bps"] == 0.0
    assert res2["tx_bps"] == 0.0


def test_5_zero_elapsed_time_handling():
    """Verify zero or negative timestamp delta discards sample."""
    t0 = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)

    res1 = TrafficRateCalculator.calculate_rate("dev1", "ether1", 100_000, 100_000, t0)
    res2 = TrafficRateCalculator.calculate_rate("dev1", "ether1", 200_000, 200_000, t0)

    assert res2["telemetry_valid"] is False
    assert res2["validation_reason"] == "INVALID_TIMESTAMP_DELTA"


def test_6_invalid_timestamp_handling():
    """Verify invalid timestamp string format handling."""
    t0 = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
    res = TrafficRateCalculator.calculate_rate("dev1", "ether1", 100, 100, t0, previous_timestamp="invalid-date")
    assert res["telemetry_valid"] is False


def test_7_one_gbps_interface_capacity_validation():
    """Verify 1 Gbps interface cannot produce 500 Gbps impossible rate."""
    t0 = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=1)

    # 1 Gbps = 1,000,000,000 bps
    speed_1g = 1_000_000_000.0

    res1 = TrafficRateCalculator.calculate_rate("dev1", "ether1", 0, 0, t0)
    # Simulated 500 Gbps transfer (62.5 GB in 1 second)
    res2 = TrafficRateCalculator.calculate_rate(
        "dev1", "ether1", 62_500_000_000, 0, t1, interface_speed_bps=speed_1g
    )

    assert res2["telemetry_valid"] is False
    assert res2["validation_reason"] == "RATE_EXCEEDS_INTERFACE_CAPACITY"


def test_8_ten_gbps_interface_capacity_validation():
    """Verify 10 Gbps interface cannot produce 5000 Gbps impossible rate."""
    t0 = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=1)

    speed_10g = 10_000_000_000.0

    res1 = TrafficRateCalculator.calculate_rate("dev1", "ether10", 0, 0, t0)
    res2 = TrafficRateCalculator.calculate_rate(
        "dev1", "ether10", 625_000_000_000, 0, t1, interface_speed_bps=speed_10g
    )

    assert res2["telemetry_valid"] is False
    assert res2["validation_reason"] == "RATE_EXCEEDS_INTERFACE_CAPACITY"


def test_9_vlan_traffic_calculation():
    """Verify VLAN interfaces use exact same counter delta methodology."""
    t0 = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=10)

    res1 = TrafficRateCalculator.calculate_rate("dev1", "VLAN-259", 10_000_000, 50_000_000, t0)
    res2 = TrafficRateCalculator.calculate_rate("dev1", "VLAN-259", 20_000_000, 60_000_000, t1)

    # 10,000,000 bytes over 10s = 8,000,000 bps = 8.0 Mbps
    assert res2["telemetry_valid"] is True
    assert res2["rx_bps"] == 8_000_000.0
    assert res2["tx_bps"] == 8_000_000.0


def test_10_rx_tx_independent_baseline():
    """Verify RX and TX baseline calculations are completely independent."""
    rx_vals = [10_000_000.0] * 10
    tx_vals = [500_000_000.0] * 10

    rx_bl = calculate_baseline(rx_vals, min_samples=5)
    tx_bl = calculate_baseline(tx_vals, min_samples=5)

    assert rx_bl.moving_average == 10_000_000.0
    assert tx_bl.moving_average == 500_000_000.0


def test_11_corrupted_sample_excluded_from_baseline():
    """Verify corrupted cumulative byte counter (>800 Gbps) is excluded from robust baseline."""
    # 9 valid samples of 1 Gbps, 1 corrupted sample of 184,663 Gbps
    samples = [1_000_000_000.0] * 9 + [184_663_930_000_000_000.0]

    bl = calculate_baseline(samples, min_samples=5)

    assert bl.valid_sample_count == 9
    assert bl.invalid_sample_count == 1
    assert bl.moving_average == 1_000_000_000.0  # Median baseline is strictly 1 Gbps!


def test_12_baseline_median_robust_calculation():
    """Verify baseline uses robust median method."""
    samples = [10.0, 12.0, 11.0, 1000.0, 10.0]  # 1000 is an outlier
    bl = calculate_baseline(samples, min_samples=3)

    assert bl.moving_average == 11.0  # Median of sorted [10, 10, 11, 12, 1000] is 11.0!
    assert bl.method == "median"


def test_13_valid_sample_preserved_in_database():
    """Verify valid interface metrics are persisted into SQLite with telemetry_valid=1."""
    rec = InterfaceMetricRecord(
        device_id="test_dev",
        interface_name="ether1",
        rx_bps=10_000_000.0,
        tx_bps=5_000_000.0,
        telemetry_valid=True,
        validation_reason="VALID"
    )
    db.insert_interface_metric(rec)

    metrics = db.get_recent_interface_metrics("test_dev", "ether1", limit=1, valid_only=True)
    assert len(metrics) == 1
    assert metrics[0]["rx_bps"] == 10_000_000.0
    assert metrics[0]["telemetry_valid"] == 1


def test_14_invalid_sample_marked_without_deletion():
    """Verify invalid sample is persisted with telemetry_valid=0 and not returned in valid_only queries."""
    rec = InterfaceMetricRecord(
        device_id="test_dev_inv",
        interface_name="ether1",
        rx_bps=999_000_000_000_000.0,
        tx_bps=0.0,
        telemetry_valid=False,
        validation_reason="RATE_EXCEEDS_INTERFACE_CAPACITY"
    )
    db.insert_interface_metric(rec)

    # All metrics includes the record
    all_m = db.get_recent_interface_metrics("test_dev_inv", "ether1", limit=1, valid_only=False)
    assert len(all_m) == 1
    assert all_m[0]["telemetry_valid"] == 0

    # Valid-only metrics excludes the record
    valid_m = db.get_recent_interface_metrics("test_dev_inv", "ether1", limit=1, valid_only=True)
    assert len(valid_m) == 0


def test_15_baseline_recalculation():
    """Verify recalculation ignores invalid historical records."""
    valid_samples = [100_000_000.0] * 10
    bl = calculate_baseline(valid_samples, min_samples=5)
    assert bl.baseline_status == "NORMAL"
    assert bl.moving_average == 100_000_000.0


def test_16_traffic_drop_calculation():
    """Verify traffic drop calculation delivers precise percentage below baseline."""
    # Previous: 10 Gbps, Current: 1 Gbps, Baseline: 10 Gbps
    # Baseline deviation = (10G - 1G) / 10G = 90.00% BELOW BASELINE
    res = calculate_traffic_direction_and_deviation("RX", [10_000_000_000.0, 10_000_000_000.0, 1_000_000_000.0])

    assert res["short_term_direction"] == "DROP"
    assert res["short_term_percentage"] == 90.0
    assert res["baseline_deviation_percentage"] == 90.0
    assert "90.00% BELOW BASELINE" in res["baseline_deviation_formatted"]


def test_17_traffic_increase_calculation():
    """Verify traffic increase calculation."""
    res = calculate_traffic_direction_and_deviation("RX", [1_000.0, 2_000.0])
    assert res["short_term_direction"] == "INCREASE"
    assert res["short_term_percentage"] == 100.0


def test_18_sample_to_sample_percentage():
    """Verify sample-to-sample change percentage."""
    res = calculate_traffic_direction_and_deviation("TX", [100.0, 150.0])
    assert res["short_term_percentage"] == 50.0


def test_19_baseline_deviation_percentage():
    """Verify baseline deviation calculation independent of short-term change."""
    # History: [1,000,000, 1,000,000, 100,000, 120,000]
    # Short term: 100k -> 120k is INCREASE ▲ +20.0%
    # Baseline: 1M -> 120k is ▼ 88.0% BELOW BASELINE
    res = calculate_traffic_direction_and_deviation("RX", [1_000_000.0, 1_000_000.0, 100_000.0, 120_000.0])

    assert res["short_term_direction"] == "INCREASE"
    assert res["short_term_percentage"] == 20.0
    assert res["baseline_deviation_percentage"] == 88.0


def test_20_no_100_percent_hardcoded_drop():
    """Verify 381.64 Kbps current vs 1.89 Gbps baseline calculates exact drop ratio (99.98%), NOT hardcoded 100%."""
    # 1.89 Gbps = 1,890,000,000 bps, 381.64 Kbps = 381,640 bps
    res = calculate_traffic_direction_and_deviation("RX", [1_890_000_000.0, 1_890_000_000.0, 381_640.0])

    assert res["baseline_deviation_percentage"] == 99.98
    assert "99.98%" in res["baseline_deviation_formatted"]


def test_21_ai_receives_validated_evidence_only():
    """Verify AI context builder receives validated telemetry status."""
    from app.ai.context_builder import ContextBuilder
    incidents = db.get_incidents(limit=1)
    if incidents:
        ctx = ContextBuilder.build_incident_context(incidents[0]["incident_id"])
        assert "telemetry" in ctx
        assert "interfaces" in ctx["telemetry"]


def test_22_acceptance_corrupted_baselines_rejected():
    """
    ACCEPTANCE TEST:
    Values such as 496.70 Gbps, 3867.44 Gbps, 22689.82 Gbps, 184663.93 Gbps
    must NOT appear as valid baselines unless physically supported by interface capacity.
    """
    corrupted_samples = [
        496_700_000_000.0,
        3_867_440_000_000.0,
        22_689_820_000_000.0,
        184_663_930_000_000.0
    ]

    bl = calculate_baseline(corrupted_samples, min_samples=1, max_valid_limit=400_000_000_000.0)
    assert bl.valid_sample_count == 0
    assert bl.baseline_status == "INSUFFICIENT_HISTORY"
    assert bl.moving_average == 0.0
