import pytest
from app.engine.investigator import (
    calculate_traffic_direction_and_deviation,
    DeepNocInvestigator
)


def test_previous_to_current_increase_math():
    """Verify 736 bps -> 887 bps is reported as ▲ +20.52% INCREASE, NOT a drop."""
    res = calculate_traffic_direction_and_deviation("RX", [736.0, 887.0])
    assert res["short_term_direction"] == "INCREASE"
    assert res["short_term_percentage"] == 20.52
    assert "▲ +20.52%" in res["short_term_formatted"]


def test_previous_to_current_decrease_math():
    """Verify sample decrease direction and percentage."""
    res = calculate_traffic_direction_and_deviation("RX", [1000.0, 500.0])
    assert res["short_term_direction"] == "DROP"
    assert res["short_term_percentage"] == 50.0
    assert "▼ -50.00%" in res["short_term_formatted"]


def test_user_example_366_to_530():
    res = calculate_traffic_direction_and_deviation("TX", [366.0, 530.0])
    assert res["short_term_direction"] == "INCREASE"
    assert res["short_term_percentage"] == 44.81


def test_baseline_deviation_separation():
    """Verify short-term change and baseline deviation are calculated separately."""
    values = [1_890_000_000.0, 736.0, 887.0]
    res = calculate_traffic_direction_and_deviation("RX", values)

    assert res["short_term_direction"] == "INCREASE"
    assert res["short_term_percentage"] == 20.52
    assert "BELOW BASELINE" in res["baseline_deviation_formatted"]
    assert res["baseline_deviation_percentage"] > 90.0


def test_rx_and_tx_separation():
    """Verify RX and TX metrics are calculated completely independently."""
    rx_res = calculate_traffic_direction_and_deviation("RX", [100.0, 200.0])
    tx_res = calculate_traffic_direction_and_deviation("TX", [500.0, 100.0])

    assert rx_res["short_term_direction"] == "INCREASE"
    assert tx_res["short_term_direction"] == "DROP"
    assert rx_res["direction"] == "RX"
    assert tx_res["direction"] == "TX"


def test_routeros_authentication_failure_blocks_dependent_steps(monkeypatch):
    """Verify RouterOS auth failure halts investigation, marks dependent steps as SKIPPED, and returns INSUFFICIENT_EVIDENCE."""
    def mock_failing_client(*args, **kwargs):
        raise RuntimeError("Authentication failed for MikroTik router.")

    monkeypatch.setattr("app.tools.routeros.get_routeros_client", mock_failing_client)

    res = DeepNocInvestigator._investigate_traffic_drop_and_interface("103.59.163.7", "ether11")

    assert res["routeros_authenticated"] is False
    assert res["routeros_status"] == "FAILED"
    assert res["evidence_completeness"] == "INCOMPLETE"
    assert res["evidence_confidence"] == "LOW"
    assert res["investigation_conclusion"] == "INSUFFICIENT_EVIDENCE"

    step_map = {s["step_id"]: s for s in res["steps"]}
    assert step_map["ROUTEROS_AUTHENTICATION"]["status"] == "FAILED"
    assert step_map["INTERFACE_STATE"]["status"] == "SKIPPED"
    assert step_map["MEDIA_CLASSIFICATION"]["status"] == "SKIPPED"
    assert step_map["IP_ADDRESS_CHECK"]["status"] == "SKIPPED"
    assert step_map["CONNECTIVITY_PING"]["status"] == "SKIPPED"
    assert step_map["OPTICAL_POWER_MONITOR"]["status"] == "NOT_APPLICABLE"

    assert "ROUTEROS_AUTHENTICATION_FAILED" in res["decision_tree_path"]
    assert "INVESTIGATION_HALTED" in res["decision_tree_path"]


class MockPath:
    def __init__(self, items):
        self.items = items
    def __iter__(self):
        return iter(self.items)
    def __call__(self, *args, **kwargs):
        return self.items


def test_unknown_media_type_safety_no_false_optical_recommendations(monkeypatch):
    """Verify UNKNOWN media type prevents optical recommendations."""
    mock_items = [{"name": "ether11", "type": "ether", "running": True, "disabled": False}]

    class MockApi:
        def path(self, p): return MockPath(mock_items)

    monkeypatch.setattr("app.tools.routeros.get_routeros_client", lambda **kwargs: MockApiContext(MockApi()))
    monkeypatch.setattr("app.tools.routeros.query_interface_optical_power", lambda api, iface: {"supported": False})
    monkeypatch.setattr("app.tools.routeros.classify_interface_media", lambda raw, opt: {
        "media_type": "UNKNOWN",
        "confidence": "LOW",
        "reason": "Insufficient RouterOS evidence",
        "optical_capable": False
    })

    res = DeepNocInvestigator._investigate_traffic_drop_and_interface("103.59.163.7", "ether11")
    assert res["media_classification"]["media_type"] == "UNKNOWN"

    recs_str = str(res["recommendations"])
    assert "Optical-specific troubleshooting has been skipped" in recs_str
    assert "Inspect physical optical fiber" not in recs_str


def test_electrical_media_investigation(monkeypatch):
    """Verify ELECTRICAL copper media produces copper troubleshooting recommendations."""
    mock_items = [{"name": "ether11", "type": "ether", "running": True, "disabled": False}]

    class MockApi:
        def path(self, p): return MockPath(mock_items)

    monkeypatch.setattr("app.tools.routeros.get_routeros_client", lambda **kwargs: MockApiContext(MockApi()))
    monkeypatch.setattr("app.tools.routeros.query_interface_optical_power", lambda api, iface: {"supported": False})
    monkeypatch.setattr("app.tools.routeros.classify_interface_media", lambda raw, opt: {
        "media_type": "ELECTRICAL",
        "confidence": "HIGH",
        "reason": "Copper electrical ethernet port",
        "optical_capable": False
    })

    res = DeepNocInvestigator._investigate_traffic_drop_and_interface("103.59.163.7", "ether11")
    assert res["media_classification"]["media_type"] == "ELECTRICAL"

    recs_str = str(res["recommendations"])
    assert "copper rj45" in recs_str.lower()
    assert "speed, duplex" in recs_str.lower()


def test_canonical_interface_state_no_contradiction(monkeypatch):
    """Verify canonical interface state is consistent (UP, DOWN, or DISABLED)."""
    mock_items = [{"name": "ether1", "type": "ether", "running": False, "disabled": False, "link-downs": 0}]

    class MockApi:
        def path(self, p): return MockPath(mock_items)

    monkeypatch.setattr("app.tools.routeros.get_routeros_client", lambda **kwargs: MockApiContext(MockApi()))
    monkeypatch.setattr("app.tools.routeros.query_interface_optical_power", lambda api, iface: {"supported": False})

    res = DeepNocInvestigator._investigate_traffic_drop_and_interface("103.59.163.7", "ether1")
    assert res["interface_state"]["canonical_state"] == "DOWN"
    assert res["interface_state"]["running"] is False
    assert res["investigation_conclusion"] == "ROOT_CAUSE_CONFIRMED"


def test_severity_confidence_separation():
    """Verify evidence confidence values are strictly HIGH/MEDIUM/LOW, never CRITICAL."""
    ctx = {
        "device_metrics": [{"cpu_percent": 90.0, "memory_percent": 80.0}],
        "interface_metrics": [{"interface_name": "ether1", "running": 1, "rx_bps": 1000}],
        "correlated_events": []
    }
    evidence = DeepNocInvestigator._build_human_readable_evidence(ctx, "INTERFACE_DOWN", "ether1")
    for row in evidence:
        assert row["confidence"] in ["HIGH", "MEDIUM", "LOW"]
        assert row["confidence"] != "CRITICAL"


class MockApiContext:
    def __init__(self, api): self.api = api
    def __enter__(self): return self.api
    def __exit__(self, *args): pass
