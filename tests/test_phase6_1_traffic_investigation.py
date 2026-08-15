import pytest
from unittest.mock import patch, MagicMock

from app.engine.investigator import DeepNocInvestigator
from app.db.database import db
from app.db.schemas import InterfaceMetricRecord


@pytest.fixture(autouse=True)
def setup_test_data():
    db.init_db()
    with db.get_connection() as conn:
        conn.execute("DELETE FROM interface_metrics")
        conn.commit()

    # Seed traffic drop metrics history for sfp-sfpplus1
    # Samples: 8.0 Gbps -> 7.9 Gbps -> 2.0 Gbps (SHARP drop)
    db.insert_interface_metric(InterfaceMetricRecord(
        device_id="103.59.163.7",
        interface_name="sfp-sfpplus1",
        rx_bps=8000000000.0,
        tx_bps=7800000000.0,
        running=1
    ))
    db.insert_interface_metric(InterfaceMetricRecord(
        device_id="103.59.163.7",
        interface_name="sfp-sfpplus1",
        rx_bps=7900000000.0,
        tx_bps=7700000000.0,
        running=1
    ))
    db.insert_interface_metric(InterfaceMetricRecord(
        device_id="103.59.163.7",
        interface_name="sfp-sfpplus1",
        rx_bps=2000000000.0,
        tx_bps=7600000000.0,
        running=1
    ))
    yield


def test_traffic_drop_magnitude_and_sharp_classification():
    """Verify magnitude, percentage, RX/TX separation, and SHARP drop classification."""
    t_inv = DeepNocInvestigator._investigate_traffic_drop_and_interface("103.59.163.7", "sfp-sfpplus1")

    assert t_inv["interface_name"] == "sfp-sfpplus1"
    assert t_inv["device_id"] == "103.59.163.7"

    rx_ch = t_inv["rx_traffic_change"]
    assert rx_ch["previous_bps"] == 7900000000.0
    assert rx_ch["current_bps"] == 2000000000.0
    assert rx_ch["absolute_drop_bps"] == 5900000000.0
    assert rx_ch["percentage_drop"] > 70.0
    assert rx_ch["rate_classification"] == "SHARP"
    assert rx_ch["severity"] in ["SEVERE", "CRITICAL"]

    tx_ch = t_inv["tx_traffic_change"]
    assert tx_ch["previous_bps"] == 7700000000.0
    assert tx_ch["current_bps"] == 7600000000.0
    assert tx_ch["percentage_drop"] < 10.0
    assert tx_ch["severity"] == "NORMAL"


@patch("app.tools.routeros.get_routeros_client")
def test_traffic_drop_decision_tree_and_ip_ping(mock_client_ctx):
    """Verify decision tree path, IP address query, ping test, and optical monitor execution."""
    mock_api = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value = mock_api
    mock_client_ctx.return_value = mock_ctx

    # Mock /interface
    mock_api.path.return_value = [
        {"name": "sfp-sfpplus1", "type": "ether", "running": True, "disabled": False}
    ]

    with patch("app.tools.routeros.query_interface_ip_address") as mock_ip, \
         patch("app.tools.routeros.query_interface_ping_test") as mock_ping, \
         patch("app.tools.routeros.query_interface_optical_power") as mock_opt:

        mock_ip.return_value = {"has_ip": True, "ip_address": "10.59.190.6", "cidr": "10.59.190.6/30"}
        mock_ping.return_value = {"reachable": True, "destination": "10.59.190.5", "loss_percent": 0.0, "avg_latency_ms": 1.8}
        mock_opt.return_value = {"supported": True, "sfp_rx_power_dbm": "-2.15", "sfp_tx_power_dbm": "-2.21"}

        t_inv = DeepNocInvestigator._investigate_traffic_drop_and_interface("103.59.163.7", "sfp-sfpplus1")

        path = t_inv["decision_tree_path"]
        assert "START_TRAFFIC_DROP_INVESTIGATION" in path
        assert "CALCULATE_TRAFFIC_DECREASE" in path
        assert "CHECK_INTERFACE_STATE" in path
        assert "INTERFACE_STATE_UP" in path
        assert "HAS_IP_TRUE" in path
        assert "PING_REACHABLE_OK" in path
