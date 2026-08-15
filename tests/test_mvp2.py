import json
from unittest.mock import MagicMock, patch
import pytest

from app.tools.routeros import (
    get_interface_detail,
    get_interface_logs,
    get_interface_traffic,
    parse_single_interface_detail,
    parse_interface_logs,
    parse_interface_traffic,
)
from app.agent import perform_cross_domain_investigation


def test_get_interface_detail_success():
    mock_api = MagicMock()
    mock_api.path.return_value = [
        {
            "name": "ether8",
            "type": "ether",
            "running": False,
            "disabled": False,
            "mtu": 1500,
            "actual-mtu": 1500,
            "mac-address": "00:0C:29:11:22:33",
            "rx-byte": 10000,
            "tx-byte": 20000,
            "rx-error": 0,
            "tx-error": 0,
            "rx-drop": 0,
            "tx-drop": 0,
            "link-downs": 2,
        }
    ]

    detail = parse_single_interface_detail(mock_api, "ether8")
    assert detail.name == "ether8"
    assert detail.running is False
    assert detail.disabled is False
    assert detail.mac_address == "00:0C:29:11:22:33"
    assert detail.link_downs == 2


def test_get_interface_detail_missing_optional_fields():
    mock_api = MagicMock()
    mock_api.path.return_value = [
        {
            "name": "ether8",
            "type": "ether",
            "running": False,
            "disabled": False,
        }
    ]

    detail = parse_single_interface_detail(mock_api, "ether8")
    assert detail.name == "ether8"
    assert detail.mac_address is None
    assert detail.link_downs is None
    assert detail.rx_bytes == 0


def test_get_interface_logs_matching_and_empty():
    mock_api = MagicMock()
    mock_api.path.return_value = [
        {"time": "14:02:10", "message": "ether8 link down", "topics": "interface,info"},
        {"time": "14:02:15", "message": "ether8 link up", "topics": "interface,info"},
        {"time": "14:03:00", "message": "ether1 link up", "topics": "interface,info"},
    ]

    logs_resp = parse_interface_logs(mock_api, "ether8")
    assert logs_resp.interface == "ether8"
    assert len(logs_resp.events) == 2
    assert logs_resp.events[0].timestamp == "14:02:10"
    assert "link down" in logs_resp.events[0].message

    empty_logs = parse_interface_logs(mock_api, "ether9")
    assert empty_logs.interface == "ether9"
    assert len(empty_logs.events) == 0


def test_get_interface_traffic():
    mock_api = MagicMock()
    mock_api.path.return_value = [
        {
            "name": "ether8",
            "rx-byte": 500000,
            "tx-byte": 900000,
            "rx-packet": 5000,
            "tx-packet": 9000,
            "rx-error": 0,
            "tx-error": 0,
            "rx-drop": 0,
            "tx-drop": 0,
        }
    ]

    traffic = parse_interface_traffic(mock_api, "ether8")
    assert traffic.interface == "ether8"
    assert traffic.rx_bytes == 500000
    assert traffic.tx_bytes == 900000


@patch("app.agent.get_routeros_client")
def test_perform_cross_domain_investigation_flow(mock_get_client):
    mock_api = MagicMock()
    mock_api.path.side_effect = lambda path: [
        {
            "name": "ether8",
            "type": "ether",
            "running": False,
            "disabled": False,
            "rx-byte": 50000,  # LINK_DOWN
            "tx-byte": 80000,
            "time": "14:02:10",
            "message": "ether8 link down",
        }
    ]
    mock_get_client.return_value.__enter__.return_value = mock_api

    evidence_text, tools_used = perform_cross_domain_investigation("Investigate the link down interface")

    assert "get_interfaces" in tools_used
    assert "get_interface_detail" in tools_used
    assert "ether8" in evidence_text
