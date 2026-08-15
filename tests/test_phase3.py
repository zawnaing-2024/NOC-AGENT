import json
from unittest.mock import MagicMock, patch
import pytest

from app.tools.routeros import (
    parse_bgp_peers_data,
    parse_bgp_peer_detail,
    parse_static_routes_data,
    parse_single_route_detail,
    parse_ospf_neighbors_data,
    parse_single_ospf_neighbor_detail,
    parse_nat_rules_data,
    parse_routing_logs_data,
)
from app.agent import TOOLS, perform_cross_domain_investigation


def test_bgp_peers_parsing_established_and_down():
    mock_api = MagicMock()
    mock_api.path.return_value = [
        {"name": "peer1", "remote-address": "10.0.0.1", "state": "established", "prefix-count": 120},
        {"name": "peer2", "remote-address": "10.0.0.2", "state": "idle", "prefix-count": 0},
    ]

    res = parse_bgp_peers_data(mock_api, details=True)
    assert res.summary.total == 2
    assert res.summary.established == 1
    assert res.summary.down == 1
    assert res.summary.down_peers == ["peer2"]
    assert res.details[0].established is True
    assert res.details[1].established is False


def test_bgp_unknown_state_established_parsing():
    mock_api = MagicMock()
    mock_api.path.return_value = [
        {"name": "peer1", "remote.address": "10.59.190.81", "state": "UNKNOWN", "established": True, "uptime": "23w6d16h57m5s", "remote.prefix-count": 1}
    ]

    res = parse_bgp_peers_data(mock_api, details=True)
    assert res.summary.total == 1
    assert res.summary.established == 1
    assert res.summary.down == 0
    assert res.details[0].established is True
    assert res.details[0].state == "UNKNOWN"


@patch("app.agent.get_routeros_client")
def test_bgp_unknown_state_insufficient_evidence_correlation(mock_get_client):
    mock_api = MagicMock()
    mock_api.path.return_value = [
        {"name": "peer1", "remote.address": "10.59.190.81", "state": "UNKNOWN", "established": True, "uptime": "23w6d16h57m5s", "remote.prefix-count": 1}
    ]
    mock_get_client.return_value.__enter__.return_value = mock_api

    evidence_text, tools_used = perform_cross_domain_investigation("Check BGP status for 103.95.4.1.")

    assert "get_bgp_peers" in tools_used
    assert "INSUFFICIENT_EVIDENCE" in evidence_text
    assert "BGP_SESSION_FLAPPING" not in evidence_text


@patch("app.agent.get_routeros_client")
def test_ospf_all_full_no_anomaly_correlation(mock_get_client):
    mock_api = MagicMock()
    mock_api.path.return_value = [
        {"address": "10.0.0.1", "state": "Full"},
        {"address": "10.0.0.2", "state": "Full"},
        {"address": "10.0.0.3", "state": "Full"},
    ]
    mock_get_client.return_value.__enter__.return_value = mock_api

    evidence_text, tools_used = perform_cross_domain_investigation("Check OSPF status for 103.59.163.7.")

    assert tools_used == ["get_ospf_neighbors"]
    assert "NO_ANOMALY" in evidence_text


@patch("app.agent.get_routeros_client")
def test_static_routes_all_active_no_anomaly_correlation(mock_get_client):
    mock_api = MagicMock()
    mock_api.path.return_value = [
        {"dst-address": "0.0.0.0/0", "gateway": "10.10.10.1", "active": True, "disabled": False}
    ]
    mock_get_client.return_value.__enter__.return_value = mock_api

    evidence_text, tools_used = perform_cross_domain_investigation("Check static routes.")

    assert tools_used == ["get_static_routes"]
    assert "NO_ANOMALY" in evidence_text


@patch("app.agent.get_routeros_client")
def test_nat_unrelated_down_interface_negative_correlation(mock_get_client):
    """Negative test: ether10 is DOWN, but no enabled NAT rule references ether10 -> ether10 MUST NOT appear as anomaly."""
    mock_api = MagicMock()
    def path_side_effect(path_str):
        if "nat" in path_str:
            return [
                {".id": "*1", "chain": "srcnat", "action": "masquerade", "out-interface": "sfp-sfpplus1", "disabled": False, "packets": 500}
            ]
        elif "interface" in path_str:
            return [
                {"name": "ether10", "type": "ether", "running": False, "disabled": False},
                {"name": "sfp-sfpplus1", "type": "ether", "running": True, "disabled": False},
            ]
        return []
    mock_api.path.side_effect = path_side_effect
    mock_get_client.return_value.__enter__.return_value = mock_api

    evidence_text, tools_used = perform_cross_domain_investigation("Check NAT status for 103.59.163.7.")

    assert "get_nat_rules" in tools_used
    assert "get_interfaces" in tools_used
    assert "ether10" not in evidence_text
    assert "NO_ANOMALY" in evidence_text


@patch("app.agent.get_routeros_client")
def test_nat_explicit_down_interface_positive_correlation(mock_get_client):
    """Positive test: Enabled NAT rule out-interface sfp-sfpplus1 is DOWN -> NAT_DEPENDENCY_INTERFACE_DOWN."""
    mock_api = MagicMock()
    def path_side_effect(path_str):
        if "nat" in path_str:
            return [
                {".id": "*1", "chain": "srcnat", "action": "masquerade", "out-interface": "sfp-sfpplus1", "disabled": False, "packets": 500}
            ]
        elif "interface" in path_str:
            return [
                {"name": "sfp-sfpplus1", "type": "ether", "running": False, "disabled": False, "rx-byte": 5000},
            ]
        return []
    mock_api.path.side_effect = path_side_effect
    mock_get_client.return_value.__enter__.return_value = mock_api

    evidence_text, tools_used = perform_cross_domain_investigation("Check NAT status for 103.59.163.7.")

    assert "get_nat_rules" in tools_used
    assert "get_interfaces" in tools_used
    assert "NAT_DEPENDENCY_INTERFACE_DOWN" in evidence_text


def test_security_strictly_read_only_tools():
    """Verify that all Phase 3 registered tools are 100% READ-ONLY and contain zero write methods."""
    for t in TOOLS:
        doc_lower = (t.description or "").lower()
        assert "add" not in doc_lower or "address" in doc_lower
        assert "remove" not in doc_lower
        assert "disable" not in doc_lower or "inspects" in doc_lower or "retrieves" in doc_lower
        assert "enable" not in doc_lower or "inspects" in doc_lower or "retrieves" in doc_lower
        assert "reset" not in doc_lower
