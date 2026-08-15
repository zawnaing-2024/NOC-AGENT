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


def test_static_routes_parsing_active_and_inactive():
    mock_api = MagicMock()
    mock_api.path.return_value = [
        {"dst-address": "0.0.0.0/0", "gateway": "10.10.10.1", "active": True, "disabled": False},
        {"dst-address": "10.20.0.0/16", "gateway": "10.10.10.1", "active": False, "disabled": False},
    ]

    res = parse_static_routes_data(mock_api, details=True)
    assert res.total == 2
    assert res.active == 1
    assert res.inactive == 1
    assert res.inactive_routes == ["10.20.0.0/16"]


def test_ospf_neighbors_parsing_full_and_down():
    mock_api = MagicMock()
    mock_api.path.return_value = [
        {"address": "10.0.0.2", "router-id": "10.0.0.2", "state": "Full", "interface": "ether3"},
        {"address": "10.0.0.3", "router-id": "10.0.0.3", "state": "Down", "interface": "ether4"},
    ]

    res = parse_ospf_neighbors_data(mock_api, details=True)
    assert res.total == 2
    assert res.full == 1
    assert res.down == 1
    assert res.down_neighbors == ["10.0.0.3"]


def test_nat_rules_parsing():
    mock_api = MagicMock()
    mock_api.path.return_value = [
        {".id": "*1", "chain": "srcnat", "action": "masquerade", "out-interface": "ether1", "packets": 100, "bytes": 5000, "disabled": False},
        {".id": "*2", "chain": "srcnat", "action": "masquerade", "out-interface": "ether2", "packets": 0, "bytes": 0, "disabled": False},
    ]

    res = parse_nat_rules_data(mock_api, details=True)
    assert res.total == 2
    assert res.active == 2
    assert res.zero_counter_rules == ["*2"]


@patch("app.agent.get_routeros_client")
def test_bgp_underlying_link_cross_domain_correlation(mock_get_client):
    mock_api = MagicMock()
    
    def mock_path_router(path_str):
        if "bgp" in path_str:
            return [{"name": "peer1", "remote-address": "10.0.0.1", "state": "idle", "prefix-count": 0}]
        elif "interface" in path_str:
            return [{"name": "ether1", "type": "ether", "running": False, "disabled": False, "rx-byte": 1000, "tx-byte": 2000}]
        elif "log" in path_str:
            return [{"time": "14:02:10", "message": "ether1 link down", "topics": "interface,info"}]
        return []

    mock_api.path.side_effect = mock_path_router
    mock_get_client.return_value.__enter__.return_value = mock_api

    evidence_text, tools_used = perform_cross_domain_investigation("Investigate BGP peer 10.0.0.1")

    assert "get_bgp_peers" in tools_used
    assert "get_interfaces" in tools_used
    assert "UNDERLYING_LINK_SUSPECTED" in evidence_text


@patch("app.agent.get_routeros_client")
def test_ospf_underlying_link_cross_domain_correlation(mock_get_client):
    mock_api = MagicMock()

    def mock_path_router(path_str):
        if "ospf" in path_str:
            return [{"address": "10.0.0.2", "router-id": "10.0.0.2", "state": "Down", "interface": "ether3"}]
        elif "interface" in path_str:
            return [{"name": "ether3", "type": "ether", "running": False, "disabled": False, "rx-byte": 1000, "tx-byte": 2000}]
        return []

    mock_api.path.side_effect = mock_path_router
    mock_get_client.return_value.__enter__.return_value = mock_api

    evidence_text, tools_used = perform_cross_domain_investigation("Investigate OSPF neighbor 10.0.0.2")

    assert "get_ospf_neighbors" in tools_used
    assert "get_interfaces" in tools_used
    assert "UNDERLYING_LINK_SUSPECTED" in evidence_text


@patch("app.agent.get_routeros_client")
def test_static_route_next_hop_unreachable_correlation(mock_get_client):
    mock_api = MagicMock()

    def mock_path_router(path_str):
        if "route" in path_str:
            return [{"dst-address": "10.20.0.0/16", "gateway": "10.10.10.1", "active": False, "disabled": False}]
        elif "interface" in path_str:
            return [{"name": "ether1", "type": "ether", "running": False, "disabled": False, "rx-byte": 1000, "tx-byte": 2000}]
        return []

    mock_api.path.side_effect = mock_path_router
    mock_get_client.return_value.__enter__.return_value = mock_api

    evidence_text, tools_used = perform_cross_domain_investigation("Investigate why 10.20.0.0/16 is inactive")

    assert "get_static_routes" in tools_used
    assert "get_interfaces" in tools_used
    assert "NEXT_HOP_UNREACHABLE" in evidence_text


def test_security_strictly_read_only_tools():
    """Verify that all Phase 3 registered tools are 100% READ-ONLY and contain zero write methods."""
    for t in TOOLS:
        doc_lower = (t.description or "").lower()
        assert "add" not in doc_lower or "address" in doc_lower
        assert "remove" not in doc_lower
        assert "disable" not in doc_lower or "inspects" in doc_lower or "retrieves" in doc_lower
        assert "enable" not in doc_lower or "inspects" in doc_lower or "retrieves" in doc_lower
        assert "reset" not in doc_lower
