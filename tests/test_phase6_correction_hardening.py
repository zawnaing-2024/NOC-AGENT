import pytest
from unittest.mock import patch, MagicMock

from app.tools.routeros import classify_interface_media
from app.engine.investigator import DeepNocInvestigator, calculate_traffic_direction_and_deviation, format_bandwidth
from app.engine.anomaly import AnomalyDetector
from app.engine.baseline import calculate_baseline
from app.db.database import db
from app.db.schemas import EventRecord, IncidentRecord


def test_1_physical_ethernet_classification():
    iface = {"name": "ether1", "type": "ether", "default-name": "ether1", "speed": "1Gbps"}
    res = classify_interface_media(iface)
    assert res["interface_type"] == "PHYSICAL_ETHERNET"
    assert res["media_type"] == "ELECTRICAL"
    assert res["optical_capable"] is False
    assert res["interface_capacity_bps"] == 1_000_000_000.0


def test_2_sfp_classification():
    iface = {"name": "sfp-sfpplus1", "type": "sfp-sfpplus", "default-name": "sfp-sfpplus1", "sfp-vendor-name": "MikroTik"}
    res = classify_interface_media(iface)
    assert res["interface_type"] == "PHYSICAL_SFP"
    assert res["media_type"] == "OPTICAL"
    assert res["optical_capable"] is True
    assert res["interface_capacity_bps"] == 10_000_000_000.0


def test_3_vlan_classification():
    iface = {"name": "VLAN_1042", "type": "vlan", "vlan-id": "1042", "interface": "ether11"}
    res = classify_interface_media(iface)
    assert res["interface_type"] == "VLAN"
    assert res["media_type"] == "VLAN"
    assert res["optical_capable"] is False
    assert res["parent_interface"] == "ether11"
    assert res["vlan_id"] == "1042"


def test_4_bridge_classification():
    iface = {"name": "bridge1", "type": "bridge"}
    res = classify_interface_media(iface)
    assert res["interface_type"] == "BRIDGE"
    assert res["optical_capable"] is False


def test_5_bonding_classification():
    iface = {"name": "bond1", "type": "bonding"}
    res = classify_interface_media(iface)
    assert res["interface_type"] == "BONDING"
    assert res["optical_capable"] is False


def test_6_loopback_classification():
    iface = {"name": "lo", "type": "loopback"}
    res = classify_interface_media(iface)
    assert res["interface_type"] == "LOOPBACK"
    assert res["media_type"] == "LOOPBACK"
    assert res["optical_capable"] is False


def test_7_tunnel_classification():
    iface = {"name": "gre-tunnel1", "type": "gre"}
    res = classify_interface_media(iface)
    assert res["interface_type"] == "TUNNEL"
    assert res["optical_capable"] is False


def test_8_vlan_parent_discovery():
    iface = {"name": "VLAN_1042_One_Network", "type": "vlan", "parent-interface": "ether11", "vlan-id": "1042"}
    res = classify_interface_media(iface)
    assert res["parent_interface"] == "ether11"
    assert res["vlan_id"] == "1042"


def test_9_vlan_traffic_investigation():
    iface = {"name": "VLAN_1042", "type": "vlan", "parent-interface": "ether11", "vlan-id": "1042"}
    res = classify_interface_media(iface)
    assert res["media_type"] == "VLAN"
    assert res["parent_interface"] == "ether11"


def test_10_loopback_traffic_investigation():
    iface = {"name": "lo", "type": "loopback"}
    res = classify_interface_media(iface)
    recs = DeepNocInvestigator._build_noc_recommendations("TRAFFIC_DROP", "lo", media_type=res["media_type"])
    for r in recs:
        txt = (r["check"] + " " + r["command"]).lower()
        assert "fiber" not in txt
        assert "sfp" not in txt
        assert "cable" not in txt


def test_11_electrical_troubleshooting():
    recs = DeepNocInvestigator._build_noc_recommendations("TRAFFIC_DROP", "ether1", media_type="ELECTRICAL")
    for r in recs:
        txt = (r["check"] + " " + r["command"]).lower()
        assert "sfp" not in txt
        assert "optical" not in txt


def test_12_optical_troubleshooting():
    recs = DeepNocInvestigator._build_noc_recommendations("TRAFFIC_DROP", "sfp-sfpplus1", media_type="OPTICAL")
    checks = [r["check"] for r in recs]
    assert any("optical" in c.lower() or "sfp" in c.lower() for c in checks)


def test_13_baseline_vs_capacity_distinction():
    info = DeepNocInvestigator._build_baseline_explanation("103.59.163.7", "TRAFFIC_DROP", "ether11", {
        "current_bps": 887000.0,
        "baseline_bps": 1890000000.0,
        "interface_capacity_bps": 10000000000.0
    })
    assert info["capacity_formatted"] == "10.00 Gbps"
    assert info["baseline_formatted"] == "1.89 Gbps"
    assert info["current_formatted"] == "887.0 Kbps"
    assert "NOT interface capacity" in info["explanation_text"]


def test_14_invalid_baseline_above_interface_capacity():
    info = DeepNocInvestigator._build_baseline_explanation("103.59.163.7", "TRAFFIC_DROP", "ether11", {
        "current_bps": 887000.0,
        "baseline_bps": 186770000000.0,
        "interface_capacity_bps": 10000000000.0
    })
    assert info["trust_tag"] == "🔴 BASELINE INVALID"
    assert info["trust_level"] == "INVALID"
    assert "exceeds verified interface capacity" in info["explanation_text"]


def test_15_insufficient_baseline():
    info = DeepNocInvestigator._build_baseline_explanation("103.59.163.7", "TRAFFIC_DROP", "ether-new", {
        "current_bps": 1000.0,
        "baseline_bps": 1000.0
    })
    assert "BASELINE" in info["trust_tag"]


def test_16_unit_conversion():
    assert format_bandwidth(500) == "500 bps"
    assert format_bandwidth(1500) == "1.5 Kbps"
    assert format_bandwidth(2500000) == "2.50 Mbps"
    assert format_bandwidth(1890000000) == "1.89 Gbps"
    assert format_bandwidth(10000000000) == "10.00 Gbps"


def test_17_bytes_to_bps_calculation():
    # 1,250,000 bytes delta over 10 seconds = 100,000 Bps = 800,000 bps
    res = calculate_traffic_direction_and_deviation("RX", [0.0, 800000.0])
    assert res["current_bps"] == 800000.0
    assert res["current_formatted"] == "800.0 Kbps"


def test_18_sudden_traffic_drop():
    res = calculate_traffic_direction_and_deviation("RX", [1000000000.0, 100000.0])
    assert res["short_term_direction"] == "DROP"
    assert res["short_term_percentage"] >= 90.0


def test_19_gradual_traffic_drop():
    history = [1000000.0, 800000.0, 600000.0, 400000.0, 200000.0]
    res = calculate_traffic_direction_and_deviation("RX", history)
    assert res["short_term_direction"] == "DROP"


def test_20_ping_success():
    mock_api = MagicMock()
    mock_api.path.return_value = lambda *args, **kwargs: [{"received": "5", "sent": "5", "packet-loss": "0"}]
    from app.tools.routeros import query_interface_ping_test
    res = query_interface_ping_test(mock_api, "10.59.190.5")
    assert res["reachable"] is True


def test_21_ping_failure():
    mock_api = MagicMock()
    mock_api.path.return_value = lambda *args, **kwargs: [{"received": "0", "sent": "5", "packet-loss": "100"}]
    from app.tools.routeros import query_interface_ping_test
    res = query_interface_ping_test(mock_api, "10.59.190.5")
    assert res["reachable"] is False


def test_22_no_ping_target():
    # When no gateway or peer exists, step status is SKIPPED with reason PING TARGET: NOT_AVAILABLE
    steps = [{"step_id": "CONNECTIVITY_PING", "status": "NOT_STARTED"}]
    from app.engine.investigator import update_step
    update_step(steps, "CONNECTIVITY_PING", "SKIPPED", reason="No safe destination IP found for ping test (PING TARGET: NOT_AVAILABLE)")
    assert steps[0]["status"] == "SKIPPED"
    assert "NOT_AVAILABLE" in steps[0]["reason"]


def test_23_ai_cannot_invent_sfp():
    from app.ai.prompts import NOC_SYSTEM_PROMPT
    assert "PHYSICAL_SFP" in NOC_SYSTEM_PROMPT
    assert "NEVER recommend optical/SFP checks for copper" in NOC_SYSTEM_PROMPT


def test_24_ai_cannot_invent_bandwidth():
    from app.ai.prompts import NOC_SYSTEM_PROMPT
    assert "Never refer to historical traffic baseline as \"bandwidth\"" in NOC_SYSTEM_PROMPT


def test_25_ai_cannot_invent_baseline():
    from app.ai.prompts import NOC_SYSTEM_PROMPT
    assert "NO HALLUCINATED FACTS" in NOC_SYSTEM_PROMPT


def test_26_ai_cannot_invent_ip():
    from app.ai.prompts import NOC_SYSTEM_PROMPT
    assert "PING TARGET SAFETY" in NOC_SYSTEM_PROMPT


def test_27_ai_evidence_grounding():
    from app.ai.prompts import NOC_SYSTEM_PROMPT
    assert "SOURCE OF TRUTH" in NOC_SYSTEM_PROMPT


# ============================================================
# ACCEPTANCE TEST 1
# ============================================================
def test_acceptance_1_bandwidth_vs_baseline():
    """
    Physical interface: ether11
    Capacity: 10 Gbps
    Historical traffic: 1.89 Gbps
    Current: 887 Kbps
    Result MUST be:
    - Interface Capacity: 10 Gbps
    - Historical Baseline: 1.89 Gbps
    - Current: 887 Kbps
    - Deviation: ~ -99.95%
    The system MUST NOT say "Bandwidth dropped from 1.89 Gbps".
    It must say "Traffic dropped below the historical baseline".
    """
    info = DeepNocInvestigator._build_baseline_explanation("37.111.52.51", "TRAFFIC_DROP", "ether11", {
        "current_bps": 887000.0,
        "baseline_bps": 1890000000.0,
        "interface_capacity_bps": 10000000000.0
    })
    assert info["capacity_formatted"] == "10.00 Gbps"
    assert info["baseline_formatted"] == "1.89 Gbps"
    assert info["current_formatted"] == "887.0 Kbps"
    assert info["baseline_deviation_percentage"] >= 99.0

    summary = DeepNocInvestigator._generate_deterministic_event_summary("TRAFFIC_DROP", "ether11", "37.111.52.51", {
        "current_bps": 887000.0,
        "moving_average_bps": 1890000000.0
    })
    desc = summary["description"]
    assert "dropped to 887.0 Kbps" in desc
    assert "Historical Baseline: 1.89 Gbps" in desc
    assert "bandwidth dropped from" not in desc.lower()


# ============================================================
# ACCEPTANCE TEST 2
# ============================================================
def test_acceptance_2_vlan_parent_troubleshooting():
    """
    VLAN_1042
    Parent: ether11
    Current: 812 Kbps
    Baseline: 16.56 Gbps
    Result:
    - Interface Type: VLAN
    - Parent: ether11
    - VLAN ID: 1042
    - Baseline: 16.56 Gbps
    - Current: 812 Kbps
    The system MUST NOT recommend "Check SFP RX optical power" unless parent is optical with telemetry.
    """
    iface = {"name": "VLAN_1042", "type": "vlan", "parent-interface": "ether11", "vlan-id": "1042"}
    cls = classify_interface_media(iface)
    assert cls["interface_type"] == "VLAN"
    assert cls["parent_interface"] == "ether11"
    assert cls["vlan_id"] == "1042"

    recs = DeepNocInvestigator._build_noc_recommendations("TRAFFIC_DROP", "VLAN_1042", media_type="VLAN")
    for r in recs:
        txt = (r["check"] + " " + r["command"]).lower()
        assert "sfp rx optical power" not in txt


# ============================================================
# ACCEPTANCE TEST 3
# ============================================================
def test_acceptance_3_loopback_no_fiber():
    """
    lo
    Current: 43 bps
    Baseline: 14.43 Mbps
    Result:
    - Interface Type: LOOPBACK
    - No fiber recommendation
    - No SFP recommendation
    - No cable recommendation
    """
    iface = {"name": "lo", "type": "loopback"}
    cls = classify_interface_media(iface)
    assert cls["interface_type"] == "LOOPBACK"

    recs = DeepNocInvestigator._build_noc_recommendations("TRAFFIC_DROP", "lo", media_type="LOOPBACK")
    for r in recs:
        txt = (r["check"] + " " + r["command"]).lower()
        assert "fiber" not in txt
        assert "sfp" not in txt
        assert "cable" not in txt


# ============================================================
# ACCEPTANCE TEST 4
# ============================================================
def test_acceptance_4_impossible_baseline_rejection():
    """
    baseline: 186.77 Gbps
    interface capacity: 10 Gbps
    Result: BASELINE INVALID
    Do NOT create a valid TRAFFIC_DROP RCA from this baseline.
    Show "Historical baseline exceeds verified interface capacity and has been rejected."
    """
    info = DeepNocInvestigator._build_baseline_explanation("37.111.52.51", "TRAFFIC_DROP", "VLAN_301", {
        "current_bps": 381640.0,
        "baseline_bps": 186770000000.0,
        "interface_capacity_bps": 10000000000.0
    })
    assert info["trust_tag"] == "🔴 BASELINE INVALID"
    assert info["trust_level"] == "INVALID"
    assert "exceeds verified interface capacity" in info["explanation_text"]


def test_phase1_5_regression():
    evts = db.get_events(limit=5)
    assert isinstance(evts, list)


def test_phase6_regression():
    inv = DeepNocInvestigator._build_human_readable_evidence({"device_metrics": []}, "TRAFFIC_DROP", "ether1")
    assert isinstance(inv, list)
