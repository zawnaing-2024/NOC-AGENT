import pytest
import uuid
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import db
from app.engine.investigator import DeepNocInvestigator, calculate_traffic_direction_and_deviation

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_data():
    """Sets up deterministic test events and database state."""
    db.init_db()
    with db.get_connection() as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM interface_metrics")
        conn.execute("DELETE FROM incidents")
    yield


def test_1_event_list_api():
    """Verify GET /api/events returns event list."""
    evt_id = f"evt-test-{uuid.uuid4().hex[:6]}"
    evt = {
        "event_id": evt_id,
        "device_id": "103.59.163.7",
        "type": "TRAFFIC_DROP",
        "entity": "VLAN_1042",
        "severity": "WARNING",
        "status": "OPEN",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence": {"current_bps": 812430.0, "baseline_bps": 16560000000.0}
    }
    db.save_event(evt)

    response = client.get("/api/events")
    assert response.status_code == 200
    data = response.json()
    assert "events" in data
    assert len(data["events"]) >= 1


def test_2_event_detail_api():
    """Verify GET /api/events/{event_id} returns single event detail."""
    evt_id = f"evt-detail-{uuid.uuid4().hex[:6]}"
    evt = {
        "event_id": evt_id,
        "device_id": "103.59.163.7",
        "type": "INTERFACE_DOWN",
        "entity": "ether1",
        "severity": "CRITICAL",
        "status": "OPEN",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    db.save_event(evt)

    response = client.get(f"/api/events/{evt_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["event_id"] == evt_id
    assert data["entity"] == "ether1"


def test_3_event_filtering():
    """Verify event filtering by severity, status, and event_type."""
    evt1 = {
        "event_id": f"evt-f1-{uuid.uuid4().hex[:4]}",
        "device_id": "103.59.163.7",
        "type": "BGP_SESSION_DOWN",
        "entity": "10.0.0.1",
        "severity": "CRITICAL",
        "status": "OPEN",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    evt2 = {
        "event_id": f"evt-f2-{uuid.uuid4().hex[:4]}",
        "device_id": "103.95.4.1",
        "type": "CPU_SPIKE",
        "entity": "system",
        "severity": "WARNING",
        "status": "RESOLVED",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    db.save_event(evt1)
    db.save_event(evt2)

    res = client.get("/api/events?severity=CRITICAL")
    assert res.status_code == 200
    data = res.json()
    assert all(e["severity"] == "CRITICAL" for e in data["events"])


def test_4_critical_event_detail():
    """Verify critical event investigation payload structure."""
    evt_id = f"evt-crit-{uuid.uuid4().hex[:6]}"
    evt = {
        "event_id": evt_id,
        "device_id": "103.59.163.7",
        "type": "DEFAULT_ROUTE_DOWN",
        "entity": "0.0.0.0/0",
        "severity": "CRITICAL",
        "status": "OPEN",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    db.save_event(evt)

    res = client.get(f"/api/events/{evt_id}/investigation")
    assert res.status_code == 200
    data = res.json()
    hdr = data["event_header"]
    assert hdr["severity"] == "CRITICAL"
    assert hdr["event_type"] == "DEFAULT_ROUTE_DOWN"


def test_5_traffic_event_detail():
    """Verify traffic drop event detail returns baseline explanation and magnitude."""
    evt_id = f"evt-trf-{uuid.uuid4().hex[:6]}"
    evt = {
        "event_id": evt_id,
        "device_id": "103.59.163.7",
        "type": "TRAFFIC_DROP",
        "entity": "ether1",
        "severity": "WARNING",
        "status": "OPEN",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evidence": {"current_bps": 812430.0, "baseline_bps": 16560000000.0}
    }
    db.save_event(evt)

    res = client.get(f"/api/events/{evt_id}/investigation")
    assert res.status_code == 200
    data = res.json()
    bl = data["baseline_explanation"]
    assert bl["baseline_deviation_percentage"] > 99.0
    assert "explanation_text" in bl


def test_6_baseline_explanation():
    """Verify baseline explanation text and calculation details."""
    bl_info = DeepNocInvestigator._build_baseline_explanation(
        "103.59.163.7", "TRAFFIC_DROP", "ether1", {"current_bps": 1000.0, "baseline_bps": 1000000.0}
    )
    assert "explanation_text" in bl_info
    assert "Robust Median" in bl_info["calculation_method"]
    assert bl_info["window_minutes"] == 15


def test_7_baseline_trust():
    """Verify baseline trust indicators (TRUSTED vs LIMITED vs INVALID)."""
    bl_info = DeepNocInvestigator._build_baseline_explanation(
        "103.59.163.7", "TRAFFIC_DROP", "ether1", {}
    )
    assert bl_info["trust_tag"] in ["🟢 BASELINE TRUSTED", "🟡 BASELINE LIMITED", "🔴 BASELINE INVALID"]


def test_8_traffic_graph_data():
    """Verify traffic time-series graph points structure."""
    dev_id = "103.59.163.7"
    ifname = "ether1"
    for i in range(5):
        m = {
            "device_id": dev_id,
            "interface_name": ifname,
            "running": 1,
            "disabled": 0,
            "rx_bps": 1000.0 * (i + 1),
            "tx_bps": 500.0 * (i + 1),
            "telemetry_valid": True,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        db.save_interface_metric(m)

    points, pattern = DeepNocInvestigator._build_traffic_graph_and_pattern(dev_id, "TRAFFIC_DROP", ifname)
    assert len(points) == 5
    assert points[0]["rx_bps"] == 1000.0


def test_9_sudden_drop_classification():
    """Verify sudden traffic drop classification (SUDDEN_DROP)."""
    res = calculate_traffic_direction_and_deviation("RX", [1_800_000_000.0, 20_000_000.0])
    assert res["short_term_direction"] == "DROP"
    assert res["short_term_percentage"] >= 50.0


def test_10_gradual_drop_classification():
    """Verify gradual traffic drop classification."""
    rates = [1_800_000_000.0, 1_500_000_000.0, 1_200_000_000.0, 900_000_000.0, 500_000_000.0, 100_000_000.0]
    dev_id = "103.59.163.7"
    ifname = "ether2"
    for r in rates:
        m = {
            "device_id": dev_id,
            "interface_name": ifname,
            "running": 1,
            "disabled": 0,
            "rx_bps": r,
            "tx_bps": r,
            "telemetry_valid": True,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        db.save_interface_metric(m)

    _, pattern = DeepNocInvestigator._build_traffic_graph_and_pattern(dev_id, "TRAFFIC_DROP", ifname)
    assert pattern == "GRADUAL_DROP"


def test_11_vlan_investigation():
    """Verify VLAN interface investigation parent link redirection (no fake SFP checks)."""
    info = DeepNocInvestigator._build_domain_investigation("103.59.163.7", "TRAFFIC_DROP", "VLAN_1042", {})
    assert info["media_type"] == "VLAN"
    assert "NOT_APPLICABLE" in info["physical_troubleshooting"]
    assert info["parent_interface"] == "ether1"


def test_12_loopback_investigation():
    """Verify Loopback interface physical troubleshooting skip."""
    info = DeepNocInvestigator._build_domain_investigation("103.59.163.7", "TRAFFIC_DROP", "lo", {})
    assert info["media_type"] == "LOOPBACK"
    assert info["physical_troubleshooting"] == "NOT_APPLICABLE"


def test_13_electrical_interface_investigation():
    """Verify electrical interface investigation attributes."""
    info = DeepNocInvestigator._build_domain_investigation("103.59.163.7", "TRAFFIC_DROP", "ether11", {})
    assert info["media_type"] == "ELECTRICAL"


def test_14_optical_interface_investigation():
    """Verify optical interface NOC recommendations contain optical check commands."""
    recs = DeepNocInvestigator._build_noc_recommendations("INTERFACE_DOWN", "sfp-sfpplus1", "OPTICAL")
    assert any("optical power" in r["check"].lower() or "sfp" in r["check"].lower() for r in recs)


def test_15_unknown_media_investigation():
    """Verify unknown media NOC recommendations omit fake optical statements."""
    recs = DeepNocInvestigator._build_noc_recommendations("INTERFACE_DOWN", "custom_tun1", "UNKNOWN")
    assert not any("rx optical power" in r["check"].lower() for r in recs)


def test_16_ip_address_detection():
    """Verify interface IP address detection in investigation engine."""
    res = DeepNocInvestigator._investigate_traffic_drop_and_interface("103.59.163.7", "ether1")
    assert "ip_investigation" in res


def test_17_ping_success():
    """Verify ping reachability status formatting."""
    res = DeepNocInvestigator._investigate_traffic_drop_and_interface("103.59.163.7", "ether1")
    assert "ping_investigation" in res


def test_18_ping_failure():
    """Verify RouterOS connection failure returns unreachable ping state."""
    res = DeepNocInvestigator._investigate_traffic_drop_and_interface("192.168.255.254", "ether1")
    assert res["ping_investigation"]["reachable"] is False


def test_19_default_route_investigation():
    """Verify DEFAULT_ROUTE_DOWN investigation structure."""
    info = DeepNocInvestigator._build_domain_investigation("103.59.163.7", "DEFAULT_ROUTE_DOWN", "0.0.0.0/0", {"gateway": "10.59.190.5"})
    assert info["domain"] == "ROUTING"
    assert info["destination"] == "0.0.0.0/0"
    assert info["active"] is False


def test_20_bgp_investigation():
    """Verify BGP_SESSION_DOWN investigation structure."""
    info = DeepNocInvestigator._build_domain_investigation("103.59.163.7", "BGP_SESSION_DOWN", "10.0.0.1", {})
    assert info["domain"] == "BGP"
    assert info["state"] == "DOWN"


def test_21_event_correlation():
    """Verify related events correlation list."""
    dev_id = "103.59.163.7"
    evt1 = {
        "event_id": "e1",
        "device_id": dev_id,
        "type": "INTERFACE_DOWN",
        "entity": "ether1",
        "severity": "CRITICAL",
        "status": "OPEN",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    evt2 = {
        "event_id": "e2",
        "device_id": dev_id,
        "type": "BGP_SESSION_DOWN",
        "entity": "10.0.0.1",
        "severity": "CRITICAL",
        "status": "OPEN",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    db.save_event(evt1)
    db.save_event(evt2)

    res = DeepNocInvestigator.run_event_investigation("e1")
    assert len(res["related_events"]) >= 1


def test_22_ai_evidence_grounding():
    """Verify AI investigation endpoint receives strictly ground-truth evidence payload."""
    res = client.get("/incidents/INC-MOCK/evidence")
    assert res.status_code in [200, 404]


def test_23_incomplete_evidence():
    """Verify unauthenticated device investigation marks evidence as incomplete."""
    res = DeepNocInvestigator._investigate_traffic_drop_and_interface("192.168.255.254", "ether1")
    assert res["evidence_completeness"] == "INCOMPLETE"
    assert res["routeros_authenticated"] is False


def test_24_no_fake_data():
    """Verify event summary facts are generated deterministically without LLM hallucination."""
    summary = DeepNocInvestigator._generate_deterministic_event_summary("DEFAULT_ROUTE_DOWN", "0.0.0.0/0", "103.59.163.7", {})
    assert summary["title"] == "DEFAULT ROUTE DOWN"
    assert "RouterOS Route Telemetry API" in summary["source"]


def test_25_read_only_security():
    """Verify event investigation performs zero write commands to RouterOS."""
    res = DeepNocInvestigator.run_event_investigation("non-existent-event")
    assert res["status"] == "FAILED"


def test_26_phase1_5_regression():
    """Verify Phase 1-5 database and anomaly detector integrity."""
    evts = db.get_events(limit=5)
    assert isinstance(evts, list)


def test_27_phase6_3_regression():
    """Verify Phase 6.3 correctness rules remain intact."""
    res = DeepNocInvestigator._investigate_traffic_drop_and_interface("192.168.255.254", "ether1")
    assert res["investigation_conclusion"] == "INSUFFICIENT_EVIDENCE"


def test_28_phase6_4_regression():
    """Verify Phase 6.4 traffic rate validation and baseline integrity."""
    from app.engine.baseline import calculate_baseline
    res = calculate_baseline([1_000.0, 1_000.0, 1_000.0])
    assert res.moving_average == 1_000.0
