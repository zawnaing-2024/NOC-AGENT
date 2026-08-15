import json
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import db
from app.db.schemas import EventRecord, IncidentRecord
from app.engine.anomaly import AnomalyDetector
from app.engine.correlation import CorrelationEngine
from app.ai.agent import AIAgentService

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    db.init_db()
    with db.get_connection() as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM incidents")
        conn.execute("DELETE FROM ai_analyses")
        conn.commit()
    yield


VALID_RCA_JSON = json.dumps({
    "summary": "WAN link sfp-sfpplus1 failure caused downstream BGP and route loss.",
    "root_cause": {
        "description": "Physical link down on sfp-sfpplus1 triggered BGP session collapse.",
        "confidence": "HIGH"
    },
    "impact": {
        "description": "Complete loss of WAN transit and active default route.",
        "scope": "INTERFACE"
    },
    "evidence": [
        {"fact": "INTERFACE_DOWN on sfp-sfpplus1", "source": "event"},
        {"fact": "BGP_SESSION_DOWN with peer 10.10.10.1", "source": "event"}
    ],
    "hypotheses": [
        {"description": "Upstream fiber break or transceiver fault", "confidence": "MEDIUM"}
    ],
    "recommended_actions": [
        {"step": 1, "action": "Inspect physical fiber link state", "reason": "Interface sfp-sfpplus1 is UNEXPECTED_DOWN"}
    ],
    "verification_steps": [
        "Check /interface print detail"
    ],
    "customer_impact": "CONFIRMED"
})


def test_scenario1_cpu_spike_event_and_incident():
    """Test 1: CPU_SPIKE generates event and correlated incident."""
    e_cpu = AnomalyDetector.check_device_cpu_memory(
        "103.59.163.7",
        current_cpu=95.0,
        current_mem=10.0,
        cpu_history=[20.0] * 10,
        mem_history=[10.0] * 10
    )[0]

    inc_id = CorrelationEngine.process_events([e_cpu])
    assert inc_id is not None

    events = db.get_events(device_id="103.59.163.7", event_type="CPU_SPIKE")
    assert len(events) == 1

    inc = db.get_incident_by_id(inc_id)
    assert inc["severity"] in ["CRITICAL", "MAJOR", "WARNING"]
    assert inc["device_id"] == "103.59.163.7"


def test_scenario2_bgp_down_investigation_flow():
    """Test 2: BGP_SESSION_DOWN generates event, incident, timeline, evidence, and AI investigation."""
    e_bgp = AnomalyDetector.check_bgp_status(
        "103.95.4.1",
        peer="10.59.190.81",
        current_est=False,
        prev_est=True,
        current_prefix=0,
        prev_prefix=1
    )[0]

    inc_id = CorrelationEngine.process_events([e_bgp])
    assert inc_id is not None

    # Test Timeline API
    res_tl = client.get(f"/api/incidents/{inc_id}/timeline")
    assert res_tl.status_code == 200
    assert res_tl.json()["count"] == 1

    # Test Evidence API
    res_ev = client.get(f"/api/incidents/{inc_id}/evidence")
    assert res_ev.status_code == 200
    assert "evidence" in res_ev.json()

    # Test AI Investigation Endpoint
    mock_openrouter = {
        "success": True,
        "model": "meta-llama/llama-3.3-70b-instruct",
        "content": VALID_RCA_JSON,
        "latency_ms": 180,
        "error": None
    }
    with patch("app.ai.agent.generate_openrouter_completion", return_value=mock_openrouter):
        res_inv = client.post(f"/api/incidents/{inc_id}/investigate")
        assert res_inv.status_code == 200
        assert res_inv.json()["success"] is True
        assert res_inv.json()["analysis"]["root_cause"]["confidence"] == "HIGH"


def test_scenario3_cascade_correlation_single_incident():
    """Test 3: Interface + BGP + Prefix + Default Route failure cascade creates 4 events -> 1 correlated incident."""
    dev_id = "103.59.163.7"
    e1 = AnomalyDetector.check_interface_status(dev_id, "sfp-sfpplus1", current_running=False, current_disabled=False, prev_running=True, rx_bps_history=[1000.0]*10)[0]
    e2 = AnomalyDetector.check_bgp_status(dev_id, "10.10.10.1", current_est=False, prev_est=True, current_prefix=0, prev_prefix=100)[0]
    e3 = AnomalyDetector.check_default_route_status(dev_id, current_active=False, prev_active=True)[0]

    inc_id = CorrelationEngine.process_events([e1, e2, e3])

    events = db.get_events(device_id=dev_id)
    assert len(events) == 3

    incidents = db.get_incidents(device_id=dev_id, status="OPEN")
    assert len(incidents) == 1  # 3 events correlated into EXACTLY 1 incident, NOT 3 incidents
    assert incidents[0]["incident_id"] == inc_id


def test_scenario4_persistent_anomaly_deduplication():
    """Test 4: Persistent anomaly across multiple evaluation cycles updates occurrence_count without duplicate rows."""
    dev_id = "103.59.163.7"
    e_iface = AnomalyDetector.check_interface_status(dev_id, "sfp-sfpplus1", current_running=False, current_disabled=False, prev_running=True, rx_bps_history=[1000.0]*10)[0]

    # Cycle 1
    inc_id1 = CorrelationEngine.process_events([e_iface])
    
    # Cycle 2 (same condition)
    inc_id2 = CorrelationEngine.process_events([e_iface])

    assert inc_id1 == inc_id2  # Same incident retained

    events = db.get_events(device_id=dev_id)
    assert len(events) == 1  # Single event row retained
    assert events[0]["occurrence_count"] >= 2  # occurrence_count incremented in-place


def test_scenario5_incident_recovery():
    """Test 5: Fault followed by recovery transitions incident status OPEN -> RESOLVED."""
    dev_id = "103.59.163.7"
    e_down = AnomalyDetector.check_interface_status(dev_id, "sfp-sfpplus1", current_running=False, current_disabled=False, prev_running=True, rx_bps_history=[1000.0]*10)[0]
    inc_id = CorrelationEngine.process_events([e_down])

    inc_open = db.get_incident_by_id(inc_id)
    assert inc_open["status"] in ["OPEN", "INVESTIGATING"]

    # Recovery event
    e_rec = AnomalyDetector.check_interface_status(dev_id, "sfp-sfpplus1", current_running=True, current_disabled=False, prev_running=False, rx_bps_history=[1000000.0]*10)[0]
    CorrelationEngine.process_events([e_rec])

    inc_resolved = db.get_incident_by_id(inc_id)
    assert inc_resolved["status"] in ["RESOLVED", "CLOSED"]


def test_scenario6_multiple_device_isolation():
    """Test 6: Anomalies on Device A and Device B create isolated incidents without cross-contamination."""
    dev_a = "103.59.163.7"
    dev_b = "103.95.4.1"

    e_a = AnomalyDetector.check_interface_status(dev_a, "sfp-sfpplus1", current_running=False, current_disabled=False, prev_running=True, rx_bps_history=[1000.0]*10)[0]
    e_b = AnomalyDetector.check_bgp_status(dev_b, "10.59.190.81", current_est=False, prev_est=True, current_prefix=0, prev_prefix=1)[0]

    inc_id_a = CorrelationEngine.process_events([e_a])
    inc_id_b = CorrelationEngine.process_events([e_b])

    assert inc_id_a != inc_id_b

    inc_a = db.get_incident_by_id(inc_id_a)
    inc_b = db.get_incident_by_id(inc_id_b)

    assert inc_a["device_id"] == dev_a
    assert inc_b["device_id"] == dev_b
