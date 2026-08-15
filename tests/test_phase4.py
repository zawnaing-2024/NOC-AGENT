import json
import uuid
from unittest.mock import MagicMock, patch
import pytest

from app.db.database import DatabaseManager
from app.db.schemas import (
    DeviceRecord,
    DeviceMetricRecord,
    InterfaceMetricRecord,
    BgpMetricRecord,
    OspfMetricRecord,
    RouteMetricRecord,
    EventRecord,
    IncidentRecord,
)
from app.engine.baseline import calculate_baseline
from app.engine.anomaly import AnomalyDetector, generate_fingerprint
from app.engine.correlation import CorrelationEngine, determine_root_event


@pytest.fixture
def test_db(tmp_path):
    db_file = tmp_path / "test_noc_agent.db"
    return DatabaseManager(db_path=str(db_file))


def test_baseline_insufficient_history():
    """Verify minimum 10 sample rule for baseline calculations."""
    samples = [10.0, 12.0, 11.0, 13.0, 10.0]  # Only 5 samples
    bl = calculate_baseline(samples, min_samples=10)
    assert bl.sample_count == 5
    assert bl.baseline_status == "INSUFFICIENT_HISTORY"


def test_baseline_sufficient_history():
    """Verify normal baseline calculation with >= 10 samples."""
    samples = [10.0, 12.0, 11.0, 13.0, 10.0, 12.0, 11.0, 13.0, 10.0, 12.0, 11.0]  # 11 samples
    bl = calculate_baseline(samples, min_samples=10)
    assert bl.sample_count == 11
    assert bl.baseline_status == "NORMAL"
    assert bl.moving_average > 0
    assert bl.stddev >= 0


def test_cpu_spike_anomaly_detection():
    """Verify deterministic CPU spike anomaly detection."""
    history = [15.0] * 12  # Normal moving avg ~15%
    events = AnomalyDetector.check_device_cpu_memory("103.59.163.7", current_cpu=95.0, current_mem=50.0, cpu_history=history, mem_history=[50.0]*12)
    assert len(events) == 1
    assert events[0].type == "CPU_SPIKE"
    assert events[0].severity == "CRITICAL"


def test_traffic_drop_anomaly_detection():
    """Verify traffic drop anomaly detection (current < 0.3 * moving_avg)."""
    rx_history = [100.0, 100.0, 100.0, 1000000.0, 1000000.0, 1000000.0, 1000000.0, 1000000.0, 1000000.0, 1000000.0]
    events = AnomalyDetector.check_interface_status("103.59.163.7", "sfp-sfpplus1", current_running=True, current_disabled=False, prev_running=True, rx_bps_history=rx_history)
    assert len(events) == 1
    assert events[0].type == "TRAFFIC_DROP"
    assert events[0].severity == "MAJOR"


def test_interface_down_and_recovery():
    """Verify interface down and recovery event generation."""
    down_events = AnomalyDetector.check_interface_status("103.59.163.7", "sfp-sfpplus1", current_running=False, current_disabled=False, prev_running=True, rx_bps_history=[])
    assert len(down_events) == 1
    assert down_events[0].type == "INTERFACE_DOWN"

    rec_events = AnomalyDetector.check_interface_status("103.59.163.7", "sfp-sfpplus1", current_running=True, current_disabled=False, prev_running=False, rx_bps_history=[])
    assert len(rec_events) == 1
    assert rec_events[0].type == "INTERFACE_RECOVERED"


def test_bgp_down_and_recovery():
    """Verify BGP down and recovery event generation."""
    down_events = AnomalyDetector.check_bgp_status("103.95.4.1", "10.59.190.81", current_est=False, prev_est=True, current_prefix=0, prev_prefix=1)
    assert len(down_events) == 1
    assert down_events[0].type == "BGP_SESSION_DOWN"

    rec_events = AnomalyDetector.check_bgp_status("103.95.4.1", "10.59.190.81", current_est=True, prev_est=False, current_prefix=1, prev_prefix=0)
    assert len(rec_events) == 1
    assert rec_events[0].type == "BGP_SESSION_RECOVERED"


def test_ospf_neighbor_down():
    """Verify OSPF neighbor down event generation."""
    events = AnomalyDetector.check_ospf_status("103.59.163.7", "10.59.166.90", current_state="Down", prev_state="Full")
    assert len(events) == 1
    assert events[0].type == "OSPF_NEIGHBOR_DOWN"


def test_default_route_down():
    """Verify default route down event generation."""
    events = AnomalyDetector.check_default_route_status("103.59.163.7", current_active=False, prev_active=True)
    assert len(events) == 1
    assert events[0].type == "DEFAULT_ROUTE_DOWN"
    assert events[0].severity == "CRITICAL"


def test_root_cause_priority_hierarchy():
    """Verify deterministic root cause hierarchy selection."""
    e_traffic = EventRecord(event_id="1", device_id="dev1", type="TRAFFIC_DROP", severity="MAJOR", source="eng", entity="sfp1", fingerprint="f1")
    e_bgp = EventRecord(event_id="2", device_id="dev1", type="BGP_SESSION_DOWN", severity="MAJOR", source="eng", entity="peer1", fingerprint="f2")
    e_iface = EventRecord(event_id="3", device_id="dev1", type="INTERFACE_DOWN", severity="MAJOR", source="eng", entity="sfp1", fingerprint="f3")
    e_route = EventRecord(event_id="4", device_id="dev1", type="DEFAULT_ROUTE_DOWN", severity="CRITICAL", source="eng", entity="0.0.0.0/0", fingerprint="f4")

    # Order in list: TRAFFIC_DROP, BGP_SESSION_DOWN, INTERFACE_DOWN, DEFAULT_ROUTE_DOWN
    events = [e_traffic, e_bgp, e_iface, e_route]
    root = determine_root_event(events)
    # INTERFACE_DOWN must be chosen as root cause
    assert root.type == "INTERFACE_DOWN"


@patch("app.engine.correlation.db")
@patch("app.engine.correlation.generate_llm_incident_summary")
def test_correlation_grouping_and_incident_creation(mock_llm, mock_db):
    """Verify correlation window groups related events into 1 incident."""
    mock_db.get_incidents.return_value = []  # No open incidents initially
    mock_llm.return_value = ("Root cause is interface down", "SUCCESS")

    e_iface = EventRecord(event_id="e1", device_id="103.59.163.7", type="INTERFACE_DOWN", severity="MAJOR", source="eng", entity="sfp-sfpplus1", fingerprint="fp1")
    
    CorrelationEngine.process_events([e_iface])
    assert mock_db.upsert_incident.called
    inc_args = mock_db.upsert_incident.call_args[0][0]
    assert inc_args.status == "OPEN"
    assert inc_args.root_event_id == "e1"


def test_bgp_prefix_drop_zero_prefix_check():
    """Verify BGP prefix drop triggers when current < 0.5 * prev, but NOT when prev == 0."""
    # Valid drop: 100 -> 10
    drop_events = AnomalyDetector.check_bgp_status("103.95.4.1", "10.59.190.81", current_est=True, prev_est=True, current_prefix=10, prev_prefix=100)
    assert len(drop_events) == 1
    assert drop_events[0].type == "BGP_PREFIX_DROP"

    # Zero previous prefix: 0 -> 0 (should NOT trigger BGP_PREFIX_DROP)
    zero_events = AnomalyDetector.check_bgp_status("103.95.4.1", "10.59.190.81", current_est=True, prev_est=True, current_prefix=0, prev_prefix=0)
    assert len(zero_events) == 0


def test_low_baseline_traffic_drop_prevention():
    """Rule 5: Verify moving_average < MIN_BASELINE_BPS (10 Kbps) prevents false positive TRAFFIC_DROP."""
    # History with moving average = 3,000 bps (< 10,000 bps threshold)
    low_rx_history = [100.0, 3000.0, 3000.0, 3000.0, 3000.0, 3000.0, 3000.0, 3000.0, 3000.0, 3000.0]
    events = AnomalyDetector.check_interface_status("103.59.163.7", "<sstp-mtw>", current_running=True, current_disabled=False, prev_running=True, rx_bps_history=low_rx_history)
    # Must NOT generate TRAFFIC_DROP
    assert len(events) == 0


def test_persistent_traffic_drop_in_place_occurrence_update(test_db):
    """Rule 1 & 8: Persistent anomaly MUST update last_seen and increment occurrence_count in-place (NOT create 5 event rows)."""
    rx_history = [1000.0, 1000.0, 1000.0, 300000.0, 300000.0, 300000.0, 300000.0, 300000.0, 300000.0, 300000.0]
    
    with patch("app.engine.correlation.db", test_db), patch("app.engine.correlation.generate_llm_incident_summary", return_value=("Traffic drop detected", "SUCCESS")):
        # Execute 5 evaluation cycles of persistent low traffic
        for i in range(5):
            evts = AnomalyDetector.check_interface_status("103.59.163.7", "ether10", current_running=True, current_disabled=False, prev_running=True, rx_bps_history=rx_history)
            CorrelationEngine.process_events(evts)

        # 1. Event DB must contain EXACTLY ONE event row
        events = test_db.get_events()
        assert len(events) == 1
        assert events[0]["occurrence_count"] == 5
        assert events[0]["type"] == "TRAFFIC_DROP"

        # 2. Incident DB must contain EXACTLY ONE incident
        incidents = test_db.get_incidents()
        assert len(incidents) == 1
        assert incidents[0]["occurrence_count"] == 5
        assert incidents[0]["event_count"] == 1


@patch("app.engine.correlation.get_llm")
def test_openrouter_failure_resilience(mock_get_llm, test_db):
    """Verify that if OpenRouter fails, incident persists with llm_status = 'FAILED'."""
    mock_get_llm.side_effect = Exception("OpenRouter API Timeout")
    
    e1 = EventRecord(event_id="e-fail-1", device_id="103.59.163.7", type="INTERFACE_DOWN", severity="MAJOR", source="eng", entity="sfp-sfpplus1", fingerprint="fp-fail-1")
    
    with patch("app.engine.correlation.db", test_db):
        CorrelationEngine.process_events([e1])
        inc = test_db.get_incident_by_id(test_db.get_incidents()[0]["incident_id"])
        assert inc["status"] == "OPEN"
        assert inc["llm_status"] == "FAILED"


def test_full_acceptance_test_simulation(test_db):
    """
    Phase 4 Full Acceptance Test Simulation:
    1. Inject 10+ normal telemetry samples
    2. sfp-sfpplus1 goes DOWN -> BGP goes DOWN -> default route becomes inactive -> traffic drops 90%
    3. Verify ONE incident created with root cause INTERFACE_DOWN
    4. Restore interface, BGP, route, traffic -> verify incident status becomes RESOLVED
    """
    device_id = "103.59.163.7"
    
    # Step 1: Inject 10 normal samples
    for i in range(11):
        test_db.insert_device_metric(DeviceMetricRecord(device_id=device_id, cpu_percent=15.0, memory_percent=40.0))
        test_db.insert_interface_metric(InterfaceMetricRecord(device_id=device_id, interface_name="sfp-sfpplus1", running=True, disabled=False, rx_bps=10000000.0, tx_bps=5000000.0))
        test_db.insert_bgp_metric(BgpMetricRecord(device_id=device_id, peer="10.59.190.81", remote_address="10.59.190.81", established=True, prefix_count=100))
        test_db.insert_route_metric(RouteMetricRecord(device_id=device_id, destination="0.0.0.0/0", gateway="10.59.190.81", active=True))

    with patch("app.engine.correlation.db", test_db), patch("app.engine.correlation.generate_llm_incident_summary", return_value=("Interface down caused BGP and route failure", "SUCCESS")):
        # Step 2: Inject Failure Cascade
        e_iface = AnomalyDetector.check_interface_status(device_id, "sfp-sfpplus1", current_running=False, current_disabled=False, prev_running=True, rx_bps_history=[100.0]+[1000000.0]*10)[0]
        e_bgp = AnomalyDetector.check_bgp_status(device_id, "10.59.190.81", current_est=False, prev_est=True, current_prefix=0, prev_prefix=100)[0]
        e_route = AnomalyDetector.check_default_route_status(device_id, current_active=False, prev_active=True)[0]

        events = [e_iface, e_bgp, e_route]
        CorrelationEngine.process_events(events)

        # Step 3: Verify ONE incident created
        incidents = test_db.get_incidents()
        assert len(incidents) == 1
        inc = incidents[0]
        assert inc["status"] == "OPEN"
        assert inc["severity"] in ["MAJOR", "CRITICAL"]
        
        # Verify Root Event is INTERFACE_DOWN
        root_evt = test_db.get_event_by_id(inc["root_event_id"])
        assert root_evt["type"] == "INTERFACE_DOWN"
        assert root_evt["entity"] == "sfp-sfpplus1"

        # Step 4: Inject Recovery Cascade
        e_iface_rec = AnomalyDetector.check_interface_status(device_id, "sfp-sfpplus1", current_running=True, current_disabled=False, prev_running=False, rx_bps_history=[1000000.0]*10)[0]
        CorrelationEngine.process_events([e_iface_rec])

        # Step 5: Verify Incident status is RESOLVED / CLOSED
        inc_resolved = test_db.get_incident_by_id(inc["incident_id"])
        assert inc_resolved["status"] in ["RESOLVED", "CLOSED"]


def test_nat_active_with_wan_interface():
    """Task 10: NAT rule referencing a DOWN outbound interface generates NAT_DEPENDENCY_DOWN."""
    nat_rules = [{"rule_id": "r1", "enabled": True, "interface_dependency": "ether10", "packets": 500}]
    # ether10 is NOT in running interfaces list
    events = AnomalyDetector.check_nat_rules("103.59.163.7", nat_rules, running_interfaces=["sfp-sfpplus1"])
    assert len(events) == 1
    assert events[0].type == "NAT_DEPENDENCY_DOWN"
    assert events[0].entity == "ether10"


def test_nat_unrelated_down_interface_negative():
    """Task 10: NAT rule with RUNNING outbound interface does NOT generate anomaly even if unrelated ether10 is down."""
    nat_rules = [{"rule_id": "r1", "enabled": True, "interface_dependency": "sfp-sfpplus1", "packets": 500}]
    # sfp-sfpplus1 IS running
    events = AnomalyDetector.check_nat_rules("103.59.163.7", nat_rules, running_interfaces=["sfp-sfpplus1"])
    assert len(events) == 0
