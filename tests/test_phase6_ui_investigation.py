import json
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import db
from app.db.schemas import EventRecord, IncidentRecord
from app.engine.investigator import DeepNocInvestigator

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    db.init_db()
    with db.get_connection() as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM incidents")
        conn.execute("DELETE FROM ai_analyses")
        conn.execute("DELETE FROM investigations")
        conn.commit()
    yield


def test_phase6_dashboard_ui_serving():
    """Test GET / serves the Phase 6 NOC Dashboard Single Page Application."""
    response = client.get("/")
    assert response.status_code == 200
    assert "ISP MikroTik NOC Agent" in response.text


def test_phase6_devices_overview_endpoint():
    """Test GET /api/devices/overview returns device matrix."""
    response = client.get("/api/devices/overview")
    assert response.status_code == 200
    data = response.json()
    assert "devices" in data
    assert len(data["devices"]) >= 1


def test_phase6_interfaces_overview_endpoint():
    """Test GET /api/interfaces/overview returns interface telemetry matrix."""
    response = client.get("/api/interfaces/overview")
    assert response.status_code == 200
    data = response.json()
    assert "interfaces" in data


def test_phase6_bgp_overview_endpoint():
    """Test GET /api/routing/bgp/overview returns BGP sessions overview."""
    response = client.get("/api/routing/bgp/overview")
    assert response.status_code == 200
    data = response.json()
    assert "bgp_peers" in data


def test_phase6_ospf_overview_endpoint():
    """Test GET /api/routing/ospf/overview returns OSPF neighbors overview."""
    response = client.get("/api/routing/ospf/overview")
    assert response.status_code == 200
    data = response.json()
    assert "ospf_neighbors" in data


def test_phase6_routing_overview_endpoint():
    """Test GET /api/routing/overview returns routing table summary."""
    response = client.get("/api/routing/overview")
    assert response.status_code == 200
    data = response.json()
    assert "default_route_status" in data


def test_phase6_deep_investigation_engine_and_endpoint():
    """Test DeepNocInvestigator and GET /api/incidents/{id}/deep-investigation."""
    db.upsert_active_event(EventRecord(
        event_id="evt-inv-root",
        device_id="103.59.163.7",
        type="INTERFACE_DOWN",
        severity="CRITICAL",
        entity="sfp-sfpplus1",
        fingerprint="103.59.163.7:INTERFACE_DOWN:sfp-sfpplus1"
    ))
    db.upsert_incident(IncidentRecord(
        incident_id="inc-inv-601",
        device_id="103.59.163.7",
        severity="CRITICAL",
        status="OPEN",
        root_event_id="evt-inv-root",
        correlated_event_ids=["evt-inv-root"]
    ))

    # Test direct investigator
    inv = DeepNocInvestigator.run_investigation("inc-inv-601")
    assert inv["status"] == "COMPLETED"
    assert "INTERFACE_DOWN" in inv["primary_failure"]
    assert len(inv["evidence"]) >= 1
    assert len(inv["visualization_flow"]) == 5
    assert len(inv["recommendations"]) >= 1

    # Test endpoint
    res = client.get("/api/incidents/inc-inv-601/deep-investigation")
    assert res.status_code == 200
    data = res.json()
    assert data["incident_id"] == "inc-inv-601"
    assert "primary_failure" in data
