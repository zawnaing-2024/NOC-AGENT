import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import db
from app.db.schemas import DeviceRecord, DeviceMetricRecord

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    db.init_db()
    with db.get_connection() as conn:
        conn.execute("DELETE FROM devices")
        conn.execute("DELETE FROM device_metrics")
        conn.execute("DELETE FROM interface_metrics")
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM incidents")
        conn.commit()

    # Seed initial test devices
    db.upsert_device(DeviceRecord(
        device_id="103.59.163.7",
        name="GD-CDN_NAT01",
        ip_address="103.59.163.7",
        role="Core Router",
        location="Yangon Data Center",
        status="HEALTHY",
        password="secretpassword123"
    ))
    db.upsert_device(DeviceRecord(
        device_id="103.95.4.1",
        name="GD_YGN_DGW1",
        ip_address="103.95.4.1",
        role="Gateway",
        location="Mandalay POP",
        status="HEALTHY",
        password="secretpassword456"
    ))
    yield


def test_get_devices_list_redacts_passwords():
    """Verify GET /api/devices returns inventory list with redacted credentials."""
    res = client.get("/api/devices")
    assert res.status_code == 200
    data = res.json()
    assert "devices" in data
    assert len(data["devices"]) == 2

    dev = data["devices"][0]
    assert dev["password"] == "[REDACTED]"
    assert dev["ip_address"] in ["103.59.163.7", "103.95.4.1"]


def test_get_device_detail_endpoint():
    """Verify GET /api/devices/{id} returns device detail summary."""
    res = client.get("/api/devices/103.59.163.7")
    assert res.status_code == 200
    data = res.json()
    assert data["device_id"] == "103.59.163.7"
    assert data["name"] == "GD-CDN_NAT01"
    assert data["password"] == "[REDACTED]"
    assert "interfaces_summary" in data
    assert "routes_summary" in data


def test_add_device_success():
    """Verify POST /api/devices adds a new device."""
    payload = {
        "name": "EDGE-RTR-02",
        "ip_address": "10.100.1.1",
        "description": "Backup Edge Router",
        "location": "Bago POP",
        "role": "Edge Router",
        "api_port": 8728,
        "username": "admin",
        "password": "mypassword123",
        "monitoring_enabled": True
    }
    res = client.post("/api/devices", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert "added successfully" in data["message"]
    assert data["device"]["name"] == "EDGE-RTR-02"
    assert data["device"]["password"] == "[REDACTED]"


def test_add_device_validation_invalid_ip():
    """Verify POST /api/devices rejects invalid IP address."""
    payload = {
        "name": "BAD-RTR",
        "ip_address": "999.999.999.999",
        "username": "admin",
        "password": "pass"
    }
    res = client.post("/api/devices", json=payload)
    assert res.status_code == 400
    assert "invalid" in res.json()["detail"].lower()


def test_add_device_duplicate_prevention():
    """Verify POST /api/devices prevents duplicate name or IP."""
    payload = {
        "name": "GD-CDN_NAT01",  # Existing name
        "ip_address": "10.200.1.1",
        "username": "admin",
        "password": "pass"
    }
    res = client.post("/api/devices", json=payload)
    assert res.status_code == 400
    assert "already exists" in res.json()["detail"].lower()


def test_update_device_retains_password_when_blank():
    """Verify PUT /api/devices/{id} retains stored password when empty or [REDACTED]."""
    payload = {
        "name": "GD-CDN_NAT01-RENAMED",
        "ip_address": "103.59.163.7",
        "role": "Core Switch",
        "password": ""  # Blank, keep existing
    }
    res = client.put("/api/devices/103.59.163.7", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["device"]["name"] == "GD-CDN_NAT01-RENAMED"
    assert data["device"]["role"] == "Core Switch"

    # Verify backend still retains original password internally
    raw_dev = db.get_device_by_id("103.59.163.7", redact_password=False)
    assert raw_dev["password"] == "secretpassword123"


def test_soft_delete_device_preserves_history():
    """Verify DELETE /api/devices/{id} soft-deletes device without destroying metrics."""
    # Insert metric history
    db.insert_device_metric(DeviceMetricRecord(device_id="103.59.163.7", cpu_percent=25.0))

    res = client.delete("/api/devices/103.59.163.7")
    assert res.status_code == 200
    assert "removed" in res.json()["message"]

    # Device list excludes deleted
    devs = db.get_devices(include_deleted=False)
    assert not any(d["device_id"] == "103.59.163.7" for d in devs)

    # Metrics history remains intact
    metrics = db.get_recent_device_metrics("103.59.163.7")
    assert len(metrics) >= 1


def test_enable_disable_monitoring():
    """Verify POST /api/devices/{id}/monitoring/disable and /enable."""
    res_dis = client.post("/api/devices/103.59.163.7/monitoring/disable")
    assert res_dis.status_code == 200
    assert res_dis.json()["monitoring_enabled"] is False

    dev = db.get_device_by_id("103.59.163.7")
    assert dev["status"] == "DISABLED"

    res_en = client.post("/api/devices/103.59.163.7/monitoring/enable")
    assert res_en.status_code == 200
    assert res_en.json()["monitoring_enabled"] is True

    dev = db.get_device_by_id("103.59.163.7")
    assert dev["status"] == "HEALTHY"


@patch("app.api.endpoints.get_routeros_client")
def test_test_connection_endpoint_success(mock_client_ctx):
    """Verify POST /api/devices/test-connection returns connection success."""
    mock_api = MagicMock()
    mock_ctx = MagicMock()
    mock_ctx.__enter__.return_value = mock_api
    mock_client_ctx.return_value = mock_ctx

    with patch("app.api.endpoints.parse_system_resource") as mock_sys:
        mock_sys.return_value = MagicMock(routeros_version="7.8 (stable)")
        res = client.post("/api/devices/103.59.163.7/test-connection")
        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert "Successful" in data["message"]
        assert data["routeros_version"] == "7.8 (stable)"
