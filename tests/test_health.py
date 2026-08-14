import json
from unittest.mock import MagicMock, patch
import pytest

from app.tools.routeros import (
    get_system_health,
    parse_system_resource,
    RouterOSConnectionError,
)


def test_parse_system_resource_success():
    mock_api = MagicMock()

    mock_resource = MagicMock()
    mock_resource.__iter__.return_value = iter([
        {
            "board-name": "RB750Gr3",
            "version": "7.12.1",
            "uptime": "2d4h12m",
            "cpu-load": 18,
            "total-memory": 268435456,
            "free-memory": 161061273,
        }
    ])

    mock_identity = MagicMock()
    mock_identity.__iter__.return_value = iter([{"name": "CORE-ROUTER-01"}])

    def path_side_effect(path_name):
        if path_name == "/system/resource":
            return mock_resource
        elif path_name == "/system/identity":
            return mock_identity
        return MagicMock()

    mock_api.path.side_effect = path_side_effect

    health = parse_system_resource(mock_api)

    assert health.identity == "CORE-ROUTER-01"
    assert health.board_name == "RB750Gr3"
    assert health.routeros_version == "7.12.1"
    assert health.cpu_load_percent == 18
    assert health.memory_usage_percent == 40.0
    assert health.status == "HEALTHY"


def test_parse_system_resource_high_cpu_critical():
    mock_api = MagicMock()

    mock_resource = MagicMock()
    mock_resource.__iter__.return_value = iter([
        {
            "board-name": "CCR2004",
            "version": "7.14",
            "uptime": "10d",
            "cpu-load": 95,
            "total-memory": 1000,
            "free-memory": 500,
        }
    ])
    mock_identity = MagicMock()
    mock_identity.__iter__.return_value = iter([{"name": "EDGE-01"}])

    mock_api.path.side_effect = lambda p: mock_resource if p == "/system/resource" else mock_identity

    health = parse_system_resource(mock_api)
    assert health.status == "CRITICAL"


@patch("app.tools.routeros.librouteros.connect")
def test_get_system_health_tool_wrapper(mock_connect):
    mock_api = MagicMock()
    mock_resource = MagicMock()
    mock_resource.__iter__.return_value = iter([
        {
            "board-name": "HEX",
            "version": "7.10",
            "uptime": "1d",
            "cpu-load": 12,
            "total-memory": 100,
            "free-memory": 80,
        }
    ])
    mock_identity = MagicMock()
    mock_identity.__iter__.return_value = iter([{"name": "MOCK-ROUTER"}])
    mock_api.path.side_effect = lambda p: mock_resource if p == "/system/resource" else mock_identity

    mock_connect.return_value = mock_api

    result_json = get_system_health.invoke({})
    data = json.loads(result_json)

    assert data["identity"] == "MOCK-ROUTER"
    assert data["status"] == "HEALTHY"


@patch("app.tools.routeros.librouteros.connect")
def test_get_system_health_connection_error(mock_connect):
    mock_connect.side_effect = ConnectionRefusedError("Connection refused")

    with pytest.raises(RouterOSConnectionError) as exc_info:
        get_system_health.invoke({})

    assert "Unable to reach MikroTik device" in str(exc_info.value)
