import json
from unittest.mock import MagicMock, patch

from app.tools.routeros import (
    get_bgp_peers,
    parse_bgp_peers_data,
)


def test_parse_bgp_peers_summary_mode():
    mock_api = MagicMock()
    mock_session = MagicMock()
    mock_session.__iter__.return_value = iter([
        {
            "name": "peer-up",
            "remote.address": "198.51.100.1",
            "state": "established",
        },
        {
            "name": "peer-down",
            "remote.address": "198.51.100.2",
            "state": "connect",
        }
    ])
    mock_api.path.return_value = mock_session

    res = parse_bgp_peers_data(mock_api, details=False)
    assert res.summary.total == 2
    assert res.summary.established == 1
    assert res.summary.down == 1
    assert res.summary.down_peers == ["peer-down"]
    assert res.details is None


def test_parse_bgp_peers_detailed_mode():
    mock_api = MagicMock()
    mock_session = MagicMock()
    mock_session.__iter__.return_value = iter([
        {
            "name": "peer-up",
            "remote.address": "198.51.100.1",
            "state": "established",
            "remote.prefix-count": 500,
            "remote.as": "65001",
        }
    ])
    mock_api.path.return_value = mock_session

    res = parse_bgp_peers_data(mock_api, details=True)
    assert res.summary.established == 1
    assert res.details is not None
    assert len(res.details) == 1
    assert res.details[0].prefix_count == 500
    assert res.details[0].remote_as == "65001"


@patch("app.tools.routeros.librouteros.connect")
def test_get_bgp_peers_tool_wrapper(mock_connect):
    mock_api = MagicMock()
    mock_session = MagicMock()
    mock_session.__iter__.return_value = iter([
        {
            "name": "peer-1",
            "remote.address": "10.0.0.1",
            "state": "established",
        }
    ])
    mock_api.path.return_value = mock_session
    mock_connect.return_value = mock_api

    result_json = get_bgp_peers.invoke({"details": False})
    data = json.loads(result_json)

    assert "summary" in data
    assert data["summary"]["established"] == 1
