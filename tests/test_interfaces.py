import json
from unittest.mock import MagicMock, patch

from app.tools.routeros import (
    get_interfaces,
    parse_interfaces_data,
)


def get_mock_iface_data():
    return [
        {
            "name": "ether1",
            "type": "ether",
            "running": True,
            "disabled": False,
            "rx-byte": 1000,
            "tx-byte": 2000,
            "rx-error": 0,
            "tx-error": 0,
        },
        {
            "name": "ether2",
            "type": "ether",
            "running": False,
            "disabled": True,  # DISABLED rule: no fault inferred
            "rx-byte": 0,
            "tx-byte": 0,
        },
        {
            "name": "ether3",
            "type": "ether",
            "running": False,
            "disabled": False,
            "rx-byte": 0,  # UNCONNECTED rule: 0 traffic, unplugged port; no fault
            "tx-byte": 0,
        },
        {
            "name": "ether4",
            "type": "ether",
            "running": False,
            "disabled": False,
            "rx-byte": 50000,  # LINK_DOWN rule: previously active link dropped; fault
            "tx-byte": 80000,
        },
        {
            "name": "ether5",
            "type": "ether",
            "running": True,
            "disabled": False,
            "rx-error": 5,  # ERROR rule: active with framing errors; fault
            "tx-error": 0,
        },
    ]


def test_parse_interfaces_data_classification_rules():
    mock_api = MagicMock()
    mock_api.path.side_effect = lambda p: get_mock_iface_data()

    # Test compact summary mode (details=False)
    res_summary = parse_interfaces_data(mock_api, details=False)
    assert res_summary.summary.total == 5
    assert res_summary.summary.active == 2  # ether1 + ether5
    assert res_summary.summary.disabled == 1  # ether2
    assert res_summary.summary.unconnected == 1  # ether3 (0 traffic)
    assert res_summary.summary.link_down == 1  # ether4 (traffic > 0, dropped link)
    assert res_summary.summary.errors == 1  # ether5
    assert res_summary.summary.link_down_interfaces == ["ether4"]
    assert res_summary.summary.error_interfaces == ["ether5"]
    assert res_summary.details is None

    # Test detailed mode (details=True)
    res_details = parse_interfaces_data(mock_api, details=True)
    assert res_details.details is not None
    assert len(res_details.details) == 5
    assert res_details.details[0].status_tag == "ACTIVE"
    assert res_details.details[1].status_tag == "DISABLED"
    assert res_details.details[2].status_tag == "UNCONNECTED"
    assert res_details.details[3].status_tag == "LINK_DOWN"
    assert res_details.details[4].status_tag == "ERROR"


@patch("app.tools.routeros.librouteros.connect")
def test_get_interfaces_tool_wrapper(mock_connect):
    mock_api = MagicMock()
    mock_api.path.side_effect = lambda p: [
        {
            "name": "ether1",
            "type": "ether",
            "running": True,
            "disabled": False,
        }
    ]
    mock_connect.return_value = mock_api

    result_json = get_interfaces.invoke({"details": False})
    data = json.loads(result_json)

    assert "summary" in data
    assert data["summary"]["active"] == 1
    assert "details" not in data
