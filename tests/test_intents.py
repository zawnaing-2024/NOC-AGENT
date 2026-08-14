import json
from unittest.mock import MagicMock, patch
import pytest

from app.tools.routeros import (
    get_interfaces,
    parse_interfaces_data,
)


def get_sample_routeros_interfaces():
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
            "disabled": True,  # DISABLED
        },
        {
            "name": "ether3",
            "type": "ether",
            "running": False,
            "disabled": False,
            "rx-byte": 0,  # UNCONNECTED (zero traffic)
            "tx-byte": 0,
        },
        {
            "name": "ether8",
            "type": "ether",
            "running": False,
            "disabled": False,
            "rx-byte": 50000,  # LINK_DOWN (prior traffic > 0)
            "tx-byte": 80000,
        },
        {
            "name": "ether9",
            "type": "ether",
            "running": True,
            "disabled": False,
            "rx-error": 120,  # ERROR (active with errors)
            "tx-error": 10,
        },
    ]


def test_targeted_interface_filter():
    mock_api = MagicMock()
    mock_api.path.return_value = get_sample_routeros_interfaces()

    # Query details with interface_name="ether8"
    response = parse_interfaces_data(mock_api, details=True, interface_name="ether8")
    
    assert response.summary.total == 5
    assert response.summary.link_down_interfaces == ["ether8"]
    assert response.details is not None
    assert len(response.details) == 1
    assert response.details[0].name == "ether8"
    assert response.details[0].status_tag == "LINK_DOWN"


def test_classification_tag_accuracy():
    mock_api = MagicMock()
    mock_api.path.return_value = get_sample_routeros_interfaces()

    response = parse_interfaces_data(mock_api, details=True)
    assert response.details is not None
    tags = {iface.name: iface.status_tag for iface in response.details}

    assert tags["ether1"] == "ACTIVE"
    assert tags["ether2"] == "DISABLED"
    assert tags["ether3"] == "UNCONNECTED"
    assert tags["ether8"] == "LINK_DOWN"
    assert tags["ether9"] == "ERROR"
