import pytest
from app.tools.routeros import classify_interface_media, query_interface_optical_power


def test_classify_electrical_copper_interface():
    """Verify electrical copper port classification (ether11)."""
    iface_data = {
        "name": "ether11",
        "type": "ether",
        "default-name": "ether11",
        "running": True,
        "disabled": False
    }
    opt_data = {"supported": False}

    res = classify_interface_media(iface_data, opt_data)
    assert res["media_type"] == "ELECTRICAL"
    assert res["confidence"] == "HIGH"
    assert res["optical_capable"] is False
    assert "copper electrical" in res["reason"].lower()


def test_classify_optical_sfp_interface():
    """Verify SFP/SFP+ optical port classification with transceiver metadata."""
    iface_data = {
        "name": "sfp-sfpplus1",
        "type": "sfp-sfpplus",
        "default-name": "sfp-sfpplus1",
        "running": True
    }
    opt_data = {
        "supported": True,
        "sfp_module_present": True,
        "sfp_vendor": "ACCELINK",
        "sfp_part_number": "RTXM228-551",
        "sfp_rx_power_dbm": "-2.217",
        "sfp_tx_power_dbm": "-2.15"
    }

    res = classify_interface_media(iface_data, opt_data)
    assert res["media_type"] == "OPTICAL"
    assert res["confidence"] == "HIGH"
    assert res["optical_capable"] is True
    assert res["details"]["vendor"] == "ACCELINK"


def test_classify_logical_interfaces():
    """Verify VLAN, Bridge, Bonding, Wireless, Virtual, Loopback classifications."""
    vlan_res = classify_interface_media({"name": "VLAN_261", "type": "vlan", "vlan-id": 261})
    assert vlan_res["media_type"] == "VLAN"
    assert vlan_res["optical_capable"] is False

    bridge_res = classify_interface_media({"name": "bridge1", "type": "bridge"})
    assert bridge_res["media_type"] == "BRIDGE"

    bond_res = classify_interface_media({"name": "bond1", "type": "bonding"})
    assert bond_res["media_type"] == "BONDING"

    lo_res = classify_interface_media({"name": "lo", "type": "loopback"})
    assert lo_res["media_type"] == "LOOPBACK"

    wireguard_res = classify_interface_media({"name": "wg0", "type": "wireguard"})
    assert wireguard_res["media_type"] == "VIRTUAL"


def test_classify_unknown_media_interface():
    """Verify fallback to UNKNOWN with LOW confidence when metadata is missing."""
    res = classify_interface_media({}, None)
    assert res["media_type"] == "UNKNOWN"
    assert res["confidence"] == "LOW"
    assert res["optical_capable"] is False


def test_no_false_optical_data_for_copper():
    """Verify optical fields are None (not 0 and not 'Generic') when optical monitoring is unsupported."""
    class MockPath:
        def __call__(self, cmd, **kwargs):
            return []

    class MockApi:
        def path(self, p):
            return MockPath()

    opt_res = query_interface_optical_power(MockApi(), "ether11")
    assert opt_res["supported"] is False
    assert opt_res.get("sfp_vendor") is None
