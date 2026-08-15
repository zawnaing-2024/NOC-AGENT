import json
import logging
from typing import Dict, Any, List, Optional

from app.db.database import db

logger = logging.getLogger("mikrotik_noc_agent.noc_tools")


def get_device_health(device_id: str) -> Dict[str, Any]:
    """Retrieves latest system resource metrics (CPU, RAM, uptime) for a device."""
    metrics = db.get_recent_device_metrics(device_id, limit=1)
    return {"device_id": device_id, "latest_health": metrics[0] if metrics else {}}


def get_device_history(device_id: str, limit: int = 10) -> Dict[str, Any]:
    """Retrieves historical CPU, RAM, and uptime metrics for a device."""
    metrics = db.get_recent_device_metrics(device_id, limit=limit)
    return {"device_id": device_id, "history": metrics, "count": len(metrics)}


def get_interface_status(device_id: str, interface_name: str) -> Dict[str, Any]:
    """Retrieves latest operational and traffic status for an interface."""
    metrics = db.get_recent_interface_metrics(device_id=device_id, interface_name=interface_name, limit=1)
    return {"device_id": device_id, "interface_name": interface_name, "status": metrics[0] if metrics else {}}


def get_interface_history(device_id: str, interface_name: str, limit: int = 10) -> Dict[str, Any]:
    """Retrieves historical traffic and link metrics for an interface."""
    metrics = db.get_recent_interface_metrics(device_id=device_id, interface_name=interface_name, limit=limit)
    return {"device_id": device_id, "interface_name": interface_name, "history": metrics, "count": len(metrics)}


def get_bgp_status(device_id: str, peer: str) -> Dict[str, Any]:
    """Retrieves latest BGP peer session status and prefix count."""
    metrics = db.get_recent_bgp_metrics(device_id=device_id, peer=peer, limit=1)
    return {"device_id": device_id, "peer": peer, "status": metrics[0] if metrics else {}}


def get_bgp_history(device_id: str, peer: str, limit: int = 10) -> Dict[str, Any]:
    """Retrieves historical BGP peer session telemetry."""
    metrics = db.get_recent_bgp_metrics(device_id=device_id, peer=peer, limit=limit)
    return {"device_id": device_id, "peer": peer, "history": metrics, "count": len(metrics)}


def get_ospf_status(device_id: str, neighbor: str) -> Dict[str, Any]:
    """Retrieves latest OSPF neighbor state."""
    metrics = db.get_recent_ospf_metrics(device_id=device_id, neighbor=neighbor, limit=1)
    return {"device_id": device_id, "neighbor": neighbor, "status": metrics[0] if metrics else {}}


def get_ospf_history(device_id: str, neighbor: str, limit: int = 10) -> Dict[str, Any]:
    """Retrieves historical OSPF neighbor telemetry."""
    metrics = db.get_recent_ospf_metrics(device_id=device_id, neighbor=neighbor, limit=limit)
    return {"device_id": device_id, "neighbor": neighbor, "history": metrics, "count": len(metrics)}


def get_routes(device_id: str, limit: int = 10) -> Dict[str, Any]:
    """Retrieves recent route table entries for a device."""
    with db.get_connection() as conn:
        rows = conn.execute("SELECT * FROM route_metrics WHERE device_id = ? ORDER BY id DESC LIMIT ?", (device_id, limit)).fetchall()
        return {"device_id": device_id, "routes": [dict(r) for r in rows]}


def get_default_route(device_id: str) -> Dict[str, Any]:
    """Retrieves active default route (0.0.0.0/0) telemetry for a device."""
    with db.get_connection() as conn:
        rows = conn.execute("SELECT * FROM route_metrics WHERE device_id = ? AND destination = '0.0.0.0/0' ORDER BY id DESC LIMIT 1", (device_id,)).fetchall()
        return {"device_id": device_id, "default_route": dict(rows[0]) if rows else {}}


def get_nat_status(device_id: str, limit: int = 10) -> Dict[str, Any]:
    """Retrieves NAT rules telemetry for a device."""
    with db.get_connection() as conn:
        rows = conn.execute("SELECT * FROM nat_metrics WHERE device_id = ? ORDER BY id DESC LIMIT ?", (device_id, limit)).fetchall()
        return {"device_id": device_id, "nat_rules": [dict(r) for r in rows]}


def get_recent_events(device_id: Optional[str] = None, limit: int = 10) -> Dict[str, Any]:
    """Retrieves recent deterministic anomaly events."""
    events = db.get_events(limit=limit, device_id=device_id)
    return {"events": events, "count": len(events)}


def get_active_incidents(device_id: Optional[str] = None, limit: int = 10) -> Dict[str, Any]:
    """Retrieves correlated AIOps incidents in OPEN or ACKNOWLEDGED status."""
    incidents = db.get_incidents(limit=limit, status="OPEN")
    if device_id:
        incidents = [i for i in incidents if i["device_id"] == device_id]
    return {"incidents": incidents, "count": len(incidents)}


def get_incident(incident_id: str) -> Dict[str, Any]:
    """Retrieves single correlated incident detail."""
    inc = db.get_incident_by_id(incident_id)
    return {"incident": inc or {}}


def get_event(event_id: str) -> Dict[str, Any]:
    """Retrieves single event detail."""
    evt = db.get_event_by_id(event_id)
    return {"event": evt or {}}


def get_database_status() -> Dict[str, Any]:
    """Retrieves database telemetry diagnostic status."""
    return db.get_database_status()


# READ-ONLY Tool Registry Schema for OpenRouter Tool Calling
READONLY_NOC_TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "get_device_health",
            "description": "Retrieves latest system resource metrics (CPU, RAM, uptime) for a device.",
            "parameters": {
                "type": "object",
                "properties": {"device_id": {"type": "string"}},
                "required": ["device_id"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_interface_status",
            "description": "Retrieves latest operational and traffic status for an interface.",
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {"type": "string"},
                    "interface_name": {"type": "string"}
                },
                "required": ["device_id", "interface_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_bgp_status",
            "description": "Retrieves latest BGP peer session status and prefix count.",
            "parameters": {
                "type": "object",
                "properties": {
                    "device_id": {"type": "string"},
                    "peer": {"type": "string"}
                },
                "required": ["device_id", "peer"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_active_incidents",
            "description": "Retrieves active correlated AIOps incidents.",
            "parameters": {
                "type": "object",
                "properties": {"device_id": {"type": "string"}},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_recent_events",
            "description": "Retrieves recent deterministic anomaly events.",
            "parameters": {
                "type": "object",
                "properties": {"device_id": {"type": "string"}},
                "required": []
            }
        }
    }
]


def execute_noc_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Executes a read-only NOC tool by name and returns result dictionary."""
    tool_map = {
        "get_device_health": lambda args: get_device_health(args["device_id"]),
        "get_device_history": lambda args: get_device_history(args["device_id"], args.get("limit", 10)),
        "get_interface_status": lambda args: get_interface_status(args["device_id"], args["interface_name"]),
        "get_interface_history": lambda args: get_interface_history(args["device_id"], args["interface_name"], args.get("limit", 10)),
        "get_bgp_status": lambda args: get_bgp_status(args["device_id"], args["peer"]),
        "get_bgp_history": lambda args: get_bgp_history(args["device_id"], args["peer"], args.get("limit", 10)),
        "get_ospf_status": lambda args: get_ospf_status(args["device_id"], args["neighbor"]),
        "get_ospf_history": lambda args: get_ospf_history(args["device_id"], args["neighbor"], args.get("limit", 10)),
        "get_routes": lambda args: get_routes(args["device_id"], args.get("limit", 10)),
        "get_default_route": lambda args: get_default_route(args["device_id"]),
        "get_nat_status": lambda args: get_nat_status(args["device_id"], args.get("limit", 10)),
        "get_recent_events": lambda args: get_recent_events(args.get("device_id"), args.get("limit", 10)),
        "get_active_incidents": lambda args: get_active_incidents(args.get("device_id"), args.get("limit", 10)),
        "get_incident": lambda args: get_incident(args["incident_id"]),
        "get_event": lambda args: get_event(args["event_id"]),
        "get_database_status": lambda args: get_database_status(),
    }

    if tool_name not in tool_map:
        return {"error": f"Tool '{tool_name}' not found or prohibited."}

    try:
        return tool_map[tool_name](arguments)
    except Exception as e:
        logger.error(f"Error executing NOC tool '{tool_name}': {e}")
        return {"error": str(e)}
