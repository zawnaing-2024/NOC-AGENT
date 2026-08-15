import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, status

from app.db.database import db
from app.collector.service import run_manual_collection

logger = logging.getLogger("mikrotik_noc_agent.api")
router = APIRouter(prefix="/api", tags=["Phase 4 AIOps Telemetry & Incidents"])


@router.get("/database/status", status_code=status.HTTP_200_OK)
def get_database_status():
    """Retrieves SQLite database diagnostic status, file size, and table row counts."""
    return db.get_database_status()


@router.post("/collector/run", status_code=status.HTTP_200_OK)
def trigger_manual_collection():
    """
    Executes ONE synchronous collection cycle across all configured routers.
    Returns collection statistics without calling LLM or modifying router config.
    """
    return run_manual_collection()


@router.get("/devices", status_code=status.HTTP_200_OK)
def get_devices():
    """Retrieves list of registered MikroTik routers in the system."""
    devices = db.get_devices()
    return {"devices": devices, "count": len(devices)}


@router.get("/events", status_code=status.HTTP_200_OK)
def get_events(limit: int = Query(default=100, ge=1, le=1000), device_id: Optional[str] = Query(default=None)):
    """Retrieves list of historical anomaly events."""
    events = db.get_events(limit=limit, device_id=device_id)
    return {"events": events, "count": len(events)}


@router.get("/events/{event_id}", status_code=status.HTTP_200_OK)
def get_event_detail(event_id: str):
    """Retrieves single historical anomaly event detail."""
    event = db.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found.")
    return event


@router.get("/incidents", status_code=status.HTTP_200_OK)
def get_incidents(limit: int = Query(default=50, ge=1, le=500), status_filter: Optional[str] = Query(default=None, alias="status")):
    """Retrieves list of correlated AIOps incidents."""
    incidents = db.get_incidents(limit=limit, status=status_filter)
    return {"incidents": incidents, "count": len(incidents)}


@router.get("/incidents/{incident_id}", status_code=status.HTTP_200_OK)
def get_incident_detail(incident_id: str):
    """Retrieves single correlated AIOps incident detail."""
    incident = db.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return incident


@router.get("/devices/{device_id}/history", status_code=status.HTTP_200_OK)
def get_device_history(device_id: str, limit: int = Query(default=100, ge=1, le=1000)):
    """Retrieves historical CPU, RAM, and uptime metrics for a device."""
    metrics = db.get_recent_device_metrics(device_id=device_id, limit=limit)
    return {"device_id": device_id, "history": metrics, "count": len(metrics)}


@router.get("/devices/{device_id}/anomalies", status_code=status.HTTP_200_OK)
def get_device_anomalies(device_id: str, limit: int = Query(default=100, ge=1, le=1000)):
    """Retrieves historical anomaly events specifically for a targeted device."""
    events = db.get_events(limit=limit, device_id=device_id)
    return {"device_id": device_id, "anomalies": events, "count": len(events)}


@router.get("/interfaces/{interface_name}/history", status_code=status.HTTP_200_OK)
def get_interface_history(interface_name: str, device_id: Optional[str] = Query(default=None), limit: int = Query(default=100, ge=1, le=1000)):
    """Retrieves historical operational and traffic metrics for an interface."""
    dev_id = device_id or "103.59.163.7"
    metrics = db.get_recent_interface_metrics(device_id=dev_id, interface_name=interface_name, limit=limit)
    return {"interface_name": interface_name, "device_id": dev_id, "history": metrics, "count": len(metrics)}


@router.get("/bgp/{peer}/history", status_code=status.HTTP_200_OK)
def get_bgp_history(peer: str, device_id: Optional[str] = Query(default=None), limit: int = Query(default=100, ge=1, le=1000)):
    """Retrieves historical BGP session state and prefix count telemetry."""
    dev_id = device_id or "103.95.4.1"
    metrics = db.get_recent_bgp_metrics(device_id=dev_id, peer=peer, limit=limit)
    return {"peer": peer, "device_id": dev_id, "history": metrics, "count": len(metrics)}


@router.get("/ospf/{neighbor}/history", status_code=status.HTTP_200_OK)
def get_ospf_history(neighbor: str, device_id: Optional[str] = Query(default=None), limit: int = Query(default=100, ge=1, le=1000)):
    """Retrieves historical OSPF neighbor state telemetry."""
    dev_id = device_id or "103.59.163.7"
    metrics = db.get_recent_ospf_metrics(device_id=dev_id, neighbor=neighbor, limit=limit)
    return {"neighbor": neighbor, "device_id": dev_id, "history": metrics, "count": len(metrics)}
