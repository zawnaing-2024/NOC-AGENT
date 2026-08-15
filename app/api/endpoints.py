import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import JSONResponse

from app.db.database import db
from app.collector.service import run_manual_collection

logger = logging.getLogger("mikrotik_noc_agent.api")
router = APIRouter(prefix="/api", tags=["Phase 4 AIOps Telemetry & Incidents"])


from app.engine.anomaly import AnomalyDetector, engine_diagnostics, CONFIGURED_RULES


@router.get("/health", status_code=status.HTTP_200_OK)
def get_health_endpoint():
    """Service health check endpoint."""
    return {"status": "ok"}


@router.get("/anomaly/status", status_code=status.HTTP_200_OK)
def get_anomaly_status():
    """Retrieves anomaly engine status and execution diagnostics."""
    return engine_diagnostics


@router.get("/anomaly/rules", status_code=status.HTTP_200_OK)
def get_anomaly_rules():
    """Retrieves list of configured deterministic anomaly detection rules."""
    return CONFIGURED_RULES


@router.post("/anomaly/evaluate", status_code=status.HTTP_200_OK)
def trigger_anomaly_evaluation():
    """
    Executes ONE deterministic anomaly evaluation cycle across historical SQLite telemetry.
    Returns rule-by-rule evaluation statistics and anomaly details.
    """
    return AnomalyDetector.run_evaluation_cycle()


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
def get_events(
    limit: int = Query(default=100, ge=1, le=1000),
    device_id: Optional[str] = Query(default=None),
    severity: Optional[str] = Query(default=None),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    event_type: Optional[str] = Query(default=None),
):
    """Retrieves list of historical anomaly events with multi-parameter filtering."""
    events = db.get_events(limit=limit, device_id=device_id, severity=severity, status=status_filter, event_type=event_type)
    return {"events": events, "count": len(events)}


@router.get("/events/{event_id}", status_code=status.HTTP_200_OK)
def get_event_detail(event_id: str):
    """Retrieves single historical anomaly event detail."""
    event = db.get_event_by_id(event_id)
    if not event:
        raise HTTPException(status_code=404, detail=f"Event '{event_id}' not found.")
    return event


@router.get("/incidents", status_code=status.HTTP_200_OK)
def get_incidents(
    limit: int = Query(default=50, ge=1, le=500),
    status_filter: Optional[str] = Query(default=None, alias="status"),
    severity: Optional[str] = Query(default=None),
    device_id: Optional[str] = Query(default=None),
):
    """Retrieves list of correlated AIOps incidents with multi-parameter filtering."""
    incidents = db.get_incidents(limit=limit, status=status_filter, severity=severity, device_id=device_id)
    return {"incidents": incidents, "count": len(incidents)}


@router.get("/incidents/{incident_id}", status_code=status.HTTP_200_OK)
def get_incident_detail(incident_id: str):
    """Retrieves single correlated AIOps incident detail."""
    incident = db.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    return incident


@router.get("/incidents/{incident_id}/timeline", status_code=status.HTTP_200_OK)
def get_incident_timeline(incident_id: str):
    """Retrieves chronological event timeline linked to a correlated incident."""
    inc = db.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    from app.ai.context_builder import ContextBuilder
    ctx = ContextBuilder.build_incident_context(incident_id)
    return {
        "incident_id": incident_id,
        "device_id": inc["device_id"],
        "timeline": ctx["timeline"],
        "count": len(ctx["timeline"])
    }


@router.get("/incidents/{incident_id}/evidence", status_code=status.HTTP_200_OK)
def get_incident_evidence(incident_id: str):
    """Retrieves complete verified evidence payload collected for a correlated incident."""
    inc = db.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    from app.ai.context_builder import ContextBuilder
    ctx = ContextBuilder.build_incident_context(incident_id)
    return {"incident_id": incident_id, "evidence": ctx}


@router.post("/incidents/{incident_id}/investigate", status_code=status.HTTP_200_OK)
def investigate_incident_openrouter(incident_id: str):
    """
    Triggers repeatable OpenRouter AI investigation on a correlated incident.
    Gathers verified evidence context, sends to OpenRouter, validates JSON, and stores analysis.
    """
    inc = db.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    from app.ai.agent import AIAgentService
    res = AIAgentService.analyze_incident(incident_id)
    if not res.get("success") and res.get("error") == "AI_PROVIDER_UNAVAILABLE":
        return JSONResponse(status_code=503, content=res)
    return res


@router.post("/incidents/{incident_id}/resolve", status_code=status.HTTP_200_OK)
def resolve_incident_endpoint(incident_id: str):
    """Manually or automatically resolves an open incident and records resolution timestamp."""
    inc = db.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    resolved_inc = db.resolve_incident(incident_id, summary="Incident manually resolved by operator.")
    return {"incident_id": incident_id, "status": "RESOLVED", "incident": resolved_inc}


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
    metrics = db.get_recent_interface_metrics(device_id=device_id, interface_name=interface_name, limit=limit)
    dev_id = device_id or (metrics[0]["device_id"] if metrics else "103.59.163.7")
    return {"interface_name": interface_name, "device_id": dev_id, "history": metrics, "count": len(metrics)}


@router.get("/bgp/{peer}/history", status_code=status.HTTP_200_OK)
def get_bgp_history(peer: str, device_id: Optional[str] = Query(default=None), limit: int = Query(default=100, ge=1, le=1000)):
    """Retrieves historical BGP session state and prefix count telemetry."""
    metrics = db.get_recent_bgp_metrics(device_id=device_id, peer=peer, limit=limit)
    dev_id = device_id or (metrics[0]["device_id"] if metrics else "103.95.4.1")
    return {"peer": peer, "device_id": dev_id, "history": metrics, "count": len(metrics)}


@router.get("/ospf/{neighbor}/history", status_code=status.HTTP_200_OK)
def get_ospf_history(neighbor: str, device_id: Optional[str] = Query(default=None), limit: int = Query(default=100, ge=1, le=1000)):
    """Retrieves historical OSPF neighbor state telemetry."""
    metrics = db.get_recent_ospf_metrics(device_id=device_id, neighbor=neighbor, limit=limit)
    dev_id = device_id or (metrics[0]["device_id"] if metrics else "103.59.163.7")
    return {"neighbor": neighbor, "device_id": dev_id, "history": metrics, "count": len(metrics)}


# --- PHASE 5 AI INTELLIGENCE & RCA ENDPOINTS ---

from app.services.llm_client import check_lm_studio_health
from app.services.ai_analyzer import AINocAnalyzer


@router.get("/ai/health", status_code=status.HTTP_200_OK)
def get_ai_health():
    """Retrieves LM Studio local AI service health, active model, and latency."""
    res = check_lm_studio_health()
    if res.get("status") != "healthy":
        return JSONResponse(status_code=503, content=res)
    return res


@router.post("/ai/incidents/{incident_id}/analyze", status_code=status.HTTP_200_OK)
def analyze_incident_ai(incident_id: str):
    """
    Triggers AI-assisted Root Cause Analysis (RCA) on a correlated incident using LM Studio.
    Validates strict JSON response, grounds facts in evidence, and persists result.
    """
    inc = db.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    res = AINocAnalyzer.analyze_incident(incident_id)
    if res.get("status") == "AI_UNAVAILABLE":
        raise HTTPException(status_code=503, detail=res.get("error", "LM Studio AI service unavailable."))
    elif res.get("status") == "FAILED":
        raise HTTPException(status_code=422, detail=res.get("error", "AI RCA JSON validation failed."))

    return res


@router.get("/api/ai/incidents/{incident_id}", status_code=status.HTTP_200_OK)
@router.get("/ai/incidents/{incident_id}", status_code=status.HTTP_200_OK)
def get_incident_ai_analysis(incident_id: str):
    """Retrieves the latest persisted AI analysis for an incident."""
    analysis = db.get_ai_analysis_by_incident_id(incident_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"No AI analysis found for incident '{incident_id}'.")
    return {"incident_id": incident_id, "analysis_status": analysis.get("status"), "analysis": analysis}


@router.post("/ai/devices/{device_id}/analyze", status_code=status.HTTP_200_OK)
def analyze_device_ai(device_id: str):
    """Triggers AI-assisted device health and risk assessment for a targeted device."""
    res = AINocAnalyzer.analyze_device(device_id)
    if res.get("status") == "AI_UNAVAILABLE":
        raise HTTPException(status_code=503, detail=res.get("error", "LM Studio AI service unavailable."))
    return res


@router.get("/ai/devices/{device_id}/latest", status_code=status.HTTP_200_OK)
def get_device_latest_ai_analysis(device_id: str):
    """Retrieves the latest persisted AI analysis for a device."""
    analysis = db.get_ai_analysis_by_device_id(device_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"No AI analysis found for device '{device_id}'.")
    return {"device_id": device_id, "analysis_status": analysis.get("status"), "analysis": analysis}


# --- OPENROUTER PHASE 5 NOC AGENT ENDPOINTS ---

from app.ai.openrouter_client import get_openrouter_status
from app.ai.agent import AIAgentService


@router.get("/ai/status", status_code=status.HTTP_200_OK)
def get_ai_provider_status():
    """Retrieves OpenRouter AI provider status and model configuration (without exposing API keys)."""
    return get_openrouter_status()


@router.get("/ai/incidents/{incident_id}/analyses", status_code=status.HTTP_200_OK)
def get_incident_analyses_history(incident_id: str):
    """Retrieves full history of AI analyses performed for an incident."""
    inc = db.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")
    analyses = AIAgentService.get_incident_analyses(incident_id)
    return {"incident_id": incident_id, "analyses": analyses, "count": len(analyses)}


@router.get("/ai/analyses/{analysis_id}", status_code=status.HTTP_200_OK)
def get_analysis_by_id_endpoint(analysis_id: str):
    """Retrieves a single AI analysis record by analysis_id."""
    analysis = AIAgentService.get_analysis_by_id(analysis_id)
    if not analysis:
        raise HTTPException(status_code=404, detail=f"Analysis '{analysis_id}' not found.")
    return analysis
