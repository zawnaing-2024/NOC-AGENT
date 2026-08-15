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


# --- PHASE 5 PRODUCTION OPENROUTER AI INTELLIGENCE & RCA ENDPOINTS ---

from app.ai.openrouter_client import get_openrouter_status
from app.ai.agent import AIAgentService
from app.services.llm_client import check_lm_studio_health


@router.get("/ai/health", status_code=status.HTTP_200_OK)
def get_ai_health():
    """Retrieves OpenRouter primary production AI provider status."""
    return get_openrouter_status()


@router.post("/ai/incidents/{incident_id}/analyze", status_code=status.HTTP_200_OK)
def analyze_incident_ai(incident_id: str):
    """
    Triggers production OpenRouter AI Root Cause Analysis (RCA) on a correlated incident.
    Gathers verified evidence payload from SQLite, sends to OpenRouter API (meta-llama/llama-3.3-70b-instruct),
    validates strict Pydantic JSON response, and persists analysis record.
    """
    inc = db.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    res = AIAgentService.analyze_incident(incident_id)
    if not res.get("success") and res.get("error") == "AI_PROVIDER_UNAVAILABLE":
        raise HTTPException(status_code=503, detail="OpenRouter AI provider unavailable.")

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
    """Triggers OpenRouter AI device health and risk assessment for a targeted device."""
    from app.services.ai_analyzer import AINocAnalyzer
    res = AINocAnalyzer.analyze_device(device_id)
    if res.get("status") == "AI_UNAVAILABLE":
        raise HTTPException(status_code=503, detail=res.get("error", "AI service unavailable."))
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


# --- PHASE 6 NOC DASHBOARD OVERVIEW & DEEP INVESTIGATION ENDPOINTS ---

from app.engine.investigator import DeepNocInvestigator


@router.get("/devices/overview", status_code=status.HTTP_200_OK)
def get_devices_overview():
    """Retrieves multi-device overview matrix (CPU, RAM, Interfaces UP/DOWN, BGP, OSPF, Routes, NAT, Health)."""
    devices = db.get_devices()
    overview_list = []
    for d in devices:
        dev_id = d["device_id"]
        dm = db.get_recent_device_metrics(dev_id, limit=1)
        im = db.get_recent_interface_metrics(dev_id, limit=200)
        bm = db.get_recent_bgp_metrics(dev_id, limit=100)
        om = db.get_recent_ospf_metrics(dev_id, limit=100)
        routes_cnt = db.get_device_route_count(dev_id)
        nat_cnt = db.get_device_nat_count(dev_id)

        curr_dm = dm[0] if dm else {}
        up_ifaces = len([i for i in im if i.get("running") == 1])
        total_ifaces = len(im)
        est_bgp = len([b for b in bm if b.get("established") == 1])
        full_ospf = len([o for o in om if "Full" in str(o.get("state"))])

        # Determine health status
        events = db.get_events(device_id=dev_id, status="ACTIVE", limit=5)
        dev_health = "HEALTHY"
        if any(e["severity"] == "CRITICAL" for e in events):
            dev_health = "CRITICAL"
        elif any(e["severity"] == "MAJOR" for e in events):
            dev_health = "WARNING"

        overview_list.append({
            "device_id": dev_id,
            "name": d.get("name", dev_id),
            "ip_address": d.get("ip_address", dev_id),
            "version": d.get("version", "RouterOS v7"),
            "cpu_percent": curr_dm.get("cpu_percent", 0.0),
            "memory_percent": curr_dm.get("memory_percent", 0.0),
            "uptime_seconds": curr_dm.get("uptime_seconds", 0),
            "interfaces_up": up_ifaces,
            "interfaces_total": total_ifaces,
            "bgp_established": est_bgp,
            "bgp_total": len(bm),
            "ospf_full": full_ospf,
            "ospf_total": len(om),
            "routes_count": routes_cnt,
            "nat_count": nat_cnt,
            "health": dev_health
        })
    return {"devices": overview_list, "count": len(overview_list)}


@router.get("/interfaces/overview", status_code=status.HTTP_200_OK)
def get_interfaces_overview(device_id: Optional[str] = Query(default=None)):
    """Retrieves complete interface status, bandwidth rates, error/drop counters, and health tags."""
    devices = [device_id] if device_id else [d["device_id"] for d in db.get_devices()]
    interface_list = []

    for dev in devices:
        im = db.get_recent_interface_metrics(dev, limit=200)
        # Deduplicate latest per interface
        seen = set()
        for i in im:
            ifname = i["interface_name"]
            if ifname not in seen:
                seen.add(ifname)
                state = "UP" if i.get("running") == 1 else "DOWN"
                h_tag = "HEALTHY" if state == "UP" else "CRITICAL"
                if i.get("rx_errors", 0) > 0 or i.get("tx_errors", 0) > 0:
                    h_tag = "WARNING"

                rx_val = float(i.get("rx_bps", 0.0))
                tx_val = float(i.get("tx_bps", 0.0))
                if rx_val > 100_000_000_000:
                    rx_val = 0.0
                if tx_val > 100_000_000_000:
                    tx_val = 0.0

                interface_list.append({
                    "device_id": dev,
                    "interface_name": ifname,
                    "status": state,
                    "running": i.get("running", 0),
                    "disabled": i.get("disabled", 0),
                    "rx_bps": rx_val,
                    "tx_bps": tx_val,
                    "rx_errors": i.get("rx_errors", 0),
                    "tx_errors": i.get("tx_errors", 0),
                    "rx_drops": i.get("rx_drops", 0),
                    "tx_drops": i.get("tx_drops", 0),
                    "health": h_tag,
                    "timestamp": i.get("timestamp")
                })

    return {"interfaces": interface_list, "count": len(interface_list)}


@router.get("/routing/bgp/overview", status_code=status.HTTP_200_OK)
def get_bgp_overview(device_id: Optional[str] = Query(default=None)):
    """Retrieves complete BGP sessions overview across all devices."""
    devices = [device_id] if device_id else [d["device_id"] for d in db.get_devices()]
    bgp_list = []
    total_est = 0
    total_down = 0

    for dev in devices:
        bm = db.get_recent_bgp_metrics(dev, limit=100)
        seen = set()
        for b in bm:
            peer = b["peer"]
            if peer not in seen:
                seen.add(peer)
                is_est = b.get("established") == 1
                if is_est:
                    total_est += 1
                else:
                    total_down += 1

                bgp_list.append({
                    "device_id": dev,
                    "peer": peer,
                    "remote_address": b.get("remote_address", peer),
                    "state": "ESTABLISHED" if is_est else "DOWN",
                    "established": is_est,
                    "uptime": b.get("uptime", "0s"),
                    "prefix_count": b.get("prefix_count", 0),
                    "health": "HEALTHY" if is_est else "CRITICAL"
                })

    return {
        "bgp_peers": bgp_list,
        "total": len(bgp_list),
        "established_count": total_est,
        "down_count": total_down
    }


@router.get("/routing/ospf/overview", status_code=status.HTTP_200_OK)
def get_ospf_overview(device_id: Optional[str] = Query(default=None)):
    """Retrieves complete OSPF neighbor overview across all devices."""
    devices = [device_id] if device_id else [d["device_id"] for d in db.get_devices()]
    ospf_list = []
    full_cnt = 0
    down_cnt = 0

    for dev in devices:
        om = db.get_recent_ospf_metrics(dev, limit=100)
        seen = set()
        for o in om:
            nbr = o["neighbor"]
            if nbr not in seen:
                seen.add(nbr)
                state_str = str(o.get("state", "UNKNOWN"))
                is_full = "Full" in state_str
                if is_full:
                    full_cnt += 1
                else:
                    down_cnt += 1

                ospf_list.append({
                    "device_id": dev,
                    "neighbor": nbr,
                    "router_id": o.get("router_id", nbr),
                    "state": state_str,
                    "interface": o.get("interface", "unknown"),
                    "area": o.get("area", "main"),
                    "health": "HEALTHY" if is_full else "CRITICAL"
                })

    return {
        "ospf_neighbors": ospf_list,
        "total": len(ospf_list),
        "full_count": full_cnt,
        "down_count": down_cnt
    }


@router.get("/routing/overview", status_code=status.HTTP_200_OK)
def get_routing_overview():
    """Retrieves routing table breakdown, default route status, active vs inactive route summary."""
    devices = db.get_devices()
    def_route_active = True
    total_routes = 0
    active_cnt = 0
    inactive_cnt = 0

    for d in devices:
        dev_id = d["device_id"]
        total_routes += db.get_device_route_count(dev_id)
        rm = db.get_recent_route_metrics(dev_id, limit=500)
        seen_dest = set()
        for r in rm:
            dst = r.get("destination")
            if dst not in seen_dest:
                seen_dest.add(dst)
                if r.get("active") == 1:
                    active_cnt += 1
                else:
                    inactive_cnt += 1
                if dst in ["0.0.0.0/0", "default"] and r.get("active") == 0:
                    def_route_active = False

    return {
        "default_route_status": "HEALTHY" if def_route_active else "CRITICAL",
        "default_route_active": def_route_active,
        "total_routes": total_routes,
        "active_routes": active_cnt,
        "inactive_routes": inactive_cnt
    }


@router.get("/incidents/{incident_id}/deep-investigation", status_code=status.HTTP_200_OK)
def get_deep_investigation_endpoint(incident_id: str):
    """Triggers and retrieves deep deterministic NOC investigation for an incident."""
    inc = db.get_incident_by_id(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found.")

    res = DeepNocInvestigator.run_investigation(incident_id)
    if res.get("status") == "FAILED":
        raise HTTPException(status_code=500, detail=res.get("error", "Investigation failed."))

    return res
