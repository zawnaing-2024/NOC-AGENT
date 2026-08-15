import logging
from typing import Dict, Any, List, Optional

from app.db.database import db

logger = logging.getLogger("mikrotik_noc_agent.evidence_builder")


class EvidenceBuilderError(Exception):
    """Exception raised when required evidence cannot be assembled."""
    pass


class EvidenceBuilder:
    """
    Assembles complete, machine-readable, deterministic evidence objects from SQLite telemetry
    for LM Studio AI RCA and device health evaluation.
    Enforces strict evidence grounding: zero LLM direct database access or hallucinated facts.
    """

    @staticmethod
    def build_incident_evidence(incident_id: str) -> Dict[str, Any]:
        """
        Builds a comprehensive evidence payload for a correlated AIOps incident.
        Collects device info, root event, correlated events, and domain-specific telemetry context.
        """
        inc = db.get_incident_by_id(incident_id)
        if not inc:
            raise EvidenceBuilderError(f"Incident '{incident_id}' not found in SQLite database.")

        dev_id = inc["device_id"]
        root_evt = db.get_event_by_id(inc["root_event_id"])
        
        corr_events = []
        for eid in inc.get("correlated_event_ids", []):
            if eid != inc["root_event_id"]:
                evt = db.get_event_by_id(eid)
                if evt:
                    corr_events.append({
                        "event_id": evt["event_id"],
                        "type": evt["type"],
                        "severity": evt["severity"],
                        "entity": evt["entity"],
                        "evidence": evt.get("evidence", {}),
                        "first_seen": evt.get("first_seen"),
                        "last_seen": evt.get("last_seen"),
                        "occurrence_count": evt.get("occurrence_count", 1)
                    })

        # Telemetry context collection
        sys_metrics = db.get_recent_device_metrics(dev_id, limit=5)
        iface_metrics = db.get_recent_interface_metrics(dev_id, limit=10)
        bgp_metrics = db.get_recent_bgp_metrics(dev_id, limit=5)
        ospf_metrics = db.get_recent_ospf_metrics(dev_id, limit=5)

        with db.get_connection() as conn:
            routes = [dict(r) for r in conn.execute("SELECT * FROM route_metrics WHERE device_id = ? ORDER BY id DESC LIMIT 10", (dev_id,)).fetchall()]
            nat_rules = [dict(r) for r in conn.execute("SELECT * FROM nat_metrics WHERE device_id = ? ORDER BY id DESC LIMIT 10", (dev_id,)).fetchall()]

        deterministic_findings = []
        if root_evt:
            deterministic_findings.append(f"Root Event: {root_evt['type']} on entity '{root_evt['entity']}' (Severity: {root_evt['severity']})")
        for e in corr_events:
            deterministic_findings.append(f"Correlated Event: {e['type']} on entity '{e['entity']}' (Severity: {e['severity']})")

        return {
            "incident": {
                "incident_id": inc["incident_id"],
                "device_id": dev_id,
                "severity": inc["severity"],
                "status": inc["status"],
                "created_at": inc["created_at"],
                "updated_at": inc["updated_at"],
                "event_count": inc.get("event_count", 1),
                "occurrence_count": inc.get("occurrence_count", 1),
                "confidence": inc.get("confidence", "HIGH"),
                "facts": inc.get("facts", {})
            },
            "root_event": {
                "event_id": root_evt["event_id"] if root_evt else "unknown",
                "type": root_evt["type"] if root_evt else "UNKNOWN",
                "severity": root_evt["severity"] if root_evt else "MAJOR",
                "source": root_evt["source"] if root_evt else "deterministic_engine",
                "entity": root_evt["entity"] if root_evt else "unknown",
                "evidence": root_evt.get("evidence", {}) if root_evt else {},
                "first_seen": root_evt.get("first_seen") if root_evt else None,
                "last_seen": root_evt.get("last_seen") if root_evt else None,
                "occurrence_count": root_evt.get("occurrence_count", 1) if root_evt else 1
            },
            "correlated_events": corr_events,
            "telemetry_context": {
                "recent_system": sys_metrics,
                "recent_interfaces": iface_metrics,
                "recent_bgp": bgp_metrics,
                "recent_ospf": ospf_metrics,
                "recent_routes": routes,
                "recent_nat": nat_rules
            },
            "deterministic_findings": deterministic_findings
        }

    @staticmethod
    def build_device_evidence(device_id: str) -> Dict[str, Any]:
        """
        Builds a comprehensive health evidence payload for a targeted MikroTik device.
        """
        devices = db.get_devices()
        dev_info = next((d for d in devices if d["device_id"] == device_id), None)
        
        sys_metrics = db.get_recent_device_metrics(device_id, limit=10)
        iface_metrics = db.get_recent_interface_metrics(device_id, limit=20)
        bgp_metrics = db.get_recent_bgp_metrics(device_id, limit=10)
        ospf_metrics = db.get_recent_ospf_metrics(device_id, limit=10)
        active_events = db.get_events(device_id=device_id, limit=20)

        with db.get_connection() as conn:
            active_incidents = [dict(r) for r in conn.execute("SELECT * FROM incidents WHERE device_id = ? AND status IN ('OPEN', 'ACKNOWLEDGED') ORDER BY created_at DESC", (device_id,)).fetchall()]
            routes = [dict(r) for r in conn.execute("SELECT * FROM route_metrics WHERE device_id = ? ORDER BY id DESC LIMIT 10", (device_id,)).fetchall()]
            nat_rules = [dict(r) for r in conn.execute("SELECT * FROM nat_metrics WHERE device_id = ? ORDER BY id DESC LIMIT 10", (device_id,)).fetchall()]

        return {
            "device": dev_info or {"device_id": device_id, "status": "UNKNOWN"},
            "active_incidents_count": len(active_incidents),
            "active_events_count": len(active_events),
            "active_incidents": active_incidents,
            "active_events": active_events,
            "telemetry": {
                "system": sys_metrics,
                "interfaces": iface_metrics,
                "bgp": bgp_metrics,
                "ospf": ospf_metrics,
                "routes": routes,
                "nat": nat_rules
            }
        }
