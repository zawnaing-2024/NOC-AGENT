import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

from app.db.database import db

logger = logging.getLogger("mikrotik_noc_agent.context_builder")

PRIORITY_HIERARCHY = {
    "DEVICE_DOWN": 1,
    "INTERFACE_DOWN": 2,
    "BGP_SESSION_DOWN": 3,
    "OSPF_NEIGHBOR_DOWN": 4,
    "DEFAULT_ROUTE_DOWN": 5,
    "TRAFFIC_DROP": 6,
    "INTERFACE_ERROR": 7,
    "INTERFACE_DROP": 8,
    "BGP_PREFIX_DROP": 9,
    "CPU_SPIKE": 10,
    "MEMORY_SPIKE": 10,
    "NAT_DEPENDENCY_DOWN": 11,
}


class ContextBuilder:
    """Assembles structured evidence payloads, evidence rankings, and chronological timelines for OpenRouter AI RCA."""

    @staticmethod
    def build_incident_context(incident_id: str) -> Dict[str, Any]:
        """
        Builds complete evidence payload, ranked symptoms, and chronological incident timeline for an incident.
        """
        inc = db.get_incident_by_id(incident_id)
        if not inc:
            # Fallback: check if target ID matches an event_id
            evt = db.get_event_by_id(incident_id)
            if evt:
                inc = {
                    "incident_id": f"INC-{evt['event_id'][:8]}",
                    "device_id": evt["device_id"],
                    "created_at": evt.get("first_seen") or evt.get("timestamp"),
                    "updated_at": evt.get("last_seen") or evt.get("timestamp"),
                    "severity": evt.get("severity", "MAJOR"),
                    "status": evt.get("status", "ACTIVE"),
                    "root_event_id": evt["event_id"],
                    "correlated_event_ids": [evt["event_id"]],
                    "event_count": 1,
                    "occurrence_count": evt.get("occurrence_count", 1),
                    "confidence": "HIGH",
                    "facts": evt.get("evidence", {}),
                    "summary": f"Event {evt['type']} on {evt['entity']}",
                    "llm_status": "PENDING"
                }
            else:
                devs = db.get_devices()
                target_dev = devs[0]["device_id"] if devs else "37.111.52.51"
                inc = {
                    "incident_id": incident_id,
                    "device_id": target_dev,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                    "severity": "MAJOR",
                    "status": "ACTIVE",
                    "root_event_id": incident_id,
                    "correlated_event_ids": [incident_id],
                    "event_count": 1,
                    "occurrence_count": 1,
                    "confidence": "MEDIUM",
                    "facts": {},
                    "summary": "Target event/incident investigation",
                    "llm_status": "PENDING"
                }

        dev_id = inc["device_id"]
        root_evt = db.get_event_by_id(inc["root_event_id"])
        
        corr_events = []
        for eid in inc.get("correlated_event_ids", []):
            if eid != inc["root_event_id"]:
                evt = db.get_event_by_id(eid)
                if evt:
                    corr_events.append(evt)

        # Build Chronological Timeline
        all_evts = ([root_evt] if root_evt else []) + corr_events
        all_evts.sort(key=lambda e: e.get("first_seen") or e.get("timestamp", ""))

        timeline = []
        for e in all_evts:
            timeline.append({
                "timestamp": e.get("first_seen") or e.get("timestamp"),
                "event_id": e.get("event_id"),
                "type": e.get("type"),
                "entity": e.get("entity"),
                "severity": e.get("severity"),
                "evidence": e.get("evidence", {})
            })

        # Telemetry context collection
        sys_metrics = db.get_recent_device_metrics(dev_id, limit=5)
        iface_metrics = db.get_recent_interface_metrics(dev_id, limit=10)
        bgp_metrics = db.get_recent_bgp_metrics(dev_id, limit=5)
        ospf_metrics = db.get_recent_ospf_metrics(dev_id, limit=5)

        with db.get_connection() as conn:
            routes = [dict(r) for r in conn.execute("SELECT * FROM route_metrics WHERE device_id = ? ORDER BY id DESC LIMIT 10", (dev_id,)).fetchall()]
            nat_rules = [dict(r) for r in conn.execute("SELECT * FROM nat_metrics WHERE device_id = ? ORDER BY id DESC LIMIT 10", (dev_id,)).fetchall()]

        # Rank evidence priority
        root_type = root_evt["type"] if root_evt else "UNKNOWN"
        root_priority = PRIORITY_HIERARCHY.get(root_type, 99)

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
            "root_cause_candidate": {
                "event_id": root_evt["event_id"] if root_evt else "unknown",
                "type": root_type,
                "priority_rank": root_priority,
                "severity": root_evt["severity"] if root_evt else "MAJOR",
                "entity": root_evt["entity"] if root_evt else "unknown",
                "evidence": root_evt.get("evidence", {}) if root_evt else {}
            },
            "timeline": timeline,
            "telemetry": {
                "system": sys_metrics,
                "interfaces": iface_metrics,
                "bgp": bgp_metrics,
                "ospf": ospf_metrics,
                "routes": routes,
                "nat": nat_rules
            }
        }
