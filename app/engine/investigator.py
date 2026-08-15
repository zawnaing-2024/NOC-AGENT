import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from app.db.database import db
from app.ai.context_builder import ContextBuilder
from app.ai.agent import AIAgentService

logger = logging.getLogger("mikrotik_noc_agent.investigator")


def format_bandwidth(bps: float) -> str:
    """Formats numeric bits-per-second into human-readable Gbps, Mbps, Kbps, or bps."""
    val = float(bps or 0.0)
    if val >= 1_000_000_000:
        return f"{val / 1_000_000_000:.2f} Gbps"
    elif val >= 1_000_000:
        return f"{val / 1_000_000:.2f} Mbps"
    elif val >= 1_000:
        return f"{val / 1_000:.1f} Kbps"
    else:
        return f"{val:.0f} bps"


class DeepNocInvestigator:
    """
    Phase 6 Deterministic Deep NOC Investigation Engine.
    Correlates telemetry, builds human-readable evidence tables, constructs visual cascade flow graphs,
    provides actionable recommendations, and integrates OpenRouter AI RCA responses safely.
    """

    @staticmethod
    def run_investigation(incident_id: str) -> Dict[str, Any]:
        """Runs a complete deep NOC investigation for a given incident."""
        inc = db.get_incident_by_id(incident_id)
        if not inc:
            return {"error": f"Incident '{incident_id}' not found.", "status": "FAILED"}

        device_id = inc["device_id"]
        ctx = ContextBuilder.build_incident_context(incident_id)
        correlated_events = ctx.get("correlated_events", [])
        root_cause_candidate = ctx.get("root_cause_candidate", {})

        # 1. Determine Primary Failure & Secondary Symptoms
        primary_failure = root_cause_candidate.get("type") or root_cause_candidate.get("event_type") or inc.get("facts", {}).get("event_type", "UNKNOWN_ANOMALY")
        primary_entity = root_cause_candidate.get("entity") or inc.get("facts", {}).get("entity", "system")

        secondary_symptoms = []
        for evt in correlated_events:
            if evt["event_id"] != root_cause_candidate.get("event_id"):
                secondary_symptoms.append(f"{evt['type']} on {evt['entity']} ({evt['severity']})")

        # 2. Build Human-Readable Evidence Table
        evidence_table = DeepNocInvestigator._build_human_readable_evidence(ctx, primary_failure, primary_entity)

        # 3. Construct Cascade Flow Diagram
        visualization_flow = DeepNocInvestigator._build_visualization_flow(primary_failure, primary_entity, correlated_events)

        # 4. Generate Actionable Troubleshooting Checks (Read-Only)
        recommendations = DeepNocInvestigator._build_recommendations(primary_failure, primary_entity)

        # 5. Invoke OpenRouter AI RCA Analysis (or report unavailable gracefully)
        try:
            ai_res = AIAgentService.analyze_incident(incident_id)
            ai_analysis = ai_res.get("analysis") if ai_res.get("success") else None
            ai_status = "COMPLETED" if ai_res.get("success") else ("AI_UNAVAILABLE" if ai_res.get("error") == "AI_PROVIDER_UNAVAILABLE" else "FAILED")
        except Exception as e:
            logger.warning(f"AI RCA analysis unavailable during investigation: {e}")
            ai_analysis = None
            ai_status = "AI_UNAVAILABLE"

        investigation_id = f"inv-{uuid.uuid4().hex[:8]}"
        now_ts = datetime.now(timezone.utc).isoformat()

        inv_record = {
            "investigation_id": investigation_id,
            "incident_id": incident_id,
            "device_id": device_id,
            "created_at": now_ts,
            "status": "COMPLETED",
            "primary_failure": f"{primary_failure} on {primary_entity}",
            "secondary_symptoms": secondary_symptoms,
            "evidence": evidence_table,
            "recommendations": recommendations,
            "visualization_flow": visualization_flow,
            "ai_analysis_status": ai_status,
            "ai_analysis": ai_analysis,
            "timeline": ctx.get("timeline", []),
            "raw_context": ctx
        }

        # Persist investigation
        db.upsert_investigation(inv_record)
        logger.info(f"Deep NOC Investigation completed for incident {incident_id} (Primary Failure: {primary_failure} on {primary_entity}).")
        return inv_record

    @staticmethod
    def _build_human_readable_evidence(ctx: Dict[str, Any], failure_type: str, entity: str) -> List[Dict[str, Any]]:
        """Constructs human-readable evidence rows with clear observed vs baseline parameters."""
        evidence = []
        metrics = ctx.get("device_metrics", [])
        curr_metric = metrics[0] if metrics else {}

        if "CPU" in failure_type or "MEMORY" in failure_type:
            evidence.append({
                "fact": f"High {failure_type} detected",
                "parameter": "CPU Usage",
                "observed_value": f"{curr_metric.get('cpu_percent', 'N/A')}%",
                "baseline_value": "< 80.0%",
                "timestamp": curr_metric.get("timestamp", "recent"),
                "source": "RouterOS API /system/resource",
                "confidence": "HIGH"
            })
            evidence.append({
                "fact": "Memory Consumption",
                "parameter": "RAM Usage",
                "observed_value": f"{curr_metric.get('memory_percent', 'N/A')}%",
                "baseline_value": "< 85.0%",
                "timestamp": curr_metric.get("timestamp", "recent"),
                "source": "RouterOS API /system/resource",
                "confidence": "HIGH"
            })

        if "INTERFACE" in failure_type or "TRAFFIC" in failure_type:
            ifaces = ctx.get("interface_metrics", [])
            target_if = next((i for i in ifaces if i.get("interface_name") == entity), ifaces[0] if ifaces else {})
            evidence.append({
                "fact": f"Interface {entity} Operational State",
                "parameter": "Running Status",
                "observed_value": "DOWN / NOT_RUNNING" if target_if.get("running") == 0 else "UP / RUNNING",
                "baseline_value": "UP / RUNNING",
                "timestamp": target_if.get("timestamp", "recent"),
                "source": "RouterOS API /interface/print",
                "confidence": "CRITICAL"
            })
            evidence.append({
                "fact": f"Interface {entity} Bandwidth Rate",
                "parameter": "RX / TX Rate",
                "observed_value": f"RX: {format_bandwidth(target_if.get('rx_bps', 0))}, TX: {format_bandwidth(target_if.get('tx_bps', 0))}",
                "baseline_value": "> Moving Average",
                "timestamp": target_if.get("timestamp", "recent"),
                "source": "RouterOS API /interface/monitor-traffic",
                "confidence": "HIGH"
            })

        if "BGP" in failure_type:
            bgp_peers = ctx.get("bgp_metrics", [])
            target_bgp = next((b for b in bgp_peers if b.get("peer") == entity), bgp_peers[0] if bgp_peers else {})
            evidence.append({
                "fact": f"BGP Peer {entity} Session State",
                "parameter": "Established Status",
                "observed_value": "DOWN / IDLE" if target_bgp.get("established") == 0 else "ESTABLISHED",
                "baseline_value": "ESTABLISHED",
                "timestamp": target_bgp.get("timestamp", "recent"),
                "source": "RouterOS API /routing/bgp/peer",
                "confidence": "CRITICAL"
            })
            evidence.append({
                "fact": f"BGP Peer {entity} Active Prefixes",
                "parameter": "Prefix Count",
                "observed_value": str(target_bgp.get("prefix_count", 0)),
                "baseline_value": "> 0 Prefixes",
                "timestamp": target_bgp.get("timestamp", "recent"),
                "source": "RouterOS API /routing/bgp/peer",
                "confidence": "HIGH"
            })

        if "ROUTE" in failure_type:
            routes = ctx.get("route_metrics", [])
            def_route = next((r for r in routes if r.get("dst_address") in ["0.0.0.0/0", "default"]), {})
            evidence.append({
                "fact": "Default Route 0.0.0.0/0 Reachability",
                "parameter": "Active Gateway Status",
                "observed_value": "UNAVAILABLE" if def_route.get("active") == 0 else "ACTIVE",
                "baseline_value": "ACTIVE",
                "timestamp": def_route.get("timestamp", "recent"),
                "source": "RouterOS API /ip/route",
                "confidence": "CRITICAL"
            })

        # Add event evidence rows
        for evt in ctx.get("correlated_events", []):
            evidence.append({
                "fact": f"Correlated Event: {evt['type']}",
                "parameter": f"Entity: {evt['entity']}",
                "observed_value": f"Status: {evt['status']}, Occurrences: {evt['occurrence_count']}",
                "baseline_value": "NO_ANOMALY",
                "timestamp": evt.get("last_seen", evt.get("first_seen", "recent")),
                "source": "Deterministic Anomaly Engine",
                "confidence": evt["severity"]
            })

        return evidence

    @staticmethod
    def _build_visualization_flow(failure_type: str, entity: str, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Constructs visual cascade flow graph highlighting primary failure vs secondary symptoms."""
        event_types = set([e["type"] for e in events] + [failure_type])

        flow = [
            {
                "step": 1,
                "domain": "INTERFACE",
                "title": f"Interface State ({entity if 'INTERFACE' in failure_type or 'TRAFFIC' in failure_type else 'WAN'})",
                "status": "CRITICAL" if "INTERFACE_DOWN" in event_types else ("WARNING" if "TRAFFIC_DROP" in event_types or "INTERFACE_ERROR" in event_types else "HEALTHY"),
                "is_primary_root": "INTERFACE" in failure_type or "TRAFFIC" in failure_type
            },
            {
                "step": 2,
                "domain": "BGP",
                "title": f"BGP Session State ({entity if 'BGP' in failure_type else 'Peers'})",
                "status": "CRITICAL" if "BGP_SESSION_DOWN" in event_types else ("WARNING" if "BGP_PREFIX_DROP" in event_types else "HEALTHY"),
                "is_primary_root": "BGP_SESSION_DOWN" in failure_type
            },
            {
                "step": 3,
                "domain": "PREFIXES",
                "title": "BGP Prefix Count",
                "status": "WARNING" if "BGP_PREFIX_DROP" in event_types or "BGP_SESSION_DOWN" in event_types else "HEALTHY",
                "is_primary_root": "BGP_PREFIX_DROP" in failure_type
            },
            {
                "step": 4,
                "domain": "ROUTES",
                "title": "Default Route 0.0.0.0/0",
                "status": "CRITICAL" if "DEFAULT_ROUTE_DOWN" in event_types else "HEALTHY",
                "is_primary_root": "DEFAULT_ROUTE_DOWN" in failure_type
            },
            {
                "step": 5,
                "domain": "IMPACT",
                "title": "Customer / Transit Service Impact",
                "status": "CRITICAL" if any(k in event_types for k in ["DEFAULT_ROUTE_DOWN", "BGP_SESSION_DOWN", "INTERFACE_DOWN"]) else "WARNING",
                "is_primary_root": False
            }
        ]
        return flow

    @staticmethod
    def _build_recommendations(failure_type: str, entity: str) -> List[Dict[str, Any]]:
        """Generates actionable troubleshooting checks for NOC engineers (Informational Only)."""
        recs = []
        if "INTERFACE" in failure_type or "TRAFFIC" in failure_type:
            recs.append({"step": 1, "check": f"Inspect physical optical fiber patch cable and SFP+ transceiver status on interface '{entity}'.", "command": f"/interface print detail where name=\"{entity}\""})
            recs.append({"step": 2, "check": "Verify optical Rx/Tx power levels to confirm physical link layer health.", "command": f"/interface ethernet monitor {entity} once"})
            recs.append({"step": 3, "check": "Check upstream switch/router port state on the remote interconnect side.", "command": "Inspect upstream provider port state"})

        elif "BGP" in failure_type:
            recs.append({"step": 1, "check": f"Verify BGP TCP port 179 reachability to peer IP '{entity}'.", "command": f"/ping {entity} count=5"})
            recs.append({"step": 2, "check": "Inspect BGP connection status and recent error logs.", "command": f"/routing bgp session print detail where remote.address=\"{entity}\""})
            recs.append({"step": 3, "check": "Verify local AS number and remote AS configuration parameters.", "command": "/routing bgp connection print"})

        elif "OSPF" in failure_type:
            recs.append({"step": 1, "check": f"Verify OSPF hello packet exchange with neighbor '{entity}'.", "command": f"/routing ospf neighbor print detail where instance=\"default\""})
            recs.append({"step": 2, "check": "Confirm matching OSPF Area ID, Hello Interval, and MTU settings.", "command": "/routing ospf interface-template print"})

        elif "CPU" in failure_type or "MEMORY" in failure_type:
            recs.append({"step": 1, "check": "Inspect top CPU-consuming RouterOS software processes.", "command": "/system resource cpu print"})
            recs.append({"step": 2, "check": "Check firewall rule counters and connection tracking table size.", "command": "/ip firewall connection tracking print"})

        else:
            recs.append({"step": 1, "check": f"Inspect device operational status for entity '{entity}'.", "command": "/system resource print"})
            recs.append({"step": 2, "check": "Check system logs for hardware or network interface events.", "command": "/log print follow-only=no"})

        return recs
