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

        # 3. Phase 6.1 Intelligent Traffic Drop & Interface Deep Investigation
        traffic_inv = None
        if "TRAFFIC" in primary_failure or "INTERFACE" in primary_failure:
            try:
                traffic_inv = DeepNocInvestigator._investigate_traffic_drop_and_interface(device_id, primary_entity)
            except Exception as ex:
                logger.warning(f"Traffic drop deep investigation error for {primary_entity}: {ex}")

        # 4. Construct Cascade Flow Diagram
        visualization_flow = DeepNocInvestigator._build_visualization_flow(primary_failure, primary_entity, correlated_events)

        # 5. Generate Actionable Troubleshooting Checks (Read-Only)
        recommendations = DeepNocInvestigator._build_recommendations(primary_failure, primary_entity)

        # 6. Invoke OpenRouter AI RCA Analysis (or report unavailable gracefully)
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
            "traffic_investigation": traffic_inv,
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

    @staticmethod
    def _investigate_traffic_drop_and_interface(device_id: str, interface_name: str) -> Dict[str, Any]:
        """
        Phase 6.1 Deterministic Traffic Drop & Interface Root-Cause Investigation:
        1. Calculates RX & TX bandwidth drop magnitude, percentage, rate of change (SHARP vs GRADUAL), and severity.
        2. Queries RouterOS API for interface state (running, disabled, link-downs, errors, drops).
        3. Queries /ip/address to verify if interface has an assigned IP address (HAS_IP = True/False).
        4. Selects a safe next-hop/peer destination IP and runs RouterOS API ping test.
        5. Queries optical transceiver Rx/Tx power levels (SFP/SFP+).
        6. Audits system log entries for link flaps or carrier loss.
        7. Constructs deterministic decision tree execution path.
        """
        from app.tools.routeros import (
            get_routeros_client,
            parse_bool_safe,
            parse_int_safe,
            query_interface_ip_address,
            query_interface_ping_test,
            query_interface_optical_power,
            query_interface_logs,
            classify_interface_media,
        )

        decision_tree_path = ["START_TRAFFIC_DROP_INVESTIGATION"]
        
        # 1. Fetch historical interface metrics from DB for magnitude & time series analysis
        history = db.get_recent_interface_metrics(device_id, interface_name, limit=50)
        history.reverse()  # Oldest to newest

        time_series = []
        rx_values = []
        tx_values = []
        for h in history:
            rx_val = float(h.get("rx_bps") or 0.0)
            tx_val = float(h.get("tx_bps") or 0.0)
            rx_values.append(rx_val)
            tx_values.append(tx_val)
            time_series.append({
                "timestamp": h.get("timestamp"),
                "rx_bps": rx_val,
                "tx_bps": tx_val,
                "rx_formatted": format_bandwidth(rx_val),
                "tx_formatted": format_bandwidth(tx_val)
            })

        # Calculate RX Traffic Drop Magnitude
        if len(rx_values) >= 2:
            prev_rx = rx_values[-2] if len(rx_values) >= 2 else rx_values[0]
            curr_rx = rx_values[-1]
            base_rx = sum(rx_values[:-1]) / max(1, len(rx_values) - 1) if len(rx_values) > 1 else prev_rx
        else:
            prev_rx = rx_values[0] if rx_values else 0.0
            curr_rx = rx_values[0] if rx_values else 0.0
            base_rx = prev_rx

        rx_abs_drop = max(0.0, prev_rx - curr_rx)
        rx_pct_drop = ((prev_rx - curr_rx) / max(1.0, prev_rx)) * 100.0 if prev_rx > 0 else 0.0

        # Severity Classification
        if rx_pct_drop >= 80.0: rx_sev = "CRITICAL"
        elif rx_pct_drop >= 50.0: rx_sev = "SEVERE"
        elif rx_pct_drop >= 30.0: rx_sev = "MODERATE"
        elif rx_pct_drop >= 10.0: rx_sev = "SLIGHT"
        else: rx_sev = "NORMAL"

        # Rate of change: SHARP vs GRADUAL
        rx_rate_type = "SHARP" if (rx_pct_drop > 50.0 or len(rx_values) <= 3) else "GRADUAL"

        rx_change = {
            "direction": "RX",
            "baseline_bps": base_rx,
            "previous_bps": prev_rx,
            "current_bps": curr_rx,
            "absolute_drop_bps": rx_abs_drop,
            "percentage_drop": round(rx_pct_drop, 2),
            "severity": rx_sev,
            "rate_classification": rx_rate_type,
            "baseline_formatted": format_bandwidth(base_rx),
            "previous_formatted": format_bandwidth(prev_rx),
            "current_formatted": format_bandwidth(curr_rx),
            "drop_formatted": format_bandwidth(rx_abs_drop)
        }

        # Calculate TX Traffic Drop Magnitude
        if len(tx_values) >= 2:
            prev_tx = tx_values[-2] if len(tx_values) >= 2 else tx_values[0]
            curr_tx = tx_values[-1]
            base_tx = sum(tx_values[:-1]) / max(1, len(tx_values) - 1) if len(tx_values) > 1 else prev_tx
        else:
            prev_tx = tx_values[0] if tx_values else 0.0
            curr_tx = tx_values[0] if tx_values else 0.0
            base_tx = prev_tx

        tx_abs_drop = max(0.0, prev_tx - curr_tx)
        tx_pct_drop = ((prev_tx - curr_tx) / max(1.0, prev_tx)) * 100.0 if prev_tx > 0 else 0.0

        if tx_pct_drop >= 80.0: tx_sev = "CRITICAL"
        elif tx_pct_drop >= 50.0: tx_sev = "SEVERE"
        elif tx_pct_drop >= 30.0: tx_sev = "MODERATE"
        elif tx_pct_drop >= 10.0: tx_sev = "SLIGHT"
        else: tx_sev = "NORMAL"

        tx_rate_type = "SHARP" if (tx_pct_drop > 50.0 or len(tx_values) <= 3) else "GRADUAL"

        tx_change = {
            "direction": "TX",
            "baseline_bps": base_tx,
            "previous_bps": prev_tx,
            "current_bps": curr_tx,
            "absolute_drop_bps": tx_abs_drop,
            "percentage_drop": round(tx_pct_drop, 2),
            "severity": tx_sev,
            "rate_classification": tx_rate_type,
            "baseline_formatted": format_bandwidth(base_tx),
            "previous_formatted": format_bandwidth(prev_tx),
            "current_formatted": format_bandwidth(curr_tx),
            "drop_formatted": format_bandwidth(tx_abs_drop)
        }

        decision_tree_path.append("CALCULATE_TRAFFIC_DECREASE")

        # 2. Live RouterOS API Checks
        iface_state = {"status": "UNKNOWN", "running": False, "disabled": False}
        iface_raw_dict = {}
        ip_info = {"has_ip": False}
        ping_res = {"reachable": False}
        optical_info = {"supported": False}
        media_info = {"media_type": "UNKNOWN", "confidence": "LOW", "reason": "Not evaluated", "optical_capable": False}
        recent_logs = []

        try:
            with get_routeros_client(host=device_id) as api:
                # A. Query Interface State & Metadata
                p_if = api.path("/interface")
                for item in list(p_if):
                    if str(item.get("name", "")).lower() == interface_name.lower():
                        iface_raw_dict = item
                        iface_state = {
                            "name": interface_name,
                            "type": str(item.get("type", "ether")),
                            "running": parse_bool_safe(item.get("running"), False),
                            "disabled": parse_bool_safe(item.get("disabled"), False),
                            "link_downs": parse_int_safe(item.get("link-downs"), 0),
                            "rx_bytes": parse_int_safe(item.get("rx-byte", item.get("rx-bytes", 0))),
                            "tx_bytes": parse_int_safe(item.get("tx-byte", item.get("tx-bytes", 0))),
                            "rx_errors": parse_int_safe(item.get("rx-error", item.get("rx-errors", 0))),
                            "tx_errors": parse_int_safe(item.get("tx-error", item.get("tx-errors", 0))),
                            "rx_drops": parse_int_safe(item.get("rx-drop", item.get("rx-drops", 0))),
                            "tx_drops": parse_int_safe(item.get("tx-drop", item.get("tx-drops", 0))),
                            "mac_address": str(item.get("mac-address", "")),
                            "comment": str(item.get("comment", ""))
                        }
                        break

                decision_tree_path.append("CHECK_INTERFACE_STATE")

                # B. Query Optical Transceiver Info (if supported)
                optical_info = query_interface_optical_power(api, interface_name)

                # C. Perform Deterministic Interface Media Classification
                media_info = classify_interface_media(iface_raw_dict or {"name": interface_name, "type": iface_state.get("type", "ether")}, optical_info)
                decision_tree_path.append(f"CLASSIFY_MEDIA({media_info['media_type']})")

                # Decision Tree: If link is physical DOWN vs UP
                if not iface_state.get("running"):
                    decision_tree_path.append("INTERFACE_STATE_DOWN")
                    decision_tree_path.append("PHYSICAL_LINK_FAILURE")
                else:
                    decision_tree_path.append("INTERFACE_STATE_UP")
                    # D. Check IP Address
                    ip_info = query_interface_ip_address(api, interface_name)
                    if ip_info.get("has_ip"):
                        decision_tree_path.append("HAS_IP_TRUE")
                        target_dest = None
                        bgp_peers = db.get_recent_bgp_metrics(device_id)
                        if bgp_peers and bgp_peers[0].get("remote_address"):
                            target_dest = bgp_peers[0]["remote_address"]
                        elif ip_info.get("ip_address"):
                            parts = ip_info["ip_address"].split(".")
                            if len(parts) == 4:
                                last_octet = int(parts[3])
                                peer_octet = last_octet - 1 if last_octet % 2 == 0 else last_octet + 1
                                target_dest = f"{parts[0]}.{parts[1]}.{parts[2]}.{peer_octet}"

                        if target_dest:
                            decision_tree_path.append(f"PING_DESTINATION_SELECTED({target_dest})")
                            ping_res = query_interface_ping_test(api, target_dest, count=5)
                            if ping_res.get("reachable"):
                                decision_tree_path.append("PING_REACHABLE_OK")
                            else:
                                decision_tree_path.append("PING_UNREACHABLE_FAIL")
                                decision_tree_path.append("L3_CONNECTIVITY_FAILURE")
                        else:
                            decision_tree_path.append("NO_VALID_DESTINATION")
                    else:
                        decision_tree_path.append("HAS_IP_FALSE")
                        decision_tree_path.append("L2_INTERFACE_INVESTIGATION")

                # Media Workflow Branching
                if media_info["media_type"] == "ELECTRICAL":
                    decision_tree_path.append("ELECTRICAL_COPPER_CHECK")
                elif media_info["media_type"] == "OPTICAL":
                    decision_tree_path.append("OPTICAL_SFP_POWER_CHECK")
                elif media_info["media_type"] in ["VLAN", "BRIDGE", "BONDING", "VIRTUAL", "LOOPBACK"]:
                    decision_tree_path.append(f"LOGICAL_{media_info['media_type']}_CHECK")

                # E. Audit System Logs
                recent_logs = query_interface_logs(api, interface_name, limit=10)
                if recent_logs:
                    decision_tree_path.append("ROUTEROS_LOGS_AUDITED")

        except Exception as ex:
            logger.warning(f"Live RouterOS API checks during investigation encountered exception: {ex}")
            decision_tree_path.append(f"ROUTEROS_API_EXCEPTION({str(ex)})")

        return {
            "interface_name": interface_name,
            "device_id": device_id,
            "rx_traffic_change": rx_change,
            "tx_traffic_change": tx_change,
            "time_series": time_series,
            "media_classification": media_info,
            "interface_state": iface_state,
            "ip_investigation": ip_info,
            "ping_investigation": ping_res,
            "optical_power": optical_info,
            "recent_logs": recent_logs,
            "decision_tree_path": decision_tree_path
        }
