import uuid
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

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


class InvestigationStepRecord(BaseModel):
    step_id: str
    name: str
    status: str  # "NOT_STARTED", "IN_PROGRESS", "COMPLETED", "FAILED", "SKIPPED", "NOT_APPLICABLE"
    started_at: str
    completed_at: Optional[str] = None
    duration_ms: int = 0
    evidence: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    reason: Optional[str] = None


def update_step(steps: List[Dict[str, Any]], step_id: str, status: str, evidence: Optional[Any] = None, error: Optional[str] = None, reason: Optional[str] = None):
    """Updates status and metadata for a specific investigation step."""
    now_ts = datetime.now(timezone.utc).isoformat()
    for s in steps:
        if s["step_id"] == step_id:
            s["status"] = status
            s["completed_at"] = now_ts
            if evidence is not None:
                s["evidence"] = evidence
            if error is not None:
                s["error"] = error
            if reason is not None:
                s["reason"] = reason
            break


def calculate_traffic_direction_and_deviation(direction: str, values: List[float]) -> Dict[str, Any]:
    """
    Phase 6.3 Traffic Change Math:
    Calculates sample-to-sample short-term change (previous -> current) AND baseline deviation (current vs baseline) independently.
    Handles direction (INCREASE vs DROP vs NO_CHANGE) accurately without confusing short-term rate with baseline.
    """
    if len(values) >= 2:
        prev_val = values[-2]
        curr_val = values[-1]
        base_val = sum(values[:-1]) / max(1, len(values) - 1)
    elif len(values) == 1:
        prev_val = values[0]
        curr_val = values[0]
        base_val = values[0]
    else:
        prev_val = 0.0
        curr_val = 0.0
        base_val = 0.0

    # 1. Short-Term Sample-to-Sample Change (previous -> current)
    if curr_val > prev_val:
        dir_type = "INCREASE"
        abs_change = curr_val - prev_val
        pct_change = ((curr_val - prev_val) / max(1.0, prev_val)) * 100.0 if prev_val > 0 else 100.0
        short_term_formatted = f"▲ +{pct_change:.2f}% ({format_bandwidth(abs_change)})"
    elif curr_val < prev_val:
        dir_type = "DROP"
        abs_change = prev_val - curr_val
        pct_change = ((prev_val - curr_val) / max(1.0, prev_val)) * 100.0 if prev_val > 0 else 100.0
        short_term_formatted = f"▼ -{pct_change:.2f}% ({format_bandwidth(abs_change)})"
    else:
        dir_type = "NO_CHANGE"
        abs_change = 0.0
        pct_change = 0.0
        short_term_formatted = "● 0.00% (0 bps)"

    # 2. Baseline Deviation (current vs moving baseline)
    if curr_val < base_val:
        base_dev_pct = ((base_val - curr_val) / max(1.0, base_val)) * 100.0
        base_dev_formatted = f"▼ {base_dev_pct:.2f}% BELOW BASELINE"
    elif curr_val > base_val:
        base_dev_pct = ((curr_val - base_val) / max(1.0, base_val)) * 100.0
        base_dev_formatted = f"▲ {base_dev_pct:.2f}% ABOVE BASELINE"
    else:
        base_dev_pct = 0.0
        base_dev_formatted = "● ON BASELINE"

    if base_dev_pct >= 80.0 and curr_val < base_val:
        severity = "CRITICAL"
    elif base_dev_pct >= 50.0 and curr_val < base_val:
        severity = "SEVERE"
    elif base_dev_pct >= 30.0 and curr_val < base_val:
        severity = "MODERATE"
    elif base_dev_pct >= 10.0 and curr_val < base_val:
        severity = "SLIGHT"
    else:
        severity = "NORMAL"

    rate_class = "SHARP" if (pct_change > 50.0 or len(values) <= 3) else "GRADUAL"

    return {
        "direction": direction,
        "baseline_bps": base_val,
        "previous_bps": prev_val,
        "current_bps": curr_val,
        "short_term_direction": dir_type,
        "short_term_absolute_bps": abs_change,
        "short_term_percentage": round(pct_change, 2),
        "short_term_formatted": short_term_formatted,
        "baseline_deviation_percentage": round(base_dev_pct, 2),
        "baseline_deviation_formatted": base_dev_formatted,
        "severity": severity,
        "rate_classification": rate_class,
        "baseline_formatted": format_bandwidth(base_val),
        "previous_formatted": format_bandwidth(prev_val),
        "current_formatted": format_bandwidth(curr_val),
        # Legacy fields for backward compatibility
        "absolute_drop_bps": abs_change if dir_type == "DROP" else 0.0,
        "percentage_drop": round(pct_change, 2) if dir_type == "DROP" else 0.0,
        "drop_formatted": format_bandwidth(abs_change) if dir_type == "DROP" else "0 bps"
    }


class DeepNocInvestigator:
    """
    Phase 6.3 Deterministic Deep NOC Investigation Engine.
    Executes step-by-step investigation with explicit step status tracking (COMPLETED, FAILED, SKIPPED, NOT_APPLICABLE).
    Enforces canonical interface state, correct short-term rate change vs baseline deviation math, and RouterOS authentication failure safety.
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

        primary_failure = root_cause_candidate.get("type") or root_cause_candidate.get("event_type") or inc.get("facts", {}).get("event_type", "UNKNOWN_ANOMALY")
        primary_entity = root_cause_candidate.get("entity") or inc.get("facts", {}).get("entity", "system")

        secondary_symptoms = []
        for evt in correlated_events:
            if evt["event_id"] != root_cause_candidate.get("event_id"):
                secondary_symptoms.append(f"{evt['type']} on {evt['entity']} ({evt['severity']})")

        evidence_table = DeepNocInvestigator._build_human_readable_evidence(ctx, primary_failure, primary_entity)

        traffic_inv = None
        if "TRAFFIC" in primary_failure or "INTERFACE" in primary_failure:
            try:
                traffic_inv = DeepNocInvestigator._investigate_traffic_drop_and_interface(device_id, primary_entity)
            except Exception as ex:
                logger.warning(f"Traffic drop deep investigation error for {primary_entity}: {ex}")

        visualization_flow = DeepNocInvestigator._build_visualization_flow(primary_failure, primary_entity, correlated_events)
        recommendations = DeepNocInvestigator._build_recommendations(primary_failure, primary_entity)

        # Invoke OpenRouter AI RCA Analysis
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

        # Determine Investigation Conclusion
        if traffic_inv and traffic_inv.get("routeros_authenticated") is False:
            conclusion = "INSUFFICIENT_EVIDENCE"
            overall_confidence = "LOW"
        elif traffic_inv and traffic_inv.get("interface_state", {}).get("canonical_state") == "DOWN":
            conclusion = "ROOT_CAUSE_CONFIRMED"
            overall_confidence = "HIGH"
        elif traffic_inv and (traffic_inv.get("rx_traffic_change", {}).get("severity") in ["CRITICAL", "SEVERE"] or traffic_inv.get("tx_traffic_change", {}).get("severity") in ["CRITICAL", "SEVERE"]):
            conclusion = "ANOMALY_CONFIRMED"
            overall_confidence = "HIGH"
        else:
            conclusion = "ROOT_CAUSE_LIKELY" if root_cause_candidate.get("type") else "NO_FAULT_FOUND"
            overall_confidence = "MEDIUM" if conclusion == "ROOT_CAUSE_LIKELY" else "HIGH"

        inv_record = {
            "investigation_id": investigation_id,
            "incident_id": incident_id,
            "device_id": device_id,
            "created_at": now_ts,
            "status": "COMPLETED",
            "primary_failure": f"{primary_failure} on {primary_entity}",
            "investigation_conclusion": conclusion,
            "overall_confidence": overall_confidence,
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

        db.upsert_investigation(inv_record)
        logger.info(f"Deep NOC Investigation completed for incident {incident_id} (Conclusion: {conclusion}).")
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
            run_val = target_if.get("running")
            dis_val = target_if.get("disabled")
            if dis_val: c_state = "DISABLED"
            elif run_val == 1 or run_val is True: c_state = "UP"
            elif run_val == 0 or run_val is False: c_state = "DOWN"
            else: c_state = "UNKNOWN"

            evidence.append({
                "fact": f"Interface {entity} Canonical State",
                "parameter": "Running Status",
                "observed_value": f"{c_state}",
                "baseline_value": "UP",
                "timestamp": target_if.get("timestamp", "recent"),
                "source": "RouterOS API /interface/print",
                "confidence": "HIGH"
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
                "confidence": "HIGH"
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
                "confidence": "HIGH"
            })

        for evt in ctx.get("correlated_events", []):
            evidence.append({
                "fact": f"Correlated Event: {evt['type']}",
                "parameter": evt.get("metric_name", "State"),
                "observed_value": str(evt.get("value", "Triggered")),
                "baseline_value": "Normal",
                "timestamp": evt.get("timestamp", "recent"),
                "source": "Deterministic Anomaly Detector",
                "confidence": "HIGH"
            })

        return evidence

    @staticmethod
    def _build_visualization_flow(failure_type: str, entity: str, correlated_events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Constructs a visual node-link cascade flow graph showing failure progression."""
        nodes = []
        links = []

        nodes.append({"id": "node-root", "label": f"Root Anomaly: {failure_type}", "type": "ROOT_CAUSE", "severity": "CRITICAL", "entity": entity})

        for idx, evt in enumerate(correlated_events):
            nid = f"node-sym-{idx}"
            nodes.append({"id": nid, "label": f"Symptom: {evt['type']} ({evt['entity']})", "type": "SECONDARY_SYMPTOM", "severity": evt.get("severity", "WARNING"), "entity": evt["entity"]})
            links.append({"source": "node-root", "target": nid, "relationship": "CAUSED_OR_CORRELATED_WITH"})

        nodes.append({"id": "node-impact", "label": "Network Impact: Traffic / Routing Degradation", "type": "IMPACT", "severity": "HIGH", "entity": "Network"})
        if len(nodes) > 2:
            links.append({"source": "node-sym-0", "target": "node-impact", "relationship": "RESULTED_IN"})
        else:
            links.append({"source": "node-root", "target": "node-impact", "relationship": "RESULTED_IN"})

        return {"nodes": nodes, "links": links}

    @staticmethod
    def _build_recommendations(failure_type: str, entity: str) -> List[Dict[str, Any]]:
        """Generates safe, strictly read-only troubleshooting steps for NOC engineers."""
        recs = []
        if "CPU" in failure_type:
            recs.append({"step": 1, "check": "Identify high CPU processes on MikroTik router.", "command": "/system resource cpu print"})
            recs.append({"step": 2, "check": "Inspect active profile allocations to pinpoint thread consumption.", "command": "/tool profile duration=5s"})
        elif "INTERFACE" in failure_type or "TRAFFIC" in failure_type:
            recs.append({"step": 1, "check": f"Inspect physical interface state and link monitor for '{entity}'.", "command": f"/interface print detail where name=\"{entity}\""})
            recs.append({"step": 2, "check": "Review recent interface error and drop counters.", "command": f"/interface ethernet monitor {entity} once"})
        elif "BGP" in failure_type:
            recs.append({"step": 1, "check": f"Inspect BGP peer session status for '{entity}'.", "command": f"/routing bgp peer print status where name=\"{entity}\""})
            recs.append({"step": 2, "check": "Check BGP log entries for TCP connection reset or hold timer expiry.", "command": "/log print topics=bgp"})
        elif "NAT" in failure_type or "ROUTE" in failure_type:
            recs.append({"step": 1, "check": "Verify active routing table entries for default gateway reachability.", "command": "/ip route print where active=yes"})
            recs.append({"step": 2, "check": "Check firewall rule counters and connection tracking table size.", "command": "/ip firewall connection tracking print"})
        else:
            recs.append({"step": 1, "check": f"Inspect device operational status for entity '{entity}'.", "command": "/system resource print"})
            recs.append({"step": 2, "check": "Check system logs for hardware or network interface events.", "command": "/log print follow-only=no"})

        return recs

    @staticmethod
    def _investigate_traffic_drop_and_interface(device_id: str, interface_name: str) -> Dict[str, Any]:
        """
        Phase 6.3 Deterministic Traffic Drop & Interface Root-Cause Investigation:
        Executes step-by-step investigation with explicit step status tracking (COMPLETED, FAILED, SKIPPED, NOT_APPLICABLE).
        Enforces canonical interface state, correct short-term rate change vs baseline deviation math, and RouterOS authentication failure safety.
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

        now_ts = datetime.now(timezone.utc).isoformat()

        steps = [
            {"step_id": "TRAFFIC_ANALYSIS", "name": "Traffic Time-Series Analysis", "status": "IN_PROGRESS", "started_at": now_ts},
            {"step_id": "ROUTEROS_AUTHENTICATION", "name": "RouterOS API Connection", "status": "NOT_STARTED", "started_at": now_ts},
            {"step_id": "INTERFACE_STATE", "name": "Interface Canonical State Inspection", "status": "NOT_STARTED", "started_at": now_ts},
            {"step_id": "MEDIA_CLASSIFICATION", "name": "Hardware Media Type Classification", "status": "NOT_STARTED", "started_at": now_ts},
            {"step_id": "IP_ADDRESS_CHECK", "name": "IP Address & Layer 3 Verification", "status": "NOT_STARTED", "started_at": now_ts},
            {"step_id": "CONNECTIVITY_PING", "name": "RouterOS Ping Reachability Test", "status": "NOT_STARTED", "started_at": now_ts},
            {"step_id": "OPTICAL_POWER_MONITOR", "name": "SFP Optical Transceiver Telemetry", "status": "NOT_STARTED", "started_at": now_ts},
            {"step_id": "SYSTEM_LOG_AUDIT", "name": "RouterOS System Log Audit", "status": "NOT_STARTED", "started_at": now_ts}
        ]

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

        rx_change = calculate_traffic_direction_and_deviation("RX", rx_values)
        tx_change = calculate_traffic_direction_and_deviation("TX", tx_values)

        update_step(steps, "TRAFFIC_ANALYSIS", "COMPLETED", evidence={"rx": rx_change, "tx": tx_change})
        decision_tree_path.append("CALCULATE_TRAFFIC_DECREASE")

        # 2. Live RouterOS API Checks
        iface_state = {"canonical_state": "UNKNOWN", "running": False, "disabled": False}
        iface_raw_dict = {}
        ip_info = {"has_ip": False}
        ping_res = {"reachable": False}
        optical_info = {"supported": False}
        media_info = {"media_type": "UNKNOWN", "confidence": "LOW", "reason": "RouterOS interface metadata could not be retrieved due to API authentication failure.", "optical_capable": False}
        recent_logs = []
        routeros_authenticated = False
        routeros_error = None

        try:
            update_step(steps, "ROUTEROS_AUTHENTICATION", "IN_PROGRESS")
            with get_routeros_client(host=device_id) as api:
                routeros_authenticated = True
                update_step(steps, "ROUTEROS_AUTHENTICATION", "COMPLETED", evidence={"device_id": device_id})

                # A. Query Interface State & Metadata
                update_step(steps, "INTERFACE_STATE", "IN_PROGRESS")
                p_if = api.path("/interface")
                for item in list(p_if):
                    if str(item.get("name", "")).lower() == interface_name.lower():
                        iface_raw_dict = item
                        run_bool = parse_bool_safe(item.get("running"), False)
                        dis_bool = parse_bool_safe(item.get("disabled"), False)

                        # Canonical Interface State (UP / DOWN / DISABLED)
                        if dis_bool: c_state = "DISABLED"
                        elif run_bool: c_state = "UP"
                        else: c_state = "DOWN"

                        iface_state = {
                            "name": interface_name,
                            "type": str(item.get("type", "ether")),
                            "running": run_bool,
                            "disabled": dis_bool,
                            "canonical_state": c_state,
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

                update_step(steps, "INTERFACE_STATE", "COMPLETED", evidence=iface_state)
                decision_tree_path.append("CHECK_INTERFACE_STATE")

                # B. Optical Transceiver Telemetry
                optical_info = query_interface_optical_power(api, interface_name)

                # C. Deterministic Interface Media Classification
                update_step(steps, "MEDIA_CLASSIFICATION", "IN_PROGRESS")
                media_info = classify_interface_media(iface_raw_dict or {"name": interface_name, "type": iface_state.get("type", "ether")}, optical_info)
                update_step(steps, "MEDIA_CLASSIFICATION", "COMPLETED", evidence=media_info)
                decision_tree_path.append(f"CLASSIFY_MEDIA({media_info['media_type']})")

                # Set Optical step status based on media type
                if media_info["media_type"] == "OPTICAL":
                    if optical_info.get("supported"):
                        update_step(steps, "OPTICAL_POWER_MONITOR", "COMPLETED", evidence=optical_info)
                        decision_tree_path.append("OPTICAL_POWER_AUDITED")
                    else:
                        update_step(steps, "OPTICAL_POWER_MONITOR", "COMPLETED", reason="Optical telemetry unavailable on interface")
                else:
                    update_step(steps, "OPTICAL_POWER_MONITOR", "NOT_APPLICABLE", reason=f"Interface media is {media_info['media_type']} (Optical monitoring not applicable)")

                # Canonical State Branching
                if iface_state.get("canonical_state") == "DOWN":
                    decision_tree_path.append("INTERFACE_STATE_DOWN")
                    decision_tree_path.append("PHYSICAL_LINK_FAILURE")
                    update_step(steps, "IP_ADDRESS_CHECK", "SKIPPED", reason="Interface link state is DOWN")
                    update_step(steps, "CONNECTIVITY_PING", "SKIPPED", reason="Interface link state is DOWN")
                else:
                    decision_tree_path.append(f"INTERFACE_STATE_{iface_state.get('canonical_state', 'UP')}")

                    # D. IP Address Verification
                    update_step(steps, "IP_ADDRESS_CHECK", "IN_PROGRESS")
                    ip_info = query_interface_ip_address(api, interface_name)
                    update_step(steps, "IP_ADDRESS_CHECK", "COMPLETED", evidence=ip_info)

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
                            update_step(steps, "CONNECTIVITY_PING", "IN_PROGRESS")
                            ping_res = query_interface_ping_test(api, target_dest, count=5)
                            update_step(steps, "CONNECTIVITY_PING", "COMPLETED", evidence=ping_res)
                            if ping_res.get("reachable"):
                                decision_tree_path.append("PING_REACHABLE_OK")
                            else:
                                decision_tree_path.append("PING_UNREACHABLE_FAIL")
                                decision_tree_path.append("L3_CONNECTIVITY_FAILURE")
                        else:
                            update_step(steps, "CONNECTIVITY_PING", "SKIPPED", reason="No safe destination IP found for ping test")
                            decision_tree_path.append("NO_VALID_DESTINATION")
                    else:
                        decision_tree_path.append("HAS_IP_FALSE")
                        update_step(steps, "CONNECTIVITY_PING", "NOT_APPLICABLE", reason="Interface has no assigned IP address")
                        decision_tree_path.append("L2_INTERFACE_INVESTIGATION")

                # E. System Log Audit
                update_step(steps, "SYSTEM_LOG_AUDIT", "IN_PROGRESS")
                recent_logs = query_interface_logs(api, interface_name, limit=10)
                update_step(steps, "SYSTEM_LOG_AUDIT", "COMPLETED", evidence={"log_count": len(recent_logs)})
                if recent_logs:
                    decision_tree_path.append("ROUTEROS_LOGS_AUDITED")

        except Exception as ex:
            routeros_authenticated = False
            routeros_error = str(ex)
            logger.warning(f"Live RouterOS API checks failed for {device_id}: {ex}")
            update_step(steps, "ROUTEROS_AUTHENTICATION", "FAILED", error=routeros_error, reason="RouterOS API authentication failed")

            # Mark dependent steps as SKIPPED or NOT_APPLICABLE
            update_step(steps, "INTERFACE_STATE", "SKIPPED", reason="RouterOS authentication failed")
            update_step(steps, "MEDIA_CLASSIFICATION", "SKIPPED", reason="RouterOS authentication failed")
            update_step(steps, "IP_ADDRESS_CHECK", "SKIPPED", reason="RouterOS authentication failed")
            update_step(steps, "CONNECTIVITY_PING", "SKIPPED", reason="RouterOS authentication failed")
            update_step(steps, "OPTICAL_POWER_MONITOR", "NOT_APPLICABLE", reason="RouterOS authentication failed")
            update_step(steps, "SYSTEM_LOG_AUDIT", "SKIPPED", reason="RouterOS authentication failed")

            decision_tree_path = [
                "START_TRAFFIC_DROP_INVESTIGATION",
                "TRAFFIC_ANALYSIS",
                "ROUTEROS_AUTHENTICATION_FAILED",
                "INVESTIGATION_HALTED",
                "INSUFFICIENT_EVIDENCE"
            ]

        # Recommendations based on media classification and auth state
        if not routeros_authenticated:
            recs = [
                {"step": 1, "check": "Physical media type could not be verified. Optical-specific troubleshooting has been skipped.", "command": "Test device connectivity in Device Management"},
                {"step": 2, "check": "Verify RouterOS API credentials, IP port 8728 accessibility, and firewall rules.", "command": "Inspect device configuration in NOC inventory"}
            ]
        elif media_info["media_type"] == "OPTICAL":
            recs = [
                {"step": 1, "check": f"Inspect physical optical fiber patch cable and SFP+ transceiver status on interface '{interface_name}'.", "command": f"/interface print detail where name=\"{interface_name}\""},
                {"step": 2, "check": "Verify optical Rx/Tx power levels to confirm physical link layer health.", "command": f"/interface ethernet monitor {interface_name} once"}
            ]
        elif media_info["media_type"] == "ELECTRICAL":
            recs = [
                {"step": 1, "check": f"Inspect physical copper RJ45 patch cable and link partner port on interface '{interface_name}'.", "command": f"/interface print detail where name=\"{interface_name}\""},
                {"step": 2, "check": "Verify speed, duplex, auto-negotiation, and hardware error/drop counters.", "command": f"/interface ethernet monitor {interface_name} once"}
            ]
        else:
            recs = [
                {"step": 1, "check": f"Physical media type could not be verified for interface '{interface_name}'. Optical-specific troubleshooting has been skipped.", "command": f"/interface print detail where name=\"{interface_name}\""},
                {"step": 2, "check": "Inspect logical interface configuration, parent interface state, and system logs.", "command": "/log print follow-only=no"}
            ]

        # Investigation Conclusion & Confidence
        if not routeros_authenticated:
            conclusion = "INSUFFICIENT_EVIDENCE"
            confidence = "LOW"
            completeness = "INCOMPLETE"
        elif iface_state.get("canonical_state") == "DOWN":
            conclusion = "ROOT_CAUSE_CONFIRMED"
            confidence = "HIGH"
            completeness = "COMPLETE"
        elif rx_change["severity"] in ["CRITICAL", "SEVERE"] or tx_change["severity"] in ["CRITICAL", "SEVERE"]:
            conclusion = "ANOMALY_CONFIRMED"
            confidence = "HIGH"
            completeness = "COMPLETE"
        else:
            conclusion = "NO_FAULT_FOUND"
            confidence = "HIGH"
            completeness = "COMPLETE"

        return {
            "interface_name": interface_name,
            "device_id": device_id,
            "routeros_authenticated": routeros_authenticated,
            "routeros_status": "COMPLETED" if routeros_authenticated else "FAILED",
            "routeros_error": routeros_error,
            "evidence_completeness": completeness,
            "evidence_confidence": confidence,
            "investigation_conclusion": conclusion,
            "rx_traffic_change": rx_change,
            "tx_traffic_change": tx_change,
            "time_series": time_series,
            "media_classification": media_info,
            "interface_state": iface_state,
            "ip_investigation": ip_info,
            "ping_investigation": ping_res,
            "optical_power": optical_info,
            "recent_logs": recent_logs,
            "recommendations": recs,
            "steps": steps,
            "decision_tree_path": decision_tree_path
        }
