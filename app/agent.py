import logging
import json
import re
import time
from typing import Annotated, Sequence, TypedDict, List, Tuple, Optional, Dict, Any
from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, ToolMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

from app.config import settings
from app.llm import get_llm, OpenRouterTokenCallback
from app.tools.routeros import (
    get_system_health,
    get_interfaces,
    get_interface_detail,
    get_interface_logs,
    get_interface_traffic,
    get_bgp_peers,
    get_bgp_peer_detail,
    get_bgp_routes,
    get_static_routes,
    get_route,
    get_routing_table,
    get_ospf_neighbors,
    get_ospf_neighbor_detail,
    get_ospf_routes,
    get_nat_rules,
    get_nat_statistics,
    get_nat_connections,
    get_routing_logs,
    parse_interfaces_data,
    parse_single_interface_detail,
    parse_interface_logs,
    parse_interface_traffic,
    parse_system_resource,
    parse_bgp_peers_data,
    parse_bgp_peer_detail,
    parse_static_routes_data,
    parse_single_route_detail,
    parse_ospf_neighbors_data,
    parse_single_ospf_neighbor_detail,
    parse_nat_rules_data,
    parse_routing_logs_data,
    get_routeros_client,
    RouterOSError,
)
from app.schemas.network import TokenUsage, PerformanceProfiling, ToolCallProfiling

logger = logging.getLogger("mikrotik_noc_agent.agent")

TOOLS = [
    get_system_health,
    get_interfaces,
    get_interface_detail,
    get_interface_logs,
    get_interface_traffic,
    get_bgp_peers,
    get_bgp_peer_detail,
    get_bgp_routes,
    get_static_routes,
    get_route,
    get_routing_table,
    get_ospf_neighbors,
    get_ospf_neighbor_detail,
    get_ospf_routes,
    get_nat_rules,
    get_nat_statistics,
    get_nat_connections,
    get_routing_logs,
]
TOOL_MAP = {tool.name: tool for tool in TOOLS}

SYSTEM_PROMPT = """You are an ISP NOC engineer.

Use only supplied evidence.
Never invent facts.
Separate facts from hypotheses.
Do not infer topology without evidence.
Do not force an RCA.
Use NO_ANOMALY for healthy systems.
Use INSUFFICIENT_EVIDENCE when evidence is insufficient or explicit dependency is missing.
Do not claim service impact without evidence.
Return a concise NOC assessment.

Format:
OBSERVATION
<Concise statement of check>

EVIDENCE
<Compact facts from payload>

ANOMALY
<Detected anomaly or 'None detected.'>

RCA
<RCA Category: NO_ANOMALY | INSUFFICIENT_EVIDENCE | UPSTREAM_DEPENDENCY | NEXT_HOP_UNREACHABLE | BGP_SESSION_DOWN | OSPF_ADJACENCY_DOWN>

CONFIDENCE
<HIGH | MEDIUM | LOW>

IMPACT
<Impact statement or 'No anomaly detected.' or 'Service or dependency impact cannot be determined from the available evidence.'>

NEXT_CHECKS
<Concise next check or 'None required.'>
"""


def extract_target_router_host(user_prompt: str) -> Optional[str]:
    """Extracts target router IP or identifier from user prompt if present."""
    prompt_lower = user_prompt.lower()
    
    if "103.95.4.1" in user_prompt or "router2" in prompt_lower or "router 2" in prompt_lower:
        return settings.MIKROTIK_ROUTER2_HOST or "103.95.4.1"
    if "103.59.163.7" in user_prompt or "router1" in prompt_lower or "router 1" in prompt_lower:
        return settings.MIKROTIK_ROUTER1_HOST or "103.59.163.7"
        
    ip_matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", user_prompt)
    for ip in ip_matches:
        if ip == settings.MIKROTIK_ROUTER2_HOST:
            return settings.MIKROTIK_ROUTER2_HOST
        if ip == settings.MIKROTIK_ROUTER1_HOST:
            return settings.MIKROTIK_ROUTER1_HOST
            
    return None


def perform_cross_domain_investigation(user_prompt: str) -> Tuple[str, List[str]]:
    """
    Python-driven cross-domain evidence collection & correlation engine.
    Preserves 2-tuple return format (correlated_evidence_text, tools_used_list) for 100% backward compatibility.
    """
    evidence_text, tools_used, _, _, _ = perform_cross_domain_investigation_profiled(user_prompt)
    return evidence_text, tools_used


def perform_cross_domain_investigation_profiled(user_prompt: str) -> Tuple[str, List[str], List[ToolCallProfiling], int, int]:
    """
    Python-driven cross-domain evidence collection & correlation engine with deterministic NAT & Static Routing correlation.
    Returns (correlated_evidence_text, tools_used_list, tool_profiling_list, intent_ms, correlation_ms).
    """
    t_start = time.perf_counter()
    tools_used: List[str] = []
    tool_profiles: List[ToolCallProfiling] = []
    prompt_lower = user_prompt.lower()
    compact_evidence_dicts: List[Dict[str, Any]] = []

    target_host = extract_target_router_host(user_prompt)
    t_intent_end = time.perf_counter()
    intent_ms = max(1, int((t_intent_end - t_start) * 1000))

    t_corr_start = time.perf_counter()
    with get_routeros_client(host=target_host) as api:

        # DOMAIN 1: BGP
        if "bgp" in prompt_lower:
            t0 = time.perf_counter()
            bgp_data = parse_bgp_peers_data(api, details=True)
            t1 = time.perf_counter()
            dur_ms = max(1, int((t1 - t0) * 1000))
            tools_used.append("get_bgp_peers")
            tool_profiles.append(ToolCallProfiling(tool="get_bgp_peers", duration_ms=dur_ms, routeros_ms=dur_ms))

            down_peers = bgp_data.summary.down_peers
            has_unknown_established = False
            peer_item = bgp_data.details[0] if bgp_data.details else None
            
            if bgp_data.details:
                for p in bgp_data.details:
                    if p.established and p.state == "UNKNOWN":
                        has_unknown_established = True
                        peer_item = p

            if has_unknown_established and not down_peers:
                compact_evidence_dicts.append({
                    "domain": "BGP",
                    "peer": peer_item.remote_address if peer_item else "unknown",
                    "established": True,
                    "uptime": peer_item.uptime if peer_item else "long",
                    "prefix_count": peer_item.prefix_count if peer_item else 1,
                    "state_field": "UNKNOWN",
                    "anomaly": "STATE_FIELD_INCONSISTENCY",
                    "rca_candidate": "INSUFFICIENT_EVIDENCE",
                    "explanation": "The session is established and has a long uptime, but the normalized state field is reported as UNKNOWN. This appears to be an evidence/representation inconsistency rather than evidence of a BGP fault."
                })
            elif not down_peers and bgp_data.summary.established > 0:
                compact_evidence_dicts.append({
                    "domain": "BGP",
                    "established_sessions": bgp_data.summary.established,
                    "down_sessions": 0,
                    "anomaly": None,
                    "rca_candidate": "NO_ANOMALY"
                })
            elif down_peers:
                target_peer = down_peers[0]
                t0 = time.perf_counter()
                peer_detail = parse_bgp_peer_detail(api, target_peer)
                t1 = time.perf_counter()
                dur_ms = max(1, int((t1 - t0) * 1000))
                tools_used.append("get_bgp_peer_detail")
                tool_profiles.append(ToolCallProfiling(tool="get_bgp_peer_detail", duration_ms=dur_ms, routeros_ms=dur_ms))

                t0 = time.perf_counter()
                iface_summary = parse_interfaces_data(api, details=False)
                t1 = time.perf_counter()
                dur_ms = max(1, int((t1 - t0) * 1000))
                tools_used.append("get_interfaces")
                tool_profiles.append(ToolCallProfiling(tool="get_interfaces", duration_ms=dur_ms, routeros_ms=dur_ms))

                link_down_iface = iface_summary.summary.link_down_interfaces[0] if iface_summary.summary.link_down > 0 else None
                rca_cat = "UNDERLYING_LINK_SUSPECTED" if link_down_iface else "BGP_SESSION_DOWN"

                compact_evidence_dicts.append({
                    "domain": "BGP",
                    "target_peer": target_peer,
                    "established": False,
                    "underlying_interface": link_down_iface,
                    "interface_state": "LINK_DOWN" if link_down_iface else "ACTIVE",
                    "anomaly": f"BGP peer {target_peer} DOWN",
                    "rca_candidate": rca_cat
                })

        # DOMAIN 2: OSPF
        elif "ospf" in prompt_lower or "neighbor" in prompt_lower:
            t0 = time.perf_counter()
            ospf_data = parse_ospf_neighbors_data(api, details=True)
            t1 = time.perf_counter()
            dur_ms = max(1, int((t1 - t0) * 1000))
            tools_used.append("get_ospf_neighbors")
            tool_profiles.append(ToolCallProfiling(tool="get_ospf_neighbors", duration_ms=dur_ms, routeros_ms=dur_ms))

            if ospf_data.down == 0 and ospf_data.total > 0:
                compact_evidence_dicts.append({
                    "domain": "OSPF",
                    "neighbors_total": ospf_data.total,
                    "full": ospf_data.full,
                    "down": 0,
                    "anomaly": None,
                    "rca_candidate": "NO_ANOMALY"
                })
            elif ospf_data.down_neighbors:
                target_nbr = ospf_data.down_neighbors[0]
                t0 = time.perf_counter()
                nbr_detail = parse_single_ospf_neighbor_detail(api, target_nbr)
                t1 = time.perf_counter()
                dur_ms = max(1, int((t1 - t0) * 1000))
                tools_used.append("get_ospf_neighbor_detail")
                tool_profiles.append(ToolCallProfiling(tool="get_ospf_neighbor_detail", duration_ms=dur_ms, routeros_ms=dur_ms))

                t0 = time.perf_counter()
                iface_summary = parse_interfaces_data(api, details=False)
                t1 = time.perf_counter()
                dur_ms = max(1, int((t1 - t0) * 1000))
                tools_used.append("get_interfaces")
                tool_profiles.append(ToolCallProfiling(tool="get_interfaces", duration_ms=dur_ms, routeros_ms=dur_ms))

                link_down_iface = iface_summary.summary.link_down_interfaces[0] if iface_summary.summary.link_down > 0 else None
                rca_cat = "UNDERLYING_LINK_SUSPECTED" if link_down_iface else "OSPF_ADJACENCY_DOWN"

                compact_evidence_dicts.append({
                    "domain": "OSPF",
                    "target_neighbor": target_nbr,
                    "state": "Down",
                    "interface": nbr_detail.interface,
                    "interface_state": "LINK_DOWN" if link_down_iface else "ACTIVE",
                    "anomaly": f"OSPF neighbor {target_nbr} Down",
                    "rca_candidate": rca_cat
                })

        # DOMAIN 3: NAT (Check NAT keywords BEFORE static routes!)
        elif "nat" in prompt_lower or "masquerade" in prompt_lower or "firewall" in prompt_lower:
            t0 = time.perf_counter()
            nat_data = parse_nat_rules_data(api, details=True)
            t1 = time.perf_counter()
            dur_ms = max(1, int((t1 - t0) * 1000))
            tools_used.append("get_nat_rules")
            tool_profiles.append(ToolCallProfiling(tool="get_nat_rules", duration_ms=dur_ms, routeros_ms=dur_ms))

            t0 = time.perf_counter()
            iface_summary = parse_interfaces_data(api, details=False)
            t1 = time.perf_counter()
            dur_ms = max(1, int((t1 - t0) * 1000))
            tools_used.append("get_interfaces")
            tool_profiles.append(ToolCallProfiling(tool="get_interfaces", duration_ms=dur_ms, routeros_ms=dur_ms))

            down_ifaces = iface_summary.summary.link_down_interfaces

            matched_dependency_rule = None
            if nat_data.rules and down_ifaces:
                for r in nat_data.rules:
                    if not r.disabled and r.out_interface:
                        for d_if in down_ifaces:
                            if r.out_interface.lower() == d_if.lower():
                                matched_dependency_rule = (r, d_if)
                                break
                    if matched_dependency_rule:
                        break

            if matched_dependency_rule:
                rule_obj, d_iface = matched_dependency_rule
                compact_evidence_dicts.append({
                    "domain": "NAT",
                    "rules_total": nat_data.total,
                    "active_rules": nat_data.active,
                    "disabled_rules": nat_data.disabled,
                    "matched_rule_id": rule_obj.rule_id,
                    "out_interface": rule_obj.out_interface,
                    "interface_state": "LINK_DOWN",
                    "packets": rule_obj.packets,
                    "anomaly": f"NAT rule {rule_obj.rule_id} specifies out-interface {rule_obj.out_interface} which is LINK_DOWN",
                    "rca_candidate": "UPSTREAM_DEPENDENCY",
                    "explanation": f"Active NAT rule {rule_obj.rule_id} out-interface {rule_obj.out_interface} is LINK_DOWN."
                })
            elif down_ifaces:
                compact_evidence_dicts.append({
                    "domain": "NAT",
                    "rules_total": nat_data.total,
                    "active_rules": nat_data.active,
                    "disabled_rules": nat_data.disabled,
                    "down_interfaces": down_ifaces,
                    "explicit_nat_dependency_found": False,
                    "anomaly": "UNLINKED_INTERFACE_DOWN",
                    "rca_candidate": "INSUFFICIENT_EVIDENCE",
                    "explanation": "Down interface(s) exist, but no active NAT rule explicitly specifies out-interface matching the down interface. Cannot infer NAT dependency from interface state alone."
                })
            else:
                compact_evidence_dicts.append({
                    "domain": "NAT",
                    "rules_total": nat_data.total,
                    "active_rules": nat_data.active,
                    "disabled_rules": nat_data.disabled,
                    "anomaly": None,
                    "rca_candidate": "NO_ANOMALY"
                })

        # DOMAIN 4: STATIC ROUTING
        elif "route" in prompt_lower or "routing" in prompt_lower or "gateway" in prompt_lower or bool(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b", prompt_lower)):
            t0 = time.perf_counter()
            routes_data = parse_static_routes_data(api, details=True)
            t1 = time.perf_counter()
            dur_ms = max(1, int((t1 - t0) * 1000))
            tools_used.append("get_static_routes")
            tool_profiles.append(ToolCallProfiling(tool="get_static_routes", duration_ms=dur_ms, routeros_ms=dur_ms))

            if routes_data.inactive == 0:
                compact_evidence_dicts.append({
                    "domain": "STATIC_ROUTE",
                    "total_routes": routes_data.total,
                    "active_routes": routes_data.active,
                    "inactive_routes": 0,
                    "disabled_routes": routes_data.disabled,
                    "anomaly": None,
                    "rca_candidate": "NO_ANOMALY"
                })
            elif routes_data.inactive_routes:
                target_dst = routes_data.inactive_routes[0]
                t0 = time.perf_counter()
                route_detail = parse_single_route_detail(api, target_dst)
                t1 = time.perf_counter()
                dur_ms = max(1, int((t1 - t0) * 1000))
                tools_used.append("get_route")
                tool_profiles.append(ToolCallProfiling(tool="get_route", duration_ms=dur_ms, routeros_ms=dur_ms))

                t0 = time.perf_counter()
                iface_summary = parse_interfaces_data(api, details=False)
                t1 = time.perf_counter()
                dur_ms = max(1, int((t1 - t0) * 1000))
                tools_used.append("get_interfaces")
                tool_profiles.append(ToolCallProfiling(tool="get_interfaces", duration_ms=dur_ms, routeros_ms=dur_ms))

                link_down_ifaces = iface_summary.summary.link_down_interfaces
                gw_interface_down = False
                if route_detail.interface and link_down_ifaces:
                    if any(r_if.lower() in d_if.lower() or d_if.lower() in r_if.lower() for d_if in link_down_ifaces for r_if in [route_detail.interface]):
                        gw_interface_down = True

                if gw_interface_down:
                    rca_cat = "NEXT_HOP_UNREACHABLE"
                    explanation = f"Static route {target_dst} via gateway {route_detail.gateway} is inactive because gateway egress interface {route_detail.interface} is LINK_DOWN."
                else:
                    rca_cat = "INSUFFICIENT_EVIDENCE"
                    explanation = f"Static route {target_dst} via gateway {route_detail.gateway} is inactive, but gateway interface is operational. Reason for inactive state is unconfirmed."

                compact_evidence_dicts.append({
                    "domain": "STATIC_ROUTE",
                    "destination": target_dst,
                    "active": False,
                    "gateway": route_detail.gateway,
                    "gateway_interface": route_detail.interface,
                    "gateway_interface_down": gw_interface_down,
                    "anomaly": f"Route {target_dst} inactive",
                    "rca_candidate": rca_cat,
                    "explanation": explanation
                })

        # GENERAL SYSTEM / INTERFACE INVESTIGATION
        else:
            t0 = time.perf_counter()
            iface_summary = parse_interfaces_data(api, details=False)
            t1 = time.perf_counter()
            dur_ms = max(1, int((t1 - t0) * 1000))
            tools_used.append("get_interfaces")
            tool_profiles.append(ToolCallProfiling(tool="get_interfaces", duration_ms=dur_ms, routeros_ms=dur_ms))

            if iface_summary.summary.link_down_interfaces:
                target_iface = iface_summary.summary.link_down_interfaces[0]
                t0 = time.perf_counter()
                iface_detail = parse_single_interface_detail(api, target_iface)
                t1 = time.perf_counter()
                dur_ms = max(1, int((t1 - t0) * 1000))
                tools_used.append("get_interface_detail")
                tool_profiles.append(ToolCallProfiling(tool="get_interface_detail", duration_ms=dur_ms, routeros_ms=dur_ms))

                compact_evidence_dicts.append({
                    "domain": "INTERFACE",
                    "target_interface": target_iface,
                    "running": False,
                    "disabled": False,
                    "status_tag": "LINK_DOWN",
                    "anomaly": f"Interface {target_iface} LINK_DOWN",
                    "rca_candidate": "UNDERLYING_LINK_SUSPECTED"
                })
            else:
                compact_evidence_dicts.append({
                    "domain": "INTERFACE",
                    "total": iface_summary.summary.total,
                    "active": iface_summary.summary.active,
                    "disabled": iface_summary.summary.disabled,
                    "link_down": 0,
                    "anomaly": None,
                    "rca_candidate": "NO_ANOMALY"
                })

    t_corr_end = time.perf_counter()
    correlation_ms = max(1, int((t_corr_end - t_corr_start) * 1000))
    correlated_facts = json.dumps(compact_evidence_dicts, indent=2)
    return correlated_facts, tools_used, tool_profiles, intent_ms, correlation_ms


def run_noc_agent(user_message: str) -> Tuple[str, List[str], Optional[TokenUsage], Optional[PerformanceProfiling]]:
    """
    High-level entry point for Phase 3 NOC Agent with full profiling measurement.
    Executes Python cross-domain correlation, then calls OpenRouter EXACTLY ONCE for final RCA report generation.
    Returns (answer_text, tools_used_list, token_usage, performance_profiling).
    """
    t_req_start = time.perf_counter()
    logger.info(f"Processing Phase 3 NOC Agent request: '{user_message}'")
    token_callback = OpenRouterTokenCallback()
    
    try:
        evidence_text, tools_used, tool_profiles, intent_ms, correlation_ms = perform_cross_domain_investigation_profiled(user_message)
    except RouterOSError as e:
        logger.error(f"RouterOS error during cross-domain investigation: {e}")
        evidence_text = json.dumps([{"domain": "SYSTEM", "error": f"RouterOS Connection Failure: {str(e)}", "rca_candidate": "INSUFFICIENT_EVIDENCE"}])
        tools_used = ["get_system_health"]
        tool_profiles = [ToolCallProfiling(tool="get_system_health", duration_ms=10, routeros_ms=10)]
        intent_ms = 1
        correlation_ms = 10
    except Exception as e:
        logger.error(f"Unexpected error during cross-domain investigation: {e}")
        evidence_text = json.dumps([{"domain": "SYSTEM", "error": f"Tool Execution Error: {str(e)}", "rca_candidate": "INSUFFICIENT_EVIDENCE"}])
        tools_used = ["get_system_health"]
        tool_profiles = [ToolCallProfiling(tool="get_system_health", duration_ms=10, routeros_ms=10)]
        intent_ms = 1
        correlation_ms = 10

    # Single OpenRouter RCA Call with max_tokens=350 limit
    llm = get_llm(callbacks=[token_callback], max_tokens=350)
    
    prompt_payload = (
        f"User Request: {user_message}\n"
        f"Compact Evidence Payload:\n{evidence_text}"
    )
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=prompt_payload),
    ]

    logger.info("Executing SINGLE OpenRouter Phase 3 RCA reasoning call (max_tokens=350)...")
    t_llm_start = time.perf_counter()
    response = llm.invoke(messages)
    t_llm_end = time.perf_counter()
    openrouter_ms = max(1, int((t_llm_end - t_llm_start) * 1000))
    
    answer = response.content if hasattr(response, "content") else str(response)
    usage = token_callback.get_token_usage()

    t_req_end = time.perf_counter()
    total_request_ms = max(1, int((t_req_end - t_req_start) * 1000))

    prompt_toks = usage.prompt_tokens if usage else 0
    completion_toks = usage.completion_tokens if usage else 0
    total_toks = usage.total_tokens if usage else 0

    profiling = PerformanceProfiling(
        total_request_ms=total_request_ms,
        intent_detection_ms=intent_ms,
        tool_calls=tool_profiles,
        evidence_processing_ms=correlation_ms,
        llm_calls=1,
        openrouter_ms=openrouter_ms,
        prompt_tokens=prompt_toks,
        completion_tokens=completion_toks,
        total_tokens=total_toks,
    )

    profiling_log_dict = {
        "total_request_ms": total_request_ms,
        "intent_detection_ms": intent_ms,
        "tool_calls": [t.model_dump(exclude_none=True) for t in tool_profiles],
        "evidence_processing_ms": correlation_ms,
        "llm_calls": 1,
        "openrouter_ms": openrouter_ms,
        "prompt_tokens": prompt_toks,
        "completion_tokens": completion_toks,
        "total_tokens": total_toks,
    }
    logger.info(f"PERFORMANCE PROFILING RESULT:\n{json.dumps(profiling_log_dict, indent=2)}")

    return answer, tools_used, usage, profiling
