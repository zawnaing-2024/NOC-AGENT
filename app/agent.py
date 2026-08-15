import logging
import json
import re
from typing import Annotated, Sequence, TypedDict, List, Tuple, Optional
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
from app.schemas.network import TokenUsage

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
Analyze only supplied evidence.
Separate facts from hypotheses.
Never invent network state.
Never claim a root cause without supporting evidence.
Never infer topology or interface role unless explicitly provided.
If evidence is insufficient, say INSUFFICIENT_EVIDENCE.
Do not claim customer or service impact without evidence.
Prefer the simplest explanation supported by multiple independent evidence points.

RCA CLASSIFICATION CATEGORIES:
- UNDERLYING_LINK_SUSPECTED: Primary BGP peer, OSPF neighbor, or static route interface is LINK_DOWN / operationally down.
- NEXT_HOP_UNREACHABLE: Static route gateway or next-hop IP is inactive/unreachable.
- UPSTREAM_DEPENDENCY: NAT outbound interface or upstream link is down/unreachable.
- BGP_SESSION_DOWN: BGP peer session is non-established without underlying link down evidence.
- BGP_SESSION_FLAPPING: BGP peer session repeatedly transitions state.
- BGP_PREFIX_ANOMALY: Unexpected drop to zero received prefixes.
- OSPF_ADJACENCY_DOWN: OSPF neighbor state is Down without underlying link down evidence.
- OSPF_ADJACENCY_FLAPPING: OSPF neighbor repeatedly transitions state.
- ROUTE_INACTIVE: Static route is inactive.
- ROUTE_MISSING: Expected static/dynamic route absent from routing table.
- NAT_RULE_DISABLED: NAT rule is administratively disabled.
- NAT_TRAFFIC_ANOMALY: Active NAT rule matching 0 packets/bytes where traffic expected.
- PHYSICAL_LINK_SUSPECTED: Interface repeatedly flaps link state.
- TRAFFIC_OR_ERROR_ANOMALY: Active interface with elevated RX/TX error or drop counters.
- EXPECTED_OR_INTENTIONAL_STATE: Item is administratively disabled or in normal standby.
- INSUFFICIENT_EVIDENCE: Anomaly exists but evidence is insufficient to determine root cause.

CONFIDENCE RULES:
- LOW: Only one weak evidence source.
- MEDIUM: Multiple supporting evidence points.
- HIGH: Multiple independent evidence sources strongly support the same conclusion.

Reasoning Output Format:
Your response MUST strictly follow this 10-section NOC format:

OBSERVATION
<Brief statement of request and diagnostic steps>

EVIDENCE
<Facts and metrics retrieved directly from RouterOS API tool calls>

NORMAL CONDITIONS
<Healthy system metrics, ACTIVE interfaces, established BGP peers, active routes, Full OSPF neighbors>

ANOMALIES
<Detected faults across BGP, Static Routes, OSPF, NAT, or Interfaces>

CORRELATION
<Explicit cross-domain dependency analysis showing how layer-2/interface state affects layer-3 routing/NAT>

RCA
<RCA Category Name>
<Evidence-backed explanation. Never claim 'bad cable' or 'broken BGP config' without direct proof>

RCA_CONFIDENCE
<LOW | MEDIUM | HIGH - rationale based on evidence completeness>

IMPACT
<State 'Dependency relationship cannot be established from the available evidence.' unless explicit evidence exists>

UNCERTAINTIES
<Missing info such as peer router status or physical layer test results>

RECOMMENDED_NEXT_CHECKS
<Read-only troubleshooting checks>
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
    Python-driven cross-domain evidence collection & correlation engine (Max 3 stages):
    Stage 1: Intent detection & target router selection & primary domain summary fetching
    Stage 2: Targeted domain detail investigation
    Stage 3: Cross-domain dependency matching (Layer-2 interface state correlation)
    Returns (correlated_evidence_text, tools_used_list).
    """
    tools_used: List[str] = []
    prompt_lower = user_prompt.lower()
    evidence_blocks: List[str] = []

    target_host = extract_target_router_host(user_prompt)

    with get_routeros_client(host=target_host) as api:
        if target_host:
            evidence_blocks.append(f"Target Router Connection: Established connection to Router {target_host}.")

        # DOMAIN 1: BGP
        if "bgp" in prompt_lower:
            tools_used.append("get_bgp_peers")
            bgp_data = parse_bgp_peers_data(api, details=True)
            evidence_blocks.append(f"BGP Session Summary & Details: {bgp_data.model_dump_json(exclude_none=True)}")

            target_peer = bgp_data.summary.down_peers[0] if bgp_data.summary.down_peers else None
            
            if target_peer or "investigate" in prompt_lower or "peer" in prompt_lower:
                peer_name = target_peer or "10.0.0.1"
                tools_used.append("get_bgp_peer_detail")
                peer_detail = parse_bgp_peer_detail(api, peer_name)
                evidence_blocks.append(f"Target BGP Peer Detail ({peer_name}): {peer_detail.model_dump_json()}")

                tools_used.append("get_routing_logs")
                logs_res = parse_routing_logs_data(api, filter_text="bgp")
                evidence_blocks.append(f"BGP Routing Logs: {logs_res.model_dump_json()}")

                tools_used.append("get_interfaces")
                iface_summary = parse_interfaces_data(api, details=False)
                evidence_blocks.append(f"Underlying Interface Summary: {iface_summary.model_dump_json(exclude_none=True)}")

                if iface_summary.summary.link_down > 0:
                    down_iface = iface_summary.summary.link_down_interfaces[0]
                    tools_used.append("get_interface_detail")
                    iface_detail = parse_single_interface_detail(api, down_iface)
                    evidence_blocks.append(f"Cross-Domain Dependency Interface ({down_iface}): {iface_detail.model_dump_json()}")
                    evidence_blocks.append(f"PYTHON CORRELATION FINDING: BGP peer {peer_name} is DOWN. Underlying interface {down_iface} is LINK_DOWN. Primary RCA Candidate: UNDERLYING_LINK_SUSPECTED.")

        # DOMAIN 2: OSPF
        elif "ospf" in prompt_lower or "neighbor" in prompt_lower:
            tools_used.append("get_ospf_neighbors")
            ospf_data = parse_ospf_neighbors_data(api, details=True)
            evidence_blocks.append(f"OSPF Neighbor Summary & Details: {ospf_data.model_dump_json(exclude_none=True)}")

            target_nbr = ospf_data.down_neighbors[0] if ospf_data.down_neighbors else None
            if target_nbr or "investigate" in prompt_lower:
                nbr_name = target_nbr or "10.0.0.2"
                tools_used.append("get_ospf_neighbor_detail")
                nbr_detail = parse_single_ospf_neighbor_detail(api, nbr_name)
                evidence_blocks.append(f"Target OSPF Neighbor Detail ({nbr_name}): {nbr_detail.model_dump_json()}")

                tools_used.append("get_interfaces")
                iface_summary = parse_interfaces_data(api, details=False)
                evidence_blocks.append(f"Underlying Interface Summary: {iface_summary.model_dump_json(exclude_none=True)}")

                if iface_summary.summary.link_down > 0:
                    down_iface = iface_summary.summary.link_down_interfaces[0]
                    evidence_blocks.append(f"PYTHON CORRELATION FINDING: OSPF neighbor {nbr_name} is Down on {nbr_detail.interface}. Interface {down_iface} is LINK_DOWN. Primary RCA Candidate: UNDERLYING_LINK_SUSPECTED.")

        # DOMAIN 3: STATIC ROUTING
        elif "route" in prompt_lower or "routing" in prompt_lower or "gateway" in prompt_lower or bool(re.search(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}\b", prompt_lower)):
            tools_used.append("get_static_routes")
            routes_data = parse_static_routes_data(api, details=True)
            evidence_blocks.append(f"Static Route Table & Details: {routes_data.model_dump_json(exclude_none=True)}")

            target_dst = routes_data.inactive_routes[0] if routes_data.inactive_routes else None
            if target_dst or "investigate" in prompt_lower or "inactive" in prompt_lower:
                dst_name = target_dst or "10.20.0.0/16"
                tools_used.append("get_route")
                route_detail = parse_single_route_detail(api, dst_name)
                evidence_blocks.append(f"Target Route Detail ({dst_name}): {route_detail.model_dump_json()}")

                tools_used.append("get_interfaces")
                iface_summary = parse_interfaces_data(api, details=False)
                evidence_blocks.append(f"Underlying Egress Interface Summary: {iface_summary.model_dump_json(exclude_none=True)}")

                if iface_summary.summary.link_down > 0:
                    down_iface = iface_summary.summary.link_down_interfaces[0]
                    evidence_blocks.append(f"PYTHON CORRELATION FINDING: Static route {dst_name} via gateway {route_detail.gateway} is active=false. Gateway egress interface {down_iface} is LINK_DOWN. Primary RCA Candidate: NEXT_HOP_UNREACHABLE.")

        # DOMAIN 4: NAT
        elif "nat" in prompt_lower or "masquerade" in prompt_lower or "firewall" in prompt_lower:
            tools_used.append("get_nat_rules")
            nat_data = parse_nat_rules_data(api, details=True)
            evidence_blocks.append(f"NAT Firewall Rules & Details: {nat_data.model_dump_json(exclude_none=True)}")

            if "investigate" in prompt_lower or nat_data.zero_counter_rules:
                tools_used.append("get_interfaces")
                iface_summary = parse_interfaces_data(api, details=False)
                evidence_blocks.append(f"WAN Outbound Interface Summary: {iface_summary.model_dump_json(exclude_none=True)}")

                if iface_summary.summary.link_down > 0:
                    down_iface = iface_summary.summary.link_down_interfaces[0]
                    evidence_blocks.append(f"PYTHON CORRELATION FINDING: NAT rule out-interface configured, but WAN interface {down_iface} is LINK_DOWN. Primary RCA Candidate: UPSTREAM_DEPENDENCY.")

        # GENERAL SYSTEM / INTERFACE INVESTIGATION
        else:
            tools_used.append("get_interfaces")
            iface_summary = parse_interfaces_data(api, details=False)
            evidence_blocks.append(f"Interface Summary: {iface_summary.model_dump_json(exclude_none=True)}")

            if iface_summary.summary.link_down_interfaces:
                target_iface = iface_summary.summary.link_down_interfaces[0]
                tools_used.append("get_interface_detail")
                iface_detail = parse_single_interface_detail(api, target_iface)
                evidence_blocks.append(f"Target Interface Detail ({target_iface}): {iface_detail.model_dump_json()}")

                tools_used.append("get_interface_logs")
                iface_logs = parse_interface_logs(api, target_iface)
                evidence_blocks.append(f"Target Interface Logs ({target_iface}): {iface_logs.model_dump_json()}")

                tools_used.append("get_interface_traffic")
                iface_traffic = parse_interface_traffic(api, target_iface)
                evidence_blocks.append(f"Target Interface Traffic ({target_iface}): {iface_traffic.model_dump_json()}")

    correlated_facts = "\n".join(evidence_blocks)
    return correlated_facts, tools_used


def run_noc_agent(user_message: str) -> Tuple[str, List[str], Optional[TokenUsage]]:
    """
    High-level entry point for Phase 3 NOC Agent.
    Executes Python cross-domain correlation, then calls OpenRouter EXACTLY ONCE for final RCA report generation.
    Returns (answer_text, tools_used_list, token_usage).
    """
    logger.info(f"Processing Phase 3 NOC Agent request: '{user_message}'")
    token_callback = OpenRouterTokenCallback()
    
    try:
        evidence_text, tools_used = perform_cross_domain_investigation(user_message)
    except RouterOSError as e:
        logger.error(f"RouterOS error during cross-domain investigation: {e}")
        evidence_text = f"RouterOS Connection Failure: {str(e)}"
        tools_used = ["get_system_health"]
    except Exception as e:
        logger.error(f"Unexpected error during cross-domain investigation: {e}")
        evidence_text = f"Tool Execution Error: {str(e)}"
        tools_used = ["get_system_health"]

    # Single OpenRouter RCA Call
    llm = get_llm(callbacks=[token_callback])
    
    prompt_payload = (
        f"User Prompt: {user_message}\n\n"
        f"CORRELATED CROSS-DOMAIN NETWORK EVIDENCE:\n{evidence_text}\n\n"
        f"Now generate the final complete NOC Report following the exact 10-section format."
    )
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=prompt_payload),
    ]

    logger.info("Executing SINGLE OpenRouter Phase 3 RCA reasoning call...")
    response = llm.invoke(messages)
    answer = response.content if hasattr(response, "content") else str(response)
    usage = token_callback.get_token_usage()

    return answer, tools_used, usage
