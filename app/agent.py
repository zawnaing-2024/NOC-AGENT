import logging
import json
from typing import Annotated, Sequence, TypedDict, List, Tuple, Optional
from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, ToolMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

from app.llm import get_llm, OpenRouterTokenCallback
from app.tools.routeros import (
    get_system_health,
    get_interfaces,
    get_interface_detail,
    get_interface_logs,
    get_interface_traffic,
    get_bgp_peers,
    parse_interfaces_data,
    parse_single_interface_detail,
    parse_interface_logs,
    parse_interface_traffic,
    parse_system_resource,
    parse_bgp_peers_data,
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
]
TOOL_MAP = {tool.name: tool for tool in TOOLS}

SYSTEM_PROMPT = """You are an ISP NOC engineer. Analyze only supplied evidence. Separate facts from hypotheses. Never invent network data. Do not claim root cause without evidence. If evidence is insufficient, say so. Explain the most likely cause only when supported by multiple evidence points. Do not infer service impact without topology or interface-role evidence.

RCA CLASSIFICATION CATEGORIES:
- PHYSICAL_LINK_SUSPECTED: Evidence of repeated link state transitions (flapping up/down) in event logs.
- INTERFACE_CONFIGURATION_SUSPECTED: Evidence of MTU or administrative configuration mismatch.
- REMOTE_DEVICE_SUSPECTED: Partner device port behavior anomaly.
- TRAFFIC_OR_ERROR_ANOMALY: Operational interface with elevated RX/TX error or drop counters.
- EXPECTED_OR_INTENTIONAL_STATE: Interface is administratively disabled (disabled=true). No fault inferred.
- INSUFFICIENT_EVIDENCE: Interface is down without role/topology context or log evidence.

CONFIDENCE RULES:
- LOW: Only one weak evidence source.
- MEDIUM: Multiple supporting evidence points.
- HIGH: Multiple independent evidence sources strongly support the same conclusion.

Reasoning Output Format:
Your response MUST strictly follow this NOC format:

OBSERVATION
<Brief statement of request and diagnostic steps>

EVIDENCE
<Facts and metrics retrieved directly from tool calls>

TIMELINE
<Chronological list of timestamped log events, or 'No timestamped log events recorded.'>

ANOMALY
<Detailed description of anomalous condition>

RCA
<RCA Category: PHYSICAL_LINK_SUSPECTED | INSUFFICIENT_EVIDENCE | TRAFFIC_OR_ERROR_ANOMALY | EXPECTED_OR_INTENTIONAL_STATE | INTERFACE_CONFIGURATION_SUSPECTED | REMOTE_DEVICE_SUSPECTED>
<Evidence-backed explanation. Never claim 'bad cable' or 'hardware failure' without proof>

RCA_CONFIDENCE
<LOW | MEDIUM | HIGH - rationale based on evidence completeness>

IMPACT
<State 'Impact cannot be determined because interface role/topology is unknown.' unless role evidence is provided>

UNCERTAINTIES
<Missing info such as connected device state, cable test results, or topology diagram>

RECOMMENDED_NEXT_CHECKS
<Read-only troubleshooting checks>
"""


def perform_evidence_driven_investigation(user_prompt: str) -> Tuple[str, List[str]]:
    """
    Executes Python-driven deterministic evidence collection & correlation (Max 3 stages):
    Stage 1: Detect summary anomalies (interfaces, BGP, system health)
    Stage 2: Targeted single-interface detail collection for any anomaly
    Stage 3: Targeted single-interface log and traffic counter collection
    Returns (correlated_evidence_text, tools_used_list).
    """
    tools_used: List[str] = []
    prompt_lower = user_prompt.lower()

    with get_routeros_client() as api:
        # Determine intent & initial summary tools
        if "bgp" in prompt_lower:
            bgp_data = parse_bgp_peers_data(api, details=False)
            tools_used.append("get_bgp_peers")
            correlated_facts = f"BGP Peer Summary: {bgp_data.model_dump_json()}"

        elif "health" in prompt_lower or "cpu" in prompt_lower or "memory" in prompt_lower:
            health_data = parse_system_resource(api)
            tools_used.append("get_system_health")
            correlated_facts = f"System Resource Health: {health_data.model_dump_json()}"

        else:
            # Interface or general network investigation (default flow)
            tools_used.append("get_interfaces")
            iface_summary = parse_interfaces_data(api, details=False)
            
            evidence_blocks = [f"Interface Summary: {iface_summary.model_dump_json(exclude_none=True)}"]
            
            # Check for LINK_DOWN or ERROR interfaces requiring targeted investigation
            link_down_ifaces = iface_summary.summary.link_down_interfaces
            error_ifaces = iface_summary.summary.error_interfaces
            target_ifaces = list(set(link_down_ifaces + error_ifaces))

            if target_ifaces:
                target_iface = target_ifaces[0]  # Focus investigation on primary anomalous interface (e.g. ether8)
                
                # Stage 2: Targeted Detail
                tools_used.append("get_interface_detail")
                iface_detail = parse_single_interface_detail(api, target_iface)
                evidence_blocks.append(f"Target Interface Detail ({target_iface}): {iface_detail.model_dump_json()}")
                
                # Stage 3: Targeted Logs & Traffic Counters
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
    High-level entry point for MVP-2 NOC Agent.
    Executes Python evidence correlation, then calls OpenRouter EXACTLY ONCE for final RCA generation.
    Returns (answer_text, tools_used_list, token_usage).
    """
    logger.info(f"Processing MVP-2 NOC Agent request: '{user_message}'")
    token_callback = OpenRouterTokenCallback()
    
    try:
        # Step 1-3: Python-driven evidence collection & correlation
        evidence_text, tools_used = perform_evidence_driven_investigation(user_message)
    except RouterOSError as e:
        logger.error(f"RouterOS error during evidence collection: {e}")
        evidence_text = f"RouterOS Connection Failure: {str(e)}"
        tools_used = ["get_interfaces"]
    except Exception as e:
        logger.error(f"Unexpected error during evidence collection: {e}")
        evidence_text = f"Tool Execution Error: {str(e)}"
        tools_used = ["get_interfaces"]

    # Step 4: Single OpenRouter Reasoning Call
    llm = get_llm(callbacks=[token_callback])
    
    prompt_payload = (
        f"User Prompt: {user_message}\n\n"
        f"CORRELATED NETWORK EVIDENCE:\n{evidence_text}\n\n"
        f"Now generate the final complete NOC Report following the exact 9-section format."
    )
    
    messages = [
        SystemMessage(content=SYSTEM_PROMPT),
        HumanMessage(content=prompt_payload),
    ]

    logger.info("Executing SINGLE OpenRouter RCA reasoning call...")
    response = llm.invoke(messages)
    answer = response.content if hasattr(response, "content") else str(response)
    usage = token_callback.get_token_usage()

    return answer, tools_used, usage
