import logging
from typing import Annotated, Sequence, TypedDict, List, Tuple, Optional
from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage, ToolMessage
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages

from app.llm import get_llm, OpenRouterTokenCallback
from app.tools.routeros import get_system_health, get_interfaces, get_bgp_peers, RouterOSError
from app.schemas.network import TokenUsage

logger = logging.getLogger("mikrotik_noc_agent.agent")

TOOLS = [get_system_health, get_interfaces, get_bgp_peers]
TOOL_MAP = {tool.name: tool for tool in TOOLS}

SYSTEM_PROMPT = """You are a Senior ISP NOC Network Engineer.
Your goal is to inspect MikroTik routers using strictly READ-ONLY evidence tools and provide concise, accurate, evidence-backed NOC reports.

INTENT-BASED TOOL ROUTING RULES:
1. HEALTH REQUEST (e.g. "Check router health", "Is system healthy?"): Call ONLY `get_system_health()`. Do NOT call interface or BGP tools unless health evidence reveals an anomaly.
2. INTERFACE REQUEST (e.g. "Check interface states", "Find link down ports"): Call ONLY `get_interfaces(details=False)`. Do NOT call health or BGP tools.
3. BGP REQUEST (e.g. "Check BGP", "Check BGP peers"): Call ONLY `get_bgp_peers(details=False)`. Do NOT call health or interface tools.
4. GENERAL NETWORK PROBLEM REQUEST (e.g. "Check for network problems", "Investigate router issues"): Call summary tools `get_system_health()`, `get_interfaces(details=False)`, and `get_bgp_peers(details=False)`.

STRICT CLASSIFICATION & EVIDENCE RULES:
1. UNCONNECTED PORTS (status_tag="UNCONNECTED"): Interfaces that are administratively enabled but running=false with zero historical traffic.
   - MANDATORY PHRASING: "<N> interfaces are currently unconnected. Their intended role is unknown. No fault is inferred from this state alone."
   - DO NOT label unconnected ports as "standby", "spare", "unused", "faults", or "incidents".
2. LINK_DOWN PORTS (status_tag="LINK_DOWN"): Interfaces that are administratively enabled but running=false after previously carrying traffic.
   - MANDATORY PHRASING: "<interface_name> is administratively enabled but currently not operational. Further investigation is required to determine whether this is expected or represents a fault."
   - DO NOT automatically classify LINK_DOWN as an active incident without role/event logs.
3. DISABLED PORTS (status_tag="DISABLED"): Interfaces that are disabled=true.
   - MANDATORY PHRASING: "<interface_name> is administratively disabled. No fault is inferred."
4. ACTIVE / HEALTHY PORTS (status_tag="ACTIVE"): Running=true with zero errors. Treat as normal.
5. ERROR PORTS (status_tag="ERROR"): Running=true with elevated RX/TX errors. Report exact error counts: "<interface_name> is operational but has elevated error counters (RX errors=<count>, TX errors=<count>) and requires investigation."

STRICT IMPACT & ROLE SPECULATION CONSTRAINTS:
- NEVER invent or assume interface roles like "primary", "uplink", "customer", "core", or "backup" unless explicitly provided in evidence.
- IF INTERFACE ROLE IS UNKNOWN, IMPACT MUST STATE EXACTLY: "Impact cannot be determined from the available evidence."
- IF NO ANOMALY EXISTS, POSSIBLE CAUSES MUST STATE EXACTLY: "No abnormal condition identified."
- DISTINGUISH FACTS FROM HYPOTHESES clearly. (Fact: "ether8 is administratively enabled and operationally down." Hypothesis: "This could indicate a physical/link issue, but there is insufficient evidence to determine the root cause.")

TARGETED STAGE 2 INVESTIGATION:
- If a single interface has a LINK_DOWN or ERROR status, call `get_interfaces(details=True, interface_name="<name>")` to investigate ONLY that specific interface. Do NOT dump all interfaces.

Reasoning Output Format:
Your response MUST strictly use this 9-section NOC format:

OBSERVATION
<Brief summary of user query and tool execution>

EVIDENCE
<Facts and metrics retrieved directly from tool calls>

NORMAL CONDITIONS
<Healthy system metrics, ACTIVE interfaces, UNCONNECTED ports, and DISABLED ports>

ANOMALIES
<Only genuine faults (LINK_DOWN or ERROR interfaces, high CPU/RAM, disconnected BGP) or 'None detected'>

UNCERTAINTIES
<Missing evidence such as interface event logs or port role context>

POSSIBLE CAUSES
<Evidence-backed hypotheses or 'No abnormal condition identified.'>

IMPACT
<Evidence-backed service impact or 'Impact cannot be determined from the available evidence.'>

CONFIDENCE
<High / Medium / Low - state rationale based on evidence completeness>

RECOMMENDED NEXT CHECKS
<Read-only diagnostic checks to run next>
"""


class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]
    tools_used: List[str]


def call_llm_node(state: AgentState) -> dict:
    """Invokes OpenRouter LLM bound with read-only network tools."""
    logger.info("Executing Agent Node via OpenRouter")
    callback = OpenRouterTokenCallback()
    llm = get_llm(callbacks=[callback])
    llm_with_tools = llm.bind_tools(TOOLS)
    
    messages = list(state["messages"])
    if not isinstance(messages[0], SystemMessage):
        messages.insert(0, SystemMessage(content=SYSTEM_PROMPT))
        
    response = llm_with_tools.invoke(messages)
    return {"messages": [response]}


def execute_tools_node(state: AgentState) -> dict:
    """Executes requested read-only tool calls safely."""
    last_message = state["messages"][-1]
    tool_messages = []
    tools_used = list(state.get("tools_used", []))

    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        for tool_call in last_message.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call.get("args", {})
            logger.info(f"Executing Tool Node for: {tool_name} with args={tool_args}")
            
            if tool_name not in tools_used:
                tools_used.append(tool_name)
                
            if tool_name in TOOL_MAP:
                try:
                    tool_output = TOOL_MAP[tool_name].invoke(tool_args)
                except RouterOSError as e:
                    logger.error(f"RouterOS error executing tool {tool_name}: {e}")
                    tool_output = f'{{"error": "{str(e)}"}}'
                except Exception as e:
                    logger.error(f"Unexpected error executing tool {tool_name}: {e}")
                    tool_output = f'{{"error": "Tool execution failed: {str(e)}"}}'
            else:
                tool_output = f'{{"error": "Unknown tool {tool_name}"}}'

            tool_messages.append(
                ToolMessage(content=str(tool_output), tool_call_id=tool_call["id"])
            )

    return {"messages": tool_messages, "tools_used": tools_used}


def force_tool_execution_node(state: AgentState) -> dict:
    """Intent-aware fallback node executing the appropriate tool if LLM skips tool calling on first pass."""
    logger.warning("OpenRouter LLM did not emit tool calls on first pass. Executing intent-based fallback.")
    tools_used = list(state.get("tools_used", []))
    
    # Inspect user query to determine prompt intent
    user_prompt = ""
    for msg in state["messages"]:
        if isinstance(msg, HumanMessage):
            user_prompt = str(msg.content).lower()
            break

    if "interface" in user_prompt or "link" in user_prompt or "port" in user_prompt:
        target_tool = "get_interfaces"
        if target_tool not in tools_used:
            tools_used.append(target_tool)
        output = get_interfaces.invoke({"details": False})
    elif "bgp" in user_prompt or "peer" in user_prompt:
        target_tool = "get_bgp_peers"
        if target_tool not in tools_used:
            tools_used.append(target_tool)
        output = get_bgp_peers.invoke({"details": False})
    else:
        target_tool = "get_system_health"
        if target_tool not in tools_used:
            tools_used.append(target_tool)
        output = get_system_health.invoke({})

    tool_msg = SystemMessage(
        content=f"System Evidence Notification: Output from {target_tool}: {output}. Now produce your final 9-section NOC report using this evidence."
    )
    return {"messages": [tool_msg], "tools_used": tools_used}


def should_continue(state: AgentState) -> str:
    """Determines whether to execute tools, force fallback summary, or end graph."""
    last_message = state["messages"][-1]
    tools_used = state.get("tools_used", [])

    if hasattr(last_message, "tool_calls") and last_message.tool_calls:
        return "tools"
    
    if not tools_used:
        return "fallback"

    return END


def create_agent_graph():
    """Builds and compiles the LangGraph NOC agent graph."""
    graph_builder = StateGraph(AgentState)
    graph_builder.add_node("agent", call_llm_node)
    graph_builder.add_node("tools", execute_tools_node)
    graph_builder.add_node("fallback", force_tool_execution_node)

    graph_builder.set_entry_point("agent")
    graph_builder.add_conditional_edges(
        "agent",
        should_continue,
        {"tools": "tools", "fallback": "fallback", END: END}
    )
    graph_builder.add_edge("tools", "agent")
    graph_builder.add_edge("fallback", "agent")

    return graph_builder.compile()


noc_agent_app = create_agent_graph()


def run_noc_agent(user_message: str) -> Tuple[str, List[str], Optional[TokenUsage]]:
    """
    High-level entry point to run the NOC Agent with OpenRouter API.
    Returns (answer_text, tools_used_list, token_usage).
    """
    token_callback = OpenRouterTokenCallback()
    
    initial_state: AgentState = {
        "messages": [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=user_message)],
        "tools_used": [],
    }
    
    final_state = noc_agent_app.invoke(initial_state, config={"callbacks": [token_callback]})
    
    last_message = final_state["messages"][-1]
    answer = last_message.content if hasattr(last_message, "content") else str(last_message)
    tools_used = final_state.get("tools_used", [])
    
    usage = token_callback.get_token_usage()
    
    return answer, tools_used, usage
