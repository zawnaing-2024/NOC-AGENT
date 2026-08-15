from typing import List, Optional, Dict, Union
from pydantic import BaseModel, Field


class SystemHealth(BaseModel):
    device: str = Field(..., description="Device identity/name")
    identity: str = Field(..., description="Router identity")
    board_name: str = Field(default="unknown", description="Board name or model")
    routeros_version: str = Field(default="unknown", description="RouterOS software version")
    uptime: str = Field(default="unknown", description="System uptime string")
    cpu_load_percent: int = Field(default=0, description="CPU usage percentage")
    total_memory: int = Field(default=0, description="Total RAM in bytes")
    free_memory: int = Field(default=0, description="Free RAM in bytes")
    memory_usage_percent: float = Field(default=0.0, description="Calculated memory usage percentage")
    status: str = Field(default="HEALTHY", description="Overall health status (HEALTHY/WARNING/CRITICAL)")


class InterfaceInfo(BaseModel):
    name: str = Field(..., description="Interface name")
    type: str = Field(default="ether", description="Interface type")
    running: bool = Field(default=False, description="Interface running state")
    disabled: bool = Field(default=False, description="Interface disabled state")
    status_tag: str = Field(
        default="ACTIVE",
        description="Deterministic tag: DISABLED (no fault), UNCONNECTED (no fault, 0 traffic), LINK_DOWN (fault, dropped link), ERROR (fault), ACTIVE (healthy)"
    )
    rx_bytes: int = Field(default=0, description="Bytes received")
    tx_bytes: int = Field(default=0, description="Bytes transmitted")
    rx_packets: int = Field(default=0, description="Packets received")
    tx_packets: int = Field(default=0, description="Packets transmitted")
    rx_errors: int = Field(default=0, description="Receive errors")
    tx_errors: int = Field(default=0, description="Transmit errors")


class InterfaceSummary(BaseModel):
    total: int = Field(default=0)
    active: int = Field(default=0)
    disabled: int = Field(default=0)
    unconnected: int = Field(default=0, description="Unplugged ports with zero historical traffic (not an incident)")
    link_down: int = Field(default=0, description="Ports that previously carried traffic but dropped link (requires investigation)")
    errors: int = Field(default=0, description="Active ports experiencing RX/TX errors")
    link_down_interfaces: List[str] = Field(default_factory=list, description="Names of LINK_DOWN interfaces")
    error_interfaces: List[str] = Field(default_factory=list, description="Names of ERROR interfaces")


class InterfacesResponse(BaseModel):
    summary: InterfaceSummary
    details: Optional[List[InterfaceInfo]] = None


class InterfaceDetail(BaseModel):
    name: str = Field(..., description="Target interface name")
    type: str = Field(default="ether", description="Interface type")
    running: bool = Field(default=False, description="Operational state")
    disabled: bool = Field(default=False, description="Administrative state")
    mtu: Optional[int] = Field(default=1500, description="Configured MTU")
    actual_mtu: Optional[int] = Field(default=1500, description="Actual operational MTU")
    mac_address: Optional[str] = Field(default=None, description="MAC address")
    rx_bytes: int = Field(default=0, description="Received bytes count")
    tx_bytes: int = Field(default=0, description="Transmitted bytes count")
    rx_packets: int = Field(default=0, description="Received packets count")
    tx_packets: int = Field(default=0, description="Transmitted packets count")
    rx_errors: int = Field(default=0, description="Receive error count")
    tx_errors: int = Field(default=0, description="Transmit error count")
    rx_drops: int = Field(default=0, description="Receive drop count")
    tx_drops: int = Field(default=0, description="Transmit drop count")
    link_downs: Optional[int] = Field(default=0, description="Link down transition counter")


class LogEvent(BaseModel):
    timestamp: str = Field(..., description="RouterOS log timestamp")
    message: str = Field(..., description="Log event message content")


class InterfaceLogsResponse(BaseModel):
    interface: str = Field(..., description="Target interface name")
    events: List[LogEvent] = Field(default_factory=list, description="Matching timestamped events")


class InterfaceTrafficResponse(BaseModel):
    interface: str = Field(..., description="Target interface name")
    rx_bytes: int = Field(default=0, description="Current received bytes count")
    tx_bytes: int = Field(default=0, description="Current transmitted bytes count")
    rx_packets: int = Field(default=0, description="Current received packets count")
    tx_packets: int = Field(default=0, description="Current transmitted packets count")
    rx_errors: int = Field(default=0, description="Current receive error count")
    tx_errors: int = Field(default=0, description="Current transmit error count")
    rx_drops: int = Field(default=0, description="Current receive drop count")
    tx_drops: int = Field(default=0, description="Current transmit drop count")


# --- Phase 3 Cross-Domain Troubleshooting Schemas ---

class BgpPeerInfo(BaseModel):
    name: str = Field(..., description="BGP peer session name")
    remote_address: str = Field(default="unknown", description="Remote peer IP address")
    local_address: str = Field(default="", description="Local IP address")
    state: str = Field(default="unknown", description="BGP session state (e.g. established, idle)")
    uptime: Optional[str] = Field(default=None, description="BGP peer uptime")
    established: bool = Field(default=False, description="Whether BGP session is established")
    prefix_count: int = Field(default=0, description="Number of prefixes received/advertised")
    remote_as: Optional[str] = Field(default=None, description="Remote Autonomous System Number")
    local_as: Optional[str] = Field(default=None, description="Local Autonomous System Number")


class BgpSummary(BaseModel):
    total: int = Field(default=0)
    established: int = Field(default=0)
    down: int = Field(default=0)
    down_peers: List[str] = Field(default_factory=list, description="Names/IPs of non-established BGP peers")


class BgpPeersResponse(BaseModel):
    summary: BgpSummary
    details: Optional[List[BgpPeerInfo]] = None


class StaticRouteInfo(BaseModel):
    destination: str = Field(..., description="Destination CIDR prefix")
    gateway: str = Field(..., description="Gateway IP or interface")
    interface: Optional[str] = Field(default=None, description="Egress interface")
    distance: int = Field(default=1, description="Route administrative distance")
    active: bool = Field(default=True, description="Whether route is active in RIB")
    disabled: bool = Field(default=False, description="Whether route is administratively disabled")


class StaticRoutesResponse(BaseModel):
    total: int = Field(default=0)
    active: int = Field(default=0)
    inactive: int = Field(default=0)
    disabled: int = Field(default=0)
    inactive_routes: List[str] = Field(default_factory=list)
    routes: Optional[List[StaticRouteInfo]] = None


class OspfNeighborInfo(BaseModel):
    neighbor: str = Field(..., description="Neighbor IP address")
    router_id: str = Field(default="unknown", description="Neighbor Router ID")
    state: str = Field(default="unknown", description="Adjacency state (e.g. Full, Down, Init, 2-Way)")
    interface: str = Field(default="unknown", description="Local interface connected to neighbor")
    uptime: str = Field(default="unknown", description="Adjacency uptime")


class OspfNeighborsResponse(BaseModel):
    total: int = Field(default=0)
    full: int = Field(default=0)
    down: int = Field(default=0)
    down_neighbors: List[str] = Field(default_factory=list)
    neighbors: Optional[List[OspfNeighborInfo]] = None


class NatRuleInfo(BaseModel):
    rule_id: str = Field(..., description="Rule ID or index")
    chain: str = Field(default="srcnat", description="NAT chain (srcnat/dstnat)")
    action: str = Field(default="masquerade", description="NAT action (masquerade/src-nat/dst-nat)")
    src_address: Optional[str] = Field(default=None, description="Source address")
    dst_address: Optional[str] = Field(default=None, description="Destination address")
    out_interface: Optional[str] = Field(default=None, description="Outbound interface")
    packets: int = Field(default=0, description="Matched packet count")
    bytes: int = Field(default=0, description="Matched byte count")
    disabled: bool = Field(default=False, description="Whether rule is disabled")


class NatRulesResponse(BaseModel):
    total: int = Field(default=0)
    active: int = Field(default=0)
    disabled: int = Field(default=0)
    zero_counter_rules: List[str] = Field(default_factory=list)
    rules: Optional[List[NatRuleInfo]] = None


class RoutingLogsResponse(BaseModel):
    filter_text: Optional[str] = Field(default=None)
    events: List[LogEvent] = Field(default_factory=list)


class TokenUsage(BaseModel):
    model: str = Field(default="", description="OpenRouter model invoked")
    prompt_tokens: int = Field(default=0, description="Prompt token count")
    completion_tokens: int = Field(default=0, description="Completion token count")
    total_tokens: int = Field(default=0, description="Total token count")
    latency_ms: int = Field(default=0, description="Total execution latency in milliseconds")


# --- Profiling Schemas ---

class ToolCallProfiling(BaseModel):
    tool: str = Field(..., description="Tool name")
    duration_ms: int = Field(..., description="Total tool execution duration in milliseconds")
    routeros_ms: Optional[int] = Field(default=None, description="RouterOS API time in milliseconds")


class PerformanceProfiling(BaseModel):
    total_request_ms: int = Field(..., description="Total request execution time in ms")
    intent_detection_ms: int = Field(..., description="Intent detection time in ms")
    tool_calls: List[ToolCallProfiling] = Field(default_factory=list, description="Tool execution timing breakdowns")
    evidence_processing_ms: int = Field(..., description="Python evidence processing & correlation time in ms")
    llm_calls: int = Field(default=1, description="Total LLM invocations")
    openrouter_ms: int = Field(..., description="OpenRouter API latency in ms")
    prompt_tokens: int = Field(default=0)
    completion_tokens: int = Field(default=0)
    total_tokens: int = Field(default=0)


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="User question or prompt for NOC Agent")


class ChatResponse(BaseModel):
    answer: str = Field(..., description="Agent NOC report response")
    tools_used: List[str] = Field(default_factory=list, description="List of tools invoked during investigation")
    usage: Optional[TokenUsage] = Field(default=None, description="OpenRouter token usage and latency metrics")
    profiling: Optional[PerformanceProfiling] = Field(default=None, description="Detailed performance profiling metrics")


class ErrorDetail(BaseModel):
    type: str = Field(..., description="Error category code")
    message: str = Field(..., description="Safe human-readable error description")


class ErrorResponse(BaseModel):
    success: bool = Field(default=False)
    error: ErrorDetail
