from typing import List, Optional
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


class BgpPeerInfo(BaseModel):
    name: str = Field(..., description="BGP peer session name")
    remote_address: str = Field(default="unknown", description="Remote peer IP address")
    local_address: str = Field(default="", description="Local IP address")
    state: str = Field(default="unknown", description="BGP session state (e.g. established, connect)")
    uptime: str = Field(default="", description="BGP peer uptime")
    established: bool = Field(default=False, description="Whether BGP session is established")
    prefix_count: int = Field(default=0, description="Number of prefixes received/advertised")
    remote_as: str = Field(default="", description="Remote Autonomous System Number")
    local_as: str = Field(default="", description="Local Autonomous System Number")


class BgpSummary(BaseModel):
    total: int = Field(default=0)
    established: int = Field(default=0)
    down: int = Field(default=0)
    down_peers: List[str] = Field(default_factory=list, description="Names of non-established BGP peers")


class BgpPeersResponse(BaseModel):
    summary: BgpSummary
    details: Optional[List[BgpPeerInfo]] = None


class TokenUsage(BaseModel):
    model: str = Field(default="", description="OpenRouter model invoked")
    prompt_tokens: int = Field(default=0, description="Prompt token count")
    completion_tokens: int = Field(default=0, description="Completion token count")
    total_tokens: int = Field(default=0, description="Total token count")
    latency_ms: int = Field(default=0, description="Total execution latency in milliseconds")


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, description="User question or prompt for NOC Agent")


class ChatResponse(BaseModel):
    answer: str = Field(..., description="Agent NOC report response")
    tools_used: List[str] = Field(default_factory=list, description="List of tools invoked during investigation")
    usage: Optional[TokenUsage] = Field(default=None, description="OpenRouter token usage and latency metrics")


class ErrorDetail(BaseModel):
    type: str = Field(..., description="Error category code")
    message: str = Field(..., description="Safe human-readable error description")


class ErrorResponse(BaseModel):
    success: bool = Field(default=False)
    error: ErrorDetail
