from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


def current_utc_timestamp() -> str:
    """Returns ISO 8601 UTC timestamp string."""
    return datetime.now(timezone.utc).isoformat()


class DeviceRecord(BaseModel):
    device_id: str = Field(..., description="Unique device identifier (e.g. host IP or Router alias)")
    name: str = Field(default="MikroTik Router")
    ip_address: str = Field(..., description="Device IP address")
    description: Optional[str] = Field(default="")
    location: Optional[str] = Field(default="")
    role: Optional[str] = Field(default="Router")
    api_protocol: str = Field(default="api")
    api_port: int = Field(default=8728)
    username: Optional[str] = Field(default="admin")
    password: Optional[str] = Field(default="")
    monitoring_enabled: bool = Field(default=True)
    collection_interval: int = Field(default=30)
    monitoring_profile: str = Field(default="Standard")
    model: Optional[str] = Field(default=None)
    version: Optional[str] = Field(default=None)
    status: str = Field(default="HEALTHY")
    last_seen: Optional[str] = Field(default=None)
    is_deleted: bool = Field(default=False)
    updated_at: str = Field(default_factory=current_utc_timestamp)


class DeviceMetricRecord(BaseModel):
    id: Optional[int] = None
    timestamp: str = Field(default_factory=current_utc_timestamp)
    device_id: str
    cpu_percent: float = Field(default=0.0)
    memory_percent: float = Field(default=0.0)
    uptime_seconds: int = Field(default=0)


class InterfaceMetricRecord(BaseModel):
    id: Optional[int] = None
    timestamp: str = Field(default_factory=current_utc_timestamp)
    device_id: str
    interface_name: str
    running: bool = Field(default=True)
    disabled: bool = Field(default=False)
    rx_bps: float = Field(default=0.0)
    tx_bps: float = Field(default=0.0)
    rx_packets: int = Field(default=0)
    tx_packets: int = Field(default=0)
    rx_errors: int = Field(default=0)
    tx_errors: int = Field(default=0)
    rx_drops: int = Field(default=0)
    tx_drops: int = Field(default=0)
    rx_bytes_raw: float = Field(default=0.0)
    tx_bytes_raw: float = Field(default=0.0)


class BgpMetricRecord(BaseModel):
    id: Optional[int] = None
    timestamp: str = Field(default_factory=current_utc_timestamp)
    device_id: str
    peer: str
    remote_address: str
    established: bool = Field(default=True)
    uptime: Optional[str] = None
    prefix_count: int = Field(default=0)


class OspfMetricRecord(BaseModel):
    id: Optional[int] = None
    timestamp: str = Field(default_factory=current_utc_timestamp)
    device_id: str
    neighbor: str
    router_id: str = Field(default="unknown")
    state: str = Field(default="Full")


class NatMetricRecord(BaseModel):
    id: Optional[int] = None
    timestamp: str = Field(default_factory=current_utc_timestamp)
    device_id: str
    rule_id: str
    enabled: bool = Field(default=True)
    packets: int = Field(default=0)
    bytes: int = Field(default=0)
    interface_dependency: Optional[str] = None


class RouteMetricRecord(BaseModel):
    id: Optional[int] = None
    timestamp: str = Field(default_factory=current_utc_timestamp)
    device_id: str
    destination: str
    gateway: str
    active: bool = Field(default=True)
    distance: int = Field(default=1)
    routing_table: str = Field(default="main")


class EventRecord(BaseModel):
    event_id: str = Field(..., description="Unique UUID event identifier")
    device_id: str
    timestamp: str = Field(default_factory=current_utc_timestamp)
    first_seen: str = Field(default_factory=current_utc_timestamp)
    last_seen: str = Field(default_factory=current_utc_timestamp)
    occurrence_count: int = Field(default=1, description="Number of times anomaly persisted across collection cycles")
    status: str = Field(default="ACTIVE", description="ACTIVE, RECOVERED, ACKNOWLEDGED, CLOSED")
    type: str = Field(..., description="Anomaly type (e.g. CPU_SPIKE, INTERFACE_DOWN)")
    severity: str = Field(default="WARNING", description="Severity: INFO, WARNING, MINOR, MAJOR, CRITICAL")
    source: str = Field(default="deterministic_engine")
    entity: str = Field(..., description="Affected entity (interface name, IP, peer, rule)")
    evidence: Dict[str, Any] = Field(default_factory=dict)
    fingerprint: str = Field(..., description="Deduplication key: device_id + type + entity")


class IncidentRecord(BaseModel):
    incident_id: str = Field(..., description="Unique UUID incident identifier")
    device_id: str
    created_at: str = Field(default_factory=current_utc_timestamp)
    updated_at: str = Field(default_factory=current_utc_timestamp)
    severity: str = Field(default="MAJOR")
    status: str = Field(default="OPEN", description="OPEN, ACKNOWLEDGED, RESOLVED, CLOSED")
    root_event_id: str
    correlated_event_ids: List[str] = Field(default_factory=list)
    event_count: int = Field(default=1, description="Distinct event types correlated in this incident")
    occurrence_count: int = Field(default=1, description="Cumulative occurrences of persistent anomalies")
    confidence: str = Field(default="HIGH")
    facts: Dict[str, Any] = Field(default_factory=dict)
    summary: Optional[str] = None
    llm_status: str = Field(default="SUCCESS", description="SUCCESS or FAILED")


class AlertRecord(BaseModel):
    alert_id: str
    incident_id: str
    device_id: str
    timestamp: str = Field(default_factory=current_utc_timestamp)
    type: str
    status: str = Field(default="OPEN")
    message: str


# Phase 5 AI Schemas for Strict JSON LM Studio RCA Response Validation

class Assessment(BaseModel):
    summary: str = Field(..., description="High-level assessment summary")
    confidence: str = Field(default="HIGH", description="HIGH, MEDIUM, or LOW")


class RootCause(BaseModel):
    category: str = Field(..., description="Category of root cause (e.g. TRAFFIC_ANOMALY, INTERFACE_DOWN)")
    finding: str = Field(..., description="Specific root cause finding grounded in evidence")
    confidence: str = Field(default="HIGH", description="HIGH, MEDIUM, or LOW")
    evidence: List[str] = Field(default_factory=list, description="Grounding evidence statements")


class Impact(BaseModel):
    severity: str = Field(default="MAJOR", description="CRITICAL, MAJOR, WARNING, INFO")
    description: str = Field(..., description="Description of network operational impact")
    affected_device: str = Field(..., description="Target device IP or alias")
    affected_entity: str = Field(..., description="Target affected interface, peer, or component")


class ContributingFactor(BaseModel):
    factor: str = Field(..., description="Contributing factor description")
    evidence: str = Field(..., description="Supporting evidence statement")


class RecommendedCheck(BaseModel):
    priority: int = Field(..., description="Priority index (1 = highest)")
    check: str = Field(..., description="Description of diagnostic check to perform")
    reason: str = Field(..., description="Technical rationale for the check")
    command: Optional[str] = Field(default=None, description="Recommended read-only RouterOS diagnostic command")


class NextAction(BaseModel):
    priority: int = Field(..., description="Priority index (1 = highest)")
    action: str = Field(..., description="Actionable troubleshooting recommendation")
    reason: str = Field(..., description="Technical rationale for action")


class CustomerImpact(BaseModel):
    status: str = Field(default="UNKNOWN", description="UNKNOWN, NONE, POSSIBLE, LIKELY, CONFIRMED")
    description: str = Field(..., description="Customer impact assessment description")


class AIAnalysisResponse(BaseModel):
    incident_id: Optional[str] = None
    device_id: Optional[str] = None
    assessment: Assessment
    root_cause: RootCause
    impact: Impact
    contributing_factors: List[ContributingFactor] = Field(default_factory=list)
    recommended_checks: List[RecommendedCheck] = Field(default_factory=list)
    next_actions: List[NextAction] = Field(default_factory=list)
    customer_impact: CustomerImpact
    limitations: List[str] = Field(default_factory=list)


class AIAnalysisRecord(BaseModel):
    analysis_id: str = Field(..., description="Unique UUID analysis identifier")
    incident_id: Optional[str] = None
    device_id: Optional[str] = None
    created_at: str = Field(default_factory=current_utc_timestamp)
    model: str = Field(default="local-model")
    prompt_version: str = Field(default="phase5-v1")
    status: str = Field(default="COMPLETED", description="PENDING, RUNNING, COMPLETED, FAILED, AI_UNAVAILABLE")
    summary: str = Field(default="")
    root_cause_json: Dict[str, Any] = Field(default_factory=dict)
    impact_json: Dict[str, Any] = Field(default_factory=dict)
    recommended_checks_json: List[Dict[str, Any]] = Field(default_factory=list)
    next_actions_json: List[Dict[str, Any]] = Field(default_factory=list)
    full_response_json: Dict[str, Any] = Field(default_factory=dict)
    confidence: str = Field(default="HIGH")
    latency_ms: int = Field(default=0)
    error_message: Optional[str] = None

