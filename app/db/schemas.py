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
    model: Optional[str] = Field(default=None)
    version: Optional[str] = Field(default=None)
    status: str = Field(default="ONLINE")
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
    status: str = Field(default="OPEN", description="OPEN, ACKNOWLEDGED, RESOLVED")
    root_event_id: str
    correlated_event_ids: List[str] = Field(default_factory=list)
    confidence: str = Field(default="HIGH")
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
