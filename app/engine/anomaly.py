import uuid
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone

from app.db.schemas import EventRecord
from app.engine.baseline import calculate_baseline, BaselineResult

logger = logging.getLogger("mikrotik_noc_agent.anomaly")


def generate_fingerprint(device_id: str, event_type: str, entity: str) -> str:
    """Generates unique deduplication fingerprint: device_id + event_type + entity."""
    return f"{device_id}:{event_type}:{entity}"


class AnomalyDetector:
    """Deterministic anomaly detection engine for Phase 4 AIOps telemetry."""

    @staticmethod
    def check_device_cpu_memory(device_id: str, current_cpu: float, current_mem: float, cpu_history: List[float], mem_history: List[float]) -> List[EventRecord]:
        events: List[EventRecord] = []
        cpu_bl = calculate_baseline(cpu_history, min_samples=10)
        
        # CPU Spike Rule
        if cpu_bl.baseline_status == "NORMAL" and current_cpu > (cpu_bl.moving_average + 3.0 * cpu_bl.stddev) and current_cpu > 70.0:
            severity = "CRITICAL" if current_cpu > 90.0 else "MAJOR" if current_cpu > 80.0 else "WARNING"
            fp = generate_fingerprint(device_id, "CPU_SPIKE", "system")
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="CPU_SPIKE",
                severity=severity,
                source="deterministic_engine",
                entity="system",
                evidence={
                    "current_cpu": current_cpu,
                    "moving_average": round(cpu_bl.moving_average, 2),
                    "stddev": round(cpu_bl.stddev, 2),
                    "sample_count": cpu_bl.sample_count
                },
                fingerprint=fp
            ))
        elif current_cpu > 90.0:
            fp = generate_fingerprint(device_id, "CPU_SPIKE", "system")
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="CPU_SPIKE",
                severity="MAJOR",
                source="deterministic_engine",
                entity="system",
                evidence={"current_cpu": current_cpu},
                fingerprint=fp
            ))

        # Memory Spike Rule
        if current_mem > 85.0:
            fp = generate_fingerprint(device_id, "MEMORY_SPIKE", "system")
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="MEMORY_SPIKE",
                severity="WARNING" if current_mem < 95.0 else "MAJOR",
                source="deterministic_engine",
                entity="system",
                evidence={"current_memory": current_mem},
                fingerprint=fp
            ))

        return events

    @staticmethod
    def check_interface_status(device_id: str, interface_name: str, current_running: bool, current_disabled: bool, prev_running: Optional[bool], rx_bps_history: List[float]) -> List[EventRecord]:
        events: List[EventRecord] = []
        
        # Interface Down Rule
        if prev_running is True and current_running is False and not current_disabled:
            fp = generate_fingerprint(device_id, "INTERFACE_DOWN", interface_name)
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="INTERFACE_DOWN",
                severity="MAJOR",
                source="deterministic_engine",
                entity=interface_name,
                evidence={"interface": interface_name, "prev_running": True, "current_running": False},
                fingerprint=fp
            ))

        # Interface Recovered Rule
        if prev_running is False and current_running is True:
            fp = generate_fingerprint(device_id, "INTERFACE_RECOVERED", interface_name)
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="INTERFACE_RECOVERED",
                severity="INFO",
                source="deterministic_engine",
                entity=interface_name,
                evidence={"interface": interface_name, "prev_running": False, "current_running": True},
                fingerprint=fp
            ))

        # Traffic Drop Rule (Baseline requirement >= 10 samples)
        if rx_bps_history and current_running:
            tr_bl = calculate_baseline(rx_bps_history, min_samples=10)
            if tr_bl.baseline_status == "NORMAL" and tr_bl.moving_average > 1000.0:
                current_bps = rx_bps_history[0]
                if current_bps < (tr_bl.moving_average * 0.3):
                    fp = generate_fingerprint(device_id, "TRAFFIC_DROP", interface_name)
                    events.append(EventRecord(
                        event_id=str(uuid.uuid4()),
                        device_id=device_id,
                        type="TRAFFIC_DROP",
                        severity="MAJOR",
                        source="deterministic_engine",
                        entity=interface_name,
                        evidence={
                            "current_bps": current_bps,
                            "moving_average_bps": round(tr_bl.moving_average, 2),
                            "drop_percentage": round((1.0 - (current_bps / tr_bl.moving_average)) * 100.0, 1),
                            "sample_count": tr_bl.sample_count
                        },
                        fingerprint=fp
                    ))

        return events

    @staticmethod
    def check_bgp_status(device_id: str, peer: str, current_est: bool, prev_est: Optional[bool], current_prefix: int, prev_prefix: Optional[int]) -> List[EventRecord]:
        events: List[EventRecord] = []

        # BGP Session Down Rule
        if prev_est is True and current_est is False:
            fp = generate_fingerprint(device_id, "BGP_SESSION_DOWN", peer)
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="BGP_SESSION_DOWN",
                severity="MAJOR",
                source="deterministic_engine",
                entity=peer,
                evidence={"peer": peer, "prev_established": True, "current_established": False},
                fingerprint=fp
            ))

        # BGP Session Recovered Rule
        if prev_est is False and current_est is True:
            fp = generate_fingerprint(device_id, "BGP_SESSION_RECOVERED", peer)
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="BGP_SESSION_RECOVERED",
                severity="INFO",
                source="deterministic_engine",
                entity=peer,
                evidence={"peer": peer, "prev_established": False, "current_established": True},
                fingerprint=fp
            ))

        # BGP Prefix Drop Rule
        if current_est and prev_prefix is not None and prev_prefix > 0:
            if current_prefix < (prev_prefix * 0.5):
                fp = generate_fingerprint(device_id, "BGP_PREFIX_DROP", peer)
                events.append(EventRecord(
                    event_id=str(uuid.uuid4()),
                    device_id=device_id,
                    type="BGP_PREFIX_DROP",
                    severity="WARNING",
                    source="deterministic_engine",
                    entity=peer,
                    evidence={"peer": peer, "prev_prefix_count": prev_prefix, "current_prefix_count": current_prefix},
                    fingerprint=fp
                ))

        return events

    @staticmethod
    def check_ospf_status(device_id: str, neighbor: str, current_state: str, prev_state: Optional[str]) -> List[EventRecord]:
        events: List[EventRecord] = []

        is_curr_full = ("full" in current_state.lower())
        is_prev_full = ("full" in prev_state.lower()) if prev_state else None

        # OSPF Neighbor Down Rule
        if is_prev_full is True and is_curr_full is False:
            fp = generate_fingerprint(device_id, "OSPF_NEIGHBOR_DOWN", neighbor)
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="OSPF_NEIGHBOR_DOWN",
                severity="MAJOR",
                source="deterministic_engine",
                entity=neighbor,
                evidence={"neighbor": neighbor, "prev_state": prev_state, "current_state": current_state},
                fingerprint=fp
            ))

        # OSPF Neighbor Recovered Rule
        if is_prev_full is False and is_curr_full is True:
            fp = generate_fingerprint(device_id, "OSPF_NEIGHBOR_RECOVERED", neighbor)
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="OSPF_NEIGHBOR_RECOVERED",
                severity="INFO",
                source="deterministic_engine",
                entity=neighbor,
                evidence={"neighbor": neighbor, "prev_state": prev_state, "current_state": current_state},
                fingerprint=fp
            ))

        return events

    @staticmethod
    def check_default_route_status(device_id: str, current_active: bool, prev_active: Optional[bool]) -> List[EventRecord]:
        events: List[EventRecord] = []

        # Default Route Down Rule
        if prev_active is True and current_active is False:
            fp = generate_fingerprint(device_id, "DEFAULT_ROUTE_DOWN", "0.0.0.0/0")
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="DEFAULT_ROUTE_DOWN",
                severity="CRITICAL",
                source="deterministic_engine",
                entity="0.0.0.0/0",
                evidence={"destination": "0.0.0.0/0", "prev_active": True, "current_active": False},
                fingerprint=fp
            ))

        # Default Route Recovered Rule
        if prev_active is False and current_active is True:
            fp = generate_fingerprint(device_id, "DEFAULT_ROUTE_RECOVERED", "0.0.0.0/0")
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="DEFAULT_ROUTE_RECOVERED",
                severity="INFO",
                source="deterministic_engine",
                entity="0.0.0.0/0",
                evidence={"destination": "0.0.0.0/0", "prev_active": False, "current_active": True},
                fingerprint=fp
            ))

        return events
