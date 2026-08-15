import uuid
import time
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone, timedelta

from app.config import settings
from app.db.schemas import EventRecord
from app.engine.baseline import calculate_baseline, BaselineResult
from app.db.database import db

logger = logging.getLogger("mikrotik_noc_agent.anomaly")

# Global Diagnostic State for Phase 4.3/4.4 Engine Diagnostics
engine_diagnostics: Dict[str, Any] = {
    "engine": "ready",
    "last_evaluation": None,
    "devices_evaluated": 0,
    "metrics_evaluated": 0,
    "rules_evaluated": 11,
    "anomalies_detected": 0,
    "events_created": 0,
    "incidents_created": 0,
    "status": "NOT_EVALUATED",
    "rule_details": {}
}

CONFIGURED_RULES: List[Dict[str, Any]] = [
    {"rule": "CPU_SPIKE", "type": "baseline", "required_samples": 10, "enabled": True},
    {"rule": "MEMORY_SPIKE", "type": "baseline", "required_samples": 10, "enabled": True},
    {"rule": "TRAFFIC_DROP", "type": "baseline", "required_samples": 10, "enabled": True},
    {"rule": "TRAFFIC_SPIKE", "type": "baseline", "required_samples": 10, "enabled": True},
    {"rule": "INTERFACE_DOWN", "type": "state_transition", "required_samples": 2, "enabled": True},
    {"rule": "INTERFACE_ERROR", "type": "counter", "required_samples": 1, "enabled": True},
    {"rule": "INTERFACE_DROP", "type": "counter", "required_samples": 1, "enabled": True},
    {"rule": "BGP_SESSION_DOWN", "type": "state_transition", "required_samples": 2, "enabled": True},
    {"rule": "BGP_PREFIX_DROP", "type": "baseline", "required_samples": 10, "enabled": True},
    {"rule": "OSPF_NEIGHBOR_DOWN", "type": "state_transition", "required_samples": 2, "enabled": True},
    {"rule": "DEFAULT_ROUTE_DOWN", "type": "state_transition", "required_samples": 2, "enabled": True},
]


def generate_fingerprint(device_id: str, event_type: str, entity: str) -> str:
    """Generates unique deduplication fingerprint: device_id + event_type + entity."""
    return f"{device_id}:{event_type}:{entity}"


class AnomalyDetector:
    """Deterministic anomaly detection engine for Phase 4 AIOps telemetry."""

    @staticmethod
    def run_evaluation_cycle() -> Dict[str, Any]:
        """
        Executes ONE deterministic anomaly evaluation cycle across historical SQLite telemetry using time-aware lookback windows.
        Updates engine diagnostics and returns statistics breakdown.
        """
        t_start = time.perf_counter()
        devices = db.get_devices()
        total_metrics = 0
        rule_details: Dict[str, Any] = {
            "CPU_SPIKE": {"evaluated": False, "samples": 0, "required": settings.MIN_BASELINE_SAMPLES, "status": "NOT_EVALUATED", "anomaly": False},
            "MEMORY_SPIKE": {"evaluated": False, "samples": 0, "required": settings.MIN_BASELINE_SAMPLES, "status": "NOT_EVALUATED", "anomaly": False},
            "TRAFFIC_DROP": {"evaluated": False, "samples": 0, "required": settings.MIN_BASELINE_SAMPLES, "status": "NOT_EVALUATED", "anomaly": False},
            "TRAFFIC_SPIKE": {"evaluated": False, "samples": 0, "required": settings.MIN_BASELINE_SAMPLES, "status": "NOT_EVALUATED", "anomaly": False},
            "INTERFACE_DOWN": {"evaluated": False, "samples": 0, "required": 2, "status": "NOT_EVALUATED", "anomaly": False},
            "BGP_SESSION_DOWN": {"evaluated": False, "samples": 0, "required": 2, "status": "NOT_EVALUATED", "anomaly": False},
            "BGP_PREFIX_DROP": {"evaluated": False, "samples": 0, "required": settings.MIN_BASELINE_SAMPLES, "status": "NOT_EVALUATED", "anomaly": False},
            "OSPF_NEIGHBOR_DOWN": {"evaluated": False, "samples": 0, "required": 2, "status": "NOT_EVALUATED", "anomaly": False},
            "DEFAULT_ROUTE_DOWN": {"evaluated": False, "samples": 0, "required": 2, "status": "NOT_EVALUATED", "anomaly": False},
        }

        all_detected_events: List[EventRecord] = []
        has_insufficient_history = False

        for dev in devices:
            dev_id = dev["device_id"]

            # 1. System Metrics Evaluation (Lookback window)
            sys_metrics = db.get_recent_device_metrics(dev_id, limit=100, lookback_minutes=settings.ANOMALY_LOOKBACK_MINUTES)
            total_metrics += len(sys_metrics)
            if sys_metrics:
                cpu_hist = [m["cpu_percent"] for m in sys_metrics]
                mem_hist = [m["memory_percent"] for m in sys_metrics]
                curr_cpu = sys_metrics[0]["cpu_percent"]
                curr_mem = sys_metrics[0]["memory_percent"]

                evts = AnomalyDetector.check_device_cpu_memory(dev_id, curr_cpu, curr_mem, cpu_hist, mem_hist)
                all_detected_events.extend(evts)

                now_utc = datetime.now(timezone.utc)
                win_start = (now_utc - timedelta(minutes=settings.ANOMALY_LOOKBACK_MINUTES)).isoformat()
                win_end = now_utc.isoformat()

                rule_details["CPU_SPIKE"]["evaluated"] = True
                rule_details["CPU_SPIKE"]["device_id"] = dev_id
                rule_details["CPU_SPIKE"]["entity"] = "system"
                rule_details["CPU_SPIKE"]["query_window_start"] = win_start
                rule_details["CPU_SPIKE"]["query_window_end"] = win_end
                rule_details["CPU_SPIKE"]["available_samples"] = len(sys_metrics)
                rule_details["CPU_SPIKE"]["samples_used"] = len(cpu_hist)
                rule_details["CPU_SPIKE"]["samples"] = max(rule_details["CPU_SPIKE"]["samples"], len(cpu_hist))
                if len(cpu_hist) < settings.MIN_BASELINE_SAMPLES:
                    rule_details["CPU_SPIKE"]["status"] = "INSUFFICIENT_HISTORY"
                    has_insufficient_history = True
                elif any(e.type == "CPU_SPIKE" for e in evts):
                    rule_details["CPU_SPIKE"]["anomaly"] = True
                    rule_details["CPU_SPIKE"]["status"] = "ANOMALY"
                else:
                    rule_details["CPU_SPIKE"]["status"] = "HEALTHY"

                rule_details["MEMORY_SPIKE"]["evaluated"] = True
                rule_details["MEMORY_SPIKE"]["device_id"] = dev_id
                rule_details["MEMORY_SPIKE"]["entity"] = "system"
                rule_details["MEMORY_SPIKE"]["query_window_start"] = win_start
                rule_details["MEMORY_SPIKE"]["query_window_end"] = win_end
                rule_details["MEMORY_SPIKE"]["available_samples"] = len(sys_metrics)
                rule_details["MEMORY_SPIKE"]["samples_used"] = len(mem_hist)
                rule_details["MEMORY_SPIKE"]["samples"] = max(rule_details["MEMORY_SPIKE"]["samples"], len(mem_hist))
                if len(mem_hist) < settings.MIN_BASELINE_SAMPLES:
                    rule_details["MEMORY_SPIKE"]["status"] = "INSUFFICIENT_HISTORY"
                    has_insufficient_history = True
                elif any(e.type == "MEMORY_SPIKE" for e in evts):
                    rule_details["MEMORY_SPIKE"]["anomaly"] = True
                    rule_details["MEMORY_SPIKE"]["status"] = "ANOMALY"
                else:
                    rule_details["MEMORY_SPIKE"]["status"] = "HEALTHY"

            # 2. Interface Metrics Evaluation
            with db.get_connection() as conn:
                iface_names = [r[0] for r in conn.execute("SELECT DISTINCT interface_name FROM interface_metrics WHERE device_id = ?", (dev_id,)).fetchall()]
            
            for if_name in iface_names:
                if_metrics = db.get_recent_interface_metrics(dev_id, if_name, limit=100, lookback_minutes=settings.ANOMALY_LOOKBACK_MINUTES)
                total_metrics += len(if_metrics)
                if if_metrics:
                    curr_running = bool(if_metrics[0]["running"])
                    curr_disabled = bool(if_metrics[0]["disabled"])
                    prev_running = bool(if_metrics[1]["running"]) if len(if_metrics) > 1 else None
                    rx_bps_hist = [m["rx_bps"] for m in if_metrics]

                    evts = AnomalyDetector.check_interface_status(dev_id, if_name, curr_running, curr_disabled, prev_running, rx_bps_hist)
                    all_detected_events.extend(evts)

                    rule_details["INTERFACE_DOWN"]["evaluated"] = True
                    rule_details["INTERFACE_DOWN"]["device_id"] = dev_id
                    rule_details["INTERFACE_DOWN"]["entity"] = if_name
                    rule_details["INTERFACE_DOWN"]["samples"] = max(rule_details["INTERFACE_DOWN"]["samples"], len(if_metrics))
                    if len(if_metrics) < 2:
                        rule_details["INTERFACE_DOWN"]["status"] = "INSUFFICIENT_HISTORY"
                    elif any(e.type == "INTERFACE_DOWN" for e in evts):
                        rule_details["INTERFACE_DOWN"]["anomaly"] = True
                        rule_details["INTERFACE_DOWN"]["status"] = "ANOMALY"
                    else:
                        rule_details["INTERFACE_DOWN"]["status"] = "HEALTHY"

                    rule_details["TRAFFIC_DROP"]["evaluated"] = True
                    rule_details["TRAFFIC_DROP"]["device_id"] = dev_id
                    rule_details["TRAFFIC_DROP"]["entity"] = if_name
                    rule_details["TRAFFIC_DROP"]["available_samples"] = max(rule_details["TRAFFIC_DROP"].get("available_samples", 0), len(if_metrics))
                    rule_details["TRAFFIC_DROP"]["samples_used"] = max(rule_details["TRAFFIC_DROP"].get("samples_used", 0), len(rx_bps_hist))
                    rule_details["TRAFFIC_DROP"]["samples"] = max(rule_details["TRAFFIC_DROP"]["samples"], len(rx_bps_hist))
                    if len(rx_bps_hist) < settings.MIN_BASELINE_SAMPLES:
                        rule_details["TRAFFIC_DROP"]["status"] = "INSUFFICIENT_HISTORY"
                        has_insufficient_history = True
                    elif any(e.type == "TRAFFIC_DROP" for e in evts):
                        rule_details["TRAFFIC_DROP"]["anomaly"] = True
                        rule_details["TRAFFIC_DROP"]["status"] = "ANOMALY"
                    else:
                        rule_details["TRAFFIC_DROP"]["status"] = "HEALTHY"

                    rule_details["TRAFFIC_SPIKE"]["evaluated"] = True
                    rule_details["TRAFFIC_SPIKE"]["device_id"] = dev_id
                    rule_details["TRAFFIC_SPIKE"]["entity"] = if_name
                    rule_details["TRAFFIC_SPIKE"]["available_samples"] = max(rule_details["TRAFFIC_SPIKE"].get("available_samples", 0), len(if_metrics))
                    rule_details["TRAFFIC_SPIKE"]["samples_used"] = max(rule_details["TRAFFIC_SPIKE"].get("samples_used", 0), len(rx_bps_hist))
                    rule_details["TRAFFIC_SPIKE"]["samples"] = max(rule_details["TRAFFIC_SPIKE"]["samples"], len(rx_bps_hist))
                    if len(rx_bps_hist) < settings.MIN_BASELINE_SAMPLES:
                        rule_details["TRAFFIC_SPIKE"]["status"] = "INSUFFICIENT_HISTORY"
                        has_insufficient_history = True
                    elif any(e.type == "TRAFFIC_SPIKE" for e in evts):
                        rule_details["TRAFFIC_SPIKE"]["anomaly"] = True
                        rule_details["TRAFFIC_SPIKE"]["status"] = "ANOMALY"
                    else:
                        rule_details["TRAFFIC_SPIKE"]["status"] = "HEALTHY"

            # 3. BGP Peer Evaluation (Lookback 30 min)
            with db.get_connection() as conn:
                peers = [r[0] for r in conn.execute("SELECT DISTINCT peer FROM bgp_metrics WHERE device_id = ?", (dev_id,)).fetchall()]
            for peer_name in peers:
                bgp_metrics = db.get_recent_bgp_metrics(dev_id, peer_name, limit=50, lookback_minutes=settings.BGP_LOOKBACK_MINUTES)
                total_metrics += len(bgp_metrics)
                if bgp_metrics:
                    curr_est = bool(bgp_metrics[0]["established"])
                    prev_est = bool(bgp_metrics[1]["established"]) if len(bgp_metrics) > 1 else None
                    curr_pfx = int(bgp_metrics[0]["prefix_count"])
                    prev_pfx = int(bgp_metrics[1]["prefix_count"]) if len(bgp_metrics) > 1 else None

                    evts = AnomalyDetector.check_bgp_status(dev_id, peer_name, curr_est, prev_est, curr_pfx, prev_pfx)
                    all_detected_events.extend(evts)

                    rule_details["BGP_SESSION_DOWN"]["evaluated"] = True
                    rule_details["BGP_SESSION_DOWN"]["samples"] = max(rule_details["BGP_SESSION_DOWN"]["samples"], len(bgp_metrics))
                    if len(bgp_metrics) < 2:
                        rule_details["BGP_SESSION_DOWN"]["status"] = "INSUFFICIENT_HISTORY"
                    elif any(e.type == "BGP_SESSION_DOWN" for e in evts):
                        rule_details["BGP_SESSION_DOWN"]["anomaly"] = True
                        rule_details["BGP_SESSION_DOWN"]["status"] = "ANOMALY"
                    else:
                        rule_details["BGP_SESSION_DOWN"]["status"] = "HEALTHY"

                    rule_details["BGP_PREFIX_DROP"]["evaluated"] = True
                    rule_details["BGP_PREFIX_DROP"]["samples"] = max(rule_details["BGP_PREFIX_DROP"]["samples"], len(bgp_metrics))
                    if len(bgp_metrics) < settings.MIN_BASELINE_SAMPLES:
                        rule_details["BGP_PREFIX_DROP"]["status"] = "INSUFFICIENT_HISTORY"
                        has_insufficient_history = True
                    elif any(e.type == "BGP_PREFIX_DROP" for e in evts):
                        rule_details["BGP_PREFIX_DROP"]["anomaly"] = True
                        rule_details["BGP_PREFIX_DROP"]["status"] = "ANOMALY"
                    else:
                        rule_details["BGP_PREFIX_DROP"]["status"] = "HEALTHY"

            # 4. OSPF Neighbor Evaluation
            with db.get_connection() as conn:
                nbrs = [r[0] for r in conn.execute("SELECT DISTINCT neighbor FROM ospf_metrics WHERE device_id = ?", (dev_id,)).fetchall()]
            for nbr_name in nbrs:
                ospf_metrics = db.get_recent_ospf_metrics(dev_id, nbr_name, limit=50, lookback_minutes=settings.ANOMALY_LOOKBACK_MINUTES)
                total_metrics += len(ospf_metrics)
                if ospf_metrics:
                    curr_st = str(ospf_metrics[0]["state"])
                    prev_st = str(ospf_metrics[1]["state"]) if len(ospf_metrics) > 1 else None

                    evts = AnomalyDetector.check_ospf_status(dev_id, nbr_name, curr_st, prev_st)
                    all_detected_events.extend(evts)

                    rule_details["OSPF_NEIGHBOR_DOWN"]["evaluated"] = True
                    rule_details["OSPF_NEIGHBOR_DOWN"]["samples"] = max(rule_details["OSPF_NEIGHBOR_DOWN"]["samples"], len(ospf_metrics))
                    if len(ospf_metrics) < 2:
                        rule_details["OSPF_NEIGHBOR_DOWN"]["status"] = "INSUFFICIENT_HISTORY"
                    elif any(e.type == "OSPF_NEIGHBOR_DOWN" for e in evts):
                        rule_details["OSPF_NEIGHBOR_DOWN"]["anomaly"] = True
                        rule_details["OSPF_NEIGHBOR_DOWN"]["status"] = "ANOMALY"
                    else:
                        rule_details["OSPF_NEIGHBOR_DOWN"]["status"] = "HEALTHY"

            # 5. Default Route Evaluation
            with db.get_connection() as conn:
                route_metrics = conn.execute("SELECT * FROM route_metrics WHERE device_id = ? AND destination = '0.0.0.0/0' ORDER BY id DESC LIMIT 50", (dev_id,)).fetchall()
                total_metrics += len(route_metrics)
                if route_metrics:
                    latest_ts = route_metrics[0]["timestamp"]
                    latest_batch = [r for r in route_metrics if r["timestamp"] == latest_ts]
                    curr_act = any(bool(r["active"]) for r in latest_batch)

                    other_batches = [r for r in route_metrics if r["timestamp"] != latest_ts]
                    prev_act = None
                    if other_batches:
                        prev_ts = other_batches[0]["timestamp"]
                        prev_batch = [r for r in other_batches if r["timestamp"] == prev_ts]
                        prev_act = any(bool(r["active"]) for r in prev_batch)

                    evts = AnomalyDetector.check_default_route_status(dev_id, curr_act, prev_act)
                    all_detected_events.extend(evts)

                    rule_details["DEFAULT_ROUTE_DOWN"]["evaluated"] = True
                    rule_details["DEFAULT_ROUTE_DOWN"]["samples"] = max(rule_details["DEFAULT_ROUTE_DOWN"]["samples"], len(route_metrics))
                    if len(route_metrics) < 2:
                        rule_details["DEFAULT_ROUTE_DOWN"]["status"] = "INSUFFICIENT_HISTORY"
                    elif any(e.type == "DEFAULT_ROUTE_DOWN" for e in evts):
                        rule_details["DEFAULT_ROUTE_DOWN"]["anomaly"] = True
                        rule_details["DEFAULT_ROUTE_DOWN"]["status"] = "ANOMALY"
                    else:
                        rule_details["DEFAULT_ROUTE_DOWN"]["status"] = "HEALTHY"

        # Deduplicate and process events via Correlation Engine
        from app.engine.correlation import CorrelationEngine
        if all_detected_events:
            CorrelationEngine.process_events(all_detected_events)

        t_end = time.perf_counter()
        dur_ms = max(1, int((t_end - t_start) * 1000))

        # Overall Status Governance (Task 16: Never report NO_ANOMALY / HEALTHY if any critical rule has INSUFFICIENT_HISTORY)
        if all_detected_events:
            overall_status = "ANOMALY"
        elif has_insufficient_history:
            overall_status = "INSUFFICIENT_HISTORY"
        else:
            overall_status = "HEALTHY"

        # Update Engine Diagnostics
        engine_diagnostics["engine"] = "running"
        engine_diagnostics["last_evaluation"] = datetime.now(timezone.utc).isoformat()
        engine_diagnostics["devices_evaluated"] = len(devices)
        engine_diagnostics["metrics_evaluated"] = total_metrics
        engine_diagnostics["rules_evaluated"] = len(CONFIGURED_RULES)
        engine_diagnostics["anomalies_detected"] = len(all_detected_events)
        engine_diagnostics["status"] = overall_status
        engine_diagnostics["rule_details"] = rule_details

        return {
            "status": "completed",
            "devices_evaluated": len(devices),
            "rules_evaluated": len(CONFIGURED_RULES),
            "anomalies_detected": len(all_detected_events),
            "events_created": len(all_detected_events),
            "duration_ms": dur_ms,
            "overall_status": overall_status,
            "rules": rule_details
        }

    @staticmethod
    def check_device_cpu_memory(device_id: str, current_cpu: float, current_mem: float, cpu_history: List[float], mem_history: List[float]) -> List[EventRecord]:
        events: List[EventRecord] = []
        cpu_bl = calculate_baseline(cpu_history, min_samples=settings.MIN_BASELINE_SAMPLES)
        
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
                severity="CRITICAL",
                source="deterministic_engine",
                entity="system",
                evidence={"current_cpu": current_cpu},
                fingerprint=fp
            ))

        # Memory Spike Rule
        mem_bl = calculate_baseline(mem_history, min_samples=settings.MIN_BASELINE_SAMPLES)
        if current_mem > 85.0 or (mem_bl.baseline_status == "NORMAL" and current_mem > (mem_bl.moving_average + 3.0 * mem_bl.stddev) and current_mem > 75.0):
            fp = generate_fingerprint(device_id, "MEMORY_SPIKE", "system")
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="MEMORY_SPIKE",
                severity="WARNING" if current_mem < 90.0 else "MAJOR",
                source="deterministic_engine",
                entity="system",
                evidence={"current_memory": current_mem},
                fingerprint=fp
            ))

        return events

    @staticmethod
    def check_interface_status(
        device_id: str,
        interface_name: str,
        current_running: bool,
        current_disabled: bool,
        prev_running: Optional[bool],
        rx_bps_history: List[float],
        errors_history: Optional[List[int]] = None,
        drops_history: Optional[List[int]] = None,
        interface_capacity_bps: Optional[float] = None,
    ) -> List[EventRecord]:
        events: List[EventRecord] = []
        
        # Interface Down Rule (Differentiating ADMIN_DOWN vs UNEXPECTED_DOWN)
        if current_disabled:
            # ADMIN_DOWN: disabled by administrator (not an operational anomaly)
            pass
        elif prev_running is True and current_running is False:
            # UNEXPECTED_DOWN: running interface suddenly went down
            fp = generate_fingerprint(device_id, "INTERFACE_DOWN", interface_name)
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="INTERFACE_DOWN",
                severity="MAJOR",
                source="deterministic_engine",
                entity=interface_name,
                evidence={"interface": interface_name, "prev_running": True, "current_running": False, "state": "UNEXPECTED_DOWN"},
                fingerprint=fp
            ))

        # Interface Recovered Rule
        if prev_running is False and current_running is True and not current_disabled:
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

        # Counter Rules: INTERFACE_ERROR & INTERFACE_DROP
        if errors_history and len(errors_history) >= 2:
            delta_err = errors_history[0] - errors_history[1]
            if delta_err >= settings.INTERFACE_ERROR_THRESHOLD:
                fp = generate_fingerprint(device_id, "INTERFACE_ERROR", interface_name)
                events.append(EventRecord(
                    event_id=str(uuid.uuid4()),
                    device_id=device_id,
                    type="INTERFACE_ERROR",
                    severity="WARNING",
                    source="deterministic_engine",
                    entity=interface_name,
                    evidence={"interface": interface_name, "delta_errors": delta_err, "current_errors": errors_history[0], "previous_errors": errors_history[1]},
                    fingerprint=fp
                ))

        if drops_history and len(drops_history) >= 2:
            delta_drop = drops_history[0] - drops_history[1]
            if delta_drop >= settings.INTERFACE_DROP_THRESHOLD:
                fp = generate_fingerprint(device_id, "INTERFACE_DROP", interface_name)
                events.append(EventRecord(
                    event_id=str(uuid.uuid4()),
                    device_id=device_id,
                    type="INTERFACE_DROP",
                    severity="WARNING",
                    source="deterministic_engine",
                    entity=interface_name,
                    evidence={"interface": interface_name, "delta_drops": delta_drop, "current_drops": drops_history[0], "previous_drops": drops_history[1]},
                    fingerprint=fp
                ))

        # Traffic Drop & Spike Rules (Baseline requirement >= MIN_BASELINE_SAMPLES)
        if rx_bps_history and current_running:
            tr_bl = calculate_baseline(rx_bps_history, min_samples=settings.MIN_BASELINE_SAMPLES)
            
            # Impossible Baseline Protection: reject baseline if it exceeds known interface capacity
            if interface_capacity_bps and tr_bl.moving_average > interface_capacity_bps:
                logger.warning(f"BASELINE_INVALID for interface {interface_name}: baseline ({tr_bl.moving_average} bps) > capacity ({interface_capacity_bps} bps)")
                tr_bl.baseline_status = "BASELINE_INVALID"

            # Low Traffic Interfaces Protection: Do NOT create TRAFFIC_DROP if baseline moving average is below MIN_BASELINE_BPS (10 Kbps)
            if tr_bl.baseline_status == "NORMAL" and tr_bl.moving_average >= settings.MIN_BASELINE_BPS:
                current_bps = rx_bps_history[0]
                drop_pct = (1.0 - (current_bps / tr_bl.moving_average)) * 100.0 if tr_bl.moving_average > 0 else 0.0
                
                # Persistence requirement (consecutive samples below threshold)
                p_samples = min(len(rx_bps_history), settings.PERSISTENCE_SAMPLES)
                recent_samples = rx_bps_history[:p_samples]
                is_persistent_low = all(s < (tr_bl.moving_average * (1.0 - (settings.TRAFFIC_DROP_PERCENT / 100.0))) for s in recent_samples)

                if drop_pct >= settings.TRAFFIC_DROP_PERCENT and is_persistent_low:
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
                            "drop_percentage": round(drop_pct, 1),
                            "sample_count": tr_bl.sample_count,
                            "persistence_samples": p_samples
                        },
                        fingerprint=fp
                    ))
                elif current_bps > (tr_bl.moving_average * (1.0 + (settings.TRAFFIC_SPIKE_THRESHOLD_PERCENT / 100.0))):
                    fp = generate_fingerprint(device_id, "TRAFFIC_SPIKE", interface_name)
                    events.append(EventRecord(
                        event_id=str(uuid.uuid4()),
                        device_id=device_id,
                        type="TRAFFIC_SPIKE",
                        severity="WARNING",
                        source="deterministic_engine",
                        entity=interface_name,
                        evidence={
                            "current_bps": current_bps,
                            "moving_average_bps": round(tr_bl.moving_average, 2),
                            "spike_ratio": round(current_bps / tr_bl.moving_average, 2),
                            "sample_count": tr_bl.sample_count
                        },
                        fingerprint=fp
                    ))

        return events

    @staticmethod
    def check_bgp_status(device_id: str, peer: str, current_est: bool, prev_est: Optional[bool], current_prefix: int, prev_prefix: Optional[int]) -> List[EventRecord]:
        events: List[EventRecord] = []

        # BGP Session Down Rule (Only triggers when previous was established AND current is not established)
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

        # BGP Prefix Drop Rule (Requires prev_prefix > 0)
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

        # OSPF Neighbor Down Rule (Only Full -> non-Full)
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
        if current_active is False and (prev_active is True or prev_active is None):
            fp = generate_fingerprint(device_id, "DEFAULT_ROUTE_DOWN", "0.0.0.0/0")
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="DEFAULT_ROUTE_DOWN",
                severity="CRITICAL",
                source="deterministic_engine",
                entity="0.0.0.0/0",
                evidence={"destination": "0.0.0.0/0", "prev_active": prev_active, "current_active": False},
                fingerprint=fp
            ))

        # Check if active DEFAULT_ROUTE_DOWN events exist in DB for this device
        active_down_cnt = 0
        try:
            with db.get_connection() as conn:
                active_down_cnt = conn.execute(
                    "SELECT COUNT(*) FROM events WHERE device_id = ? AND type = 'DEFAULT_ROUTE_DOWN' AND status IN ('ACTIVE', 'OPEN')",
                    (device_id,)
                ).fetchone()[0]
        except Exception:
            pass

        # Default Route Recovered Rule
        if current_active is True and (prev_active is False or active_down_cnt > 0):
            fp = generate_fingerprint(device_id, "DEFAULT_ROUTE_RECOVERED", "0.0.0.0/0")
            events.append(EventRecord(
                event_id=str(uuid.uuid4()),
                device_id=device_id,
                type="DEFAULT_ROUTE_RECOVERED",
                severity="INFO",
                source="deterministic_engine",
                entity="0.0.0.0/0",
                evidence={"destination": "0.0.0.0/0", "prev_active": prev_active, "current_active": True},
                fingerprint=fp
            ))

        return events

    @staticmethod
    def check_nat_rules(device_id: str, nat_rules: List[Dict[str, Any]], running_interfaces: List[str]) -> List[EventRecord]:
        """
        Task 10: NAT Rule Correlation.
        Inspects active NAT rules and out-interface / out-interface-list dependencies.
        Never infers ether10 = WAN arbitrarily. If dependency cannot be established, returns empty or INSUFFICIENT_EVIDENCE.
        """
        events: List[EventRecord] = []
        for r in nat_rules:
            if not r.get("enabled", True):
                continue
            out_if = r.get("interface_dependency") or r.get("out_interface")
            if out_if and out_if not in running_interfaces:
                fp = generate_fingerprint(device_id, "NAT_DEPENDENCY_DOWN", out_if)
                events.append(EventRecord(
                    event_id=str(uuid.uuid4()),
                    device_id=device_id,
                    type="NAT_DEPENDENCY_DOWN",
                    severity="MAJOR",
                    source="deterministic_engine",
                    entity=out_if,
                    evidence={
                        "rule_id": r.get("rule_id"),
                        "out_interface": out_if,
                        "interface_running": False,
                        "packets": r.get("packets", 0)
                    },
                    fingerprint=fp
                ))
        return events
