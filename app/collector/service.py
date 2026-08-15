import re
import time
import asyncio
import logging
from typing import List, Dict, Any, Optional

from app.config import settings
from app.db.database import db
from app.db.schemas import (
    DeviceRecord,
    DeviceMetricRecord,
    InterfaceMetricRecord,
    BgpMetricRecord,
    OspfMetricRecord,
    NatMetricRecord,
    RouteMetricRecord,
    EventRecord,
)
from app.tools.routeros import (
    get_routeros_client,
    parse_system_resource,
    parse_interfaces_data,
    parse_bgp_peers_data,
    parse_ospf_neighbors_data,
    parse_nat_rules_data,
    parse_static_routes_data,
    RouterOSError,
)
from app.engine.anomaly import AnomalyDetector
from app.engine.correlation import CorrelationEngine

logger = logging.getLogger("mikrotik_noc_agent.collector")


def parse_uptime_to_seconds(uptime_str: str) -> int:
    """Parses RouterOS uptime string like '37w3d8h35m1s' into total seconds."""
    if not uptime_str or uptime_str == "unknown":
        return 0
    total_sec = 0
    weeks = re.search(r'(\d+)w', uptime_str)
    days = re.search(r'(\d+)d', uptime_str)
    hours = re.search(r'(\d+)h', uptime_str)
    minutes = re.search(r'(\d+)m', uptime_str)
    seconds = re.search(r'(\d+)s', uptime_str)
    
    if weeks: total_sec += int(weeks.group(1)) * 604800
    if days: total_sec += int(days.group(1)) * 86400
    if hours: total_sec += int(hours.group(1)) * 3600
    if minutes: total_sec += int(minutes.group(1)) * 60
    if seconds: total_sec += int(seconds.group(1))
    return total_sec


def collect_device_telemetry(host: str) -> Dict[str, Any]:
    """
    Polls MikroTik router via RouterOS API, persists historical metrics into SQLite,
    and runs deterministic anomaly detection and event correlation.
    Each metric domain fails independently so one domain error will not discard other metrics.
    """
    device_id = host
    logger.info(f"Collecting AIOps telemetry for device {device_id}...")

    stats = {
        "device_id": device_id,
        "device_metrics": 0,
        "interface_metrics": 0,
        "bgp_metrics": 0,
        "ospf_metrics": 0,
        "nat_metrics": 0,
        "route_metrics": 0,
        "errors": {}
    }
    events: List[EventRecord] = []

    try:
        with get_routeros_client(host=host) as api:
            
            # --- DOMAIN 1: System Health & Device Metrics ---
            try:
                sys_info = parse_system_resource(api)
                db.upsert_device(DeviceRecord(
                    device_id=device_id,
                    name=sys_info.identity or f"Router-{device_id}",
                    ip_address=host,
                    version=sys_info.routeros_version,
                    status="ONLINE"
                ))

                cpu_val = float(sys_info.cpu_load_percent or 0.0)
                mem_pct = float(sys_info.memory_usage_percent or 0.0)
                uptime_sec = parse_uptime_to_seconds(sys_info.uptime)

                db.insert_device_metric(DeviceMetricRecord(
                    device_id=device_id,
                    cpu_percent=cpu_val,
                    memory_percent=mem_pct,
                    uptime_seconds=uptime_sec
                ))
                stats["device_metrics"] += 1

                cpu_hist = [r["cpu_percent"] for r in db.get_recent_device_metrics(device_id, limit=50)]
                mem_hist = [r["memory_percent"] for r in db.get_recent_device_metrics(device_id, limit=50)]
                events.extend(AnomalyDetector.check_device_cpu_memory(device_id, cpu_val, mem_pct, cpu_hist, mem_hist))
            except Exception as e:
                logger.error(f"System metrics collection error for {device_id}: {e}")
                stats["errors"]["system"] = str(e)

            # --- DOMAIN 2: Interface Metrics ---
            try:
                ifaces_data = parse_interfaces_data(api, details=True)
                if ifaces_data.details:
                    for iface in ifaces_data.details:
                        db.insert_interface_metric(InterfaceMetricRecord(
                            device_id=device_id,
                            interface_name=iface.name,
                            running=iface.running,
                            disabled=iface.disabled,
                            rx_bps=float(iface.rx_bytes),
                            tx_bps=float(iface.tx_bytes),
                            rx_packets=iface.rx_packets,
                            tx_packets=iface.tx_packets,
                            rx_errors=iface.rx_errors,
                            tx_errors=iface.tx_errors,
                            rx_drops=0,
                            tx_drops=0
                        ))
                        stats["interface_metrics"] += 1

                        iface_hist = db.get_recent_interface_metrics(device_id, iface.name, limit=50)
                        prev_running = bool(iface_hist[1]["running"]) if len(iface_hist) > 1 else None
                        rx_bps_hist = [r["rx_bps"] for r in iface_hist]

                        events.extend(AnomalyDetector.check_interface_status(
                            device_id=device_id,
                            interface_name=iface.name,
                            current_running=iface.running,
                            current_disabled=iface.disabled,
                            prev_running=prev_running,
                            rx_bps_history=rx_bps_hist
                        ))
            except Exception as e:
                logger.error(f"Interface metrics collection error for {device_id}: {e}")
                stats["errors"]["interfaces"] = str(e)

            # --- DOMAIN 3: BGP Peer Metrics ---
            try:
                bgp_data = parse_bgp_peers_data(api, details=True)
                if bgp_data.details:
                    for peer in bgp_data.details:
                        db.insert_bgp_metric(BgpMetricRecord(
                            device_id=device_id,
                            peer=peer.remote_address or peer.name,
                            remote_address=peer.remote_address or "unknown",
                            established=peer.established,
                            uptime=peer.uptime,
                            prefix_count=peer.prefix_count
                        ))
                        stats["bgp_metrics"] += 1

                        bgp_hist = db.get_recent_bgp_metrics(device_id, peer.remote_address or peer.name, limit=10)
                        prev_est = bool(bgp_hist[1]["established"]) if len(bgp_hist) > 1 else None
                        prev_pfx = int(bgp_hist[1]["prefix_count"]) if len(bgp_hist) > 1 else None

                        events.extend(AnomalyDetector.check_bgp_status(
                            device_id=device_id,
                            peer=peer.remote_address or peer.name,
                            current_est=peer.established,
                            prev_est=prev_est,
                            current_prefix=peer.prefix_count,
                            prev_prefix=prev_pfx
                        ))
            except Exception as e:
                logger.error(f"BGP metrics collection error for {device_id}: {e}")
                stats["errors"]["bgp"] = str(e)

            # --- DOMAIN 4: OSPF Neighbor Metrics ---
            try:
                ospf_data = parse_ospf_neighbors_data(api, details=True)
                if ospf_data.neighbors:
                    for nbr in ospf_data.neighbors:
                        db.insert_ospf_metric(OspfMetricRecord(
                            device_id=device_id,
                            neighbor=nbr.neighbor,
                            router_id=nbr.router_id,
                            state=nbr.state
                        ))
                        stats["ospf_metrics"] += 1

                        ospf_hist = db.get_recent_ospf_metrics(device_id, nbr.neighbor, limit=10)
                        prev_st = str(ospf_hist[1]["state"]) if len(ospf_hist) > 1 else None

                        events.extend(AnomalyDetector.check_ospf_status(
                            device_id=device_id,
                            neighbor=nbr.neighbor,
                            current_state=nbr.state,
                            prev_state=prev_st
                        ))
            except Exception as e:
                logger.error(f"OSPF metrics collection error for {device_id}: {e}")
                stats["errors"]["ospf"] = str(e)

            # --- DOMAIN 5: NAT Metrics ---
            try:
                nat_resp = parse_nat_rules_data(api, details=True)
                if nat_resp and nat_resp.rules:
                    for r in nat_resp.rules:
                        db.insert_nat_metric(NatMetricRecord(
                            device_id=device_id,
                            rule_id=r.rule_id,
                            enabled=not r.disabled,
                            packets=r.packets,
                            bytes=r.bytes,
                            interface_dependency=r.out_interface
                        ))
                        stats["nat_metrics"] += 1
            except Exception as e:
                logger.error(f"NAT metrics collection error for {device_id}: {e}")
                stats["errors"]["nat"] = str(e)

            # --- DOMAIN 6: Static Route Metrics ---
            try:
                routes_data = parse_static_routes_data(api, details=True)
                if routes_data.routes:
                    for r in routes_data.routes:
                        db.insert_route_metric(RouteMetricRecord(
                            device_id=device_id,
                            destination=r.destination,
                            gateway=r.gateway,
                            active=r.active,
                            distance=r.distance
                        ))
                        stats["route_metrics"] += 1

                    def_route = next((r for r in routes_data.routes if r.destination == "0.0.0.0/0"), None)
                    if def_route:
                        with db.get_connection() as conn:
                            rows = conn.execute("SELECT * FROM route_metrics WHERE device_id = ? AND destination = '0.0.0.0/0' ORDER BY id DESC LIMIT 2", (device_id,)).fetchall()
                            prev_act = bool(rows[1]["active"]) if len(rows) > 1 else None
                            events.extend(AnomalyDetector.check_default_route_status(device_id, def_route.active, prev_act))
            except Exception as e:
                logger.error(f"Static routes collection error for {device_id}: {e}")
                stats["errors"]["routes"] = str(e)

            # --- Process Anomalies & Events via Deterministic Correlation Engine ---
            if events:
                CorrelationEngine.process_events(events)

    except RouterOSError as e:
        logger.warning(f"Telemetry connection failed for {device_id}: {e}")
        db.upsert_device(DeviceRecord(device_id=device_id, ip_address=host, status="OFFLINE"))
        stats["errors"]["connection"] = str(e)
    except Exception as e:
        logger.error(f"Unexpected error during telemetry collection for {device_id}: {e}")
        stats["errors"]["unexpected"] = str(e)

    return stats


def run_manual_collection() -> Dict[str, Any]:
    """Executes ONE synchronous collection cycle across all configured routers and returns stats."""
    t_start = time.perf_counter()
    hosts_to_collect = []
    if settings.MIKROTIK_ROUTER1_HOST:
        hosts_to_collect.append(settings.MIKROTIK_ROUTER1_HOST)
    if settings.MIKROTIK_ROUTER2_HOST and settings.MIKROTIK_ROUTER2_HOST != settings.MIKROTIK_ROUTER1_HOST:
        hosts_to_collect.append(settings.MIKROTIK_ROUTER2_HOST)
    if not hosts_to_collect:
        hosts_to_collect.append(settings.MIKROTIK_HOST)

    summary_stats = {
        "status": "completed",
        "devices": len(hosts_to_collect),
        "device_metrics": 0,
        "interface_metrics": 0,
        "bgp_metrics": 0,
        "ospf_metrics": 0,
        "nat_metrics": 0,
        "route_metrics": 0,
        "duration_ms": 0,
        "device_details": []
    }

    for host in hosts_to_collect:
        res = collect_device_telemetry(host)
        summary_stats["device_metrics"] += res.get("device_metrics", 0)
        summary_stats["interface_metrics"] += res.get("interface_metrics", 0)
        summary_stats["bgp_metrics"] += res.get("bgp_metrics", 0)
        summary_stats["ospf_metrics"] += res.get("ospf_metrics", 0)
        summary_stats["nat_metrics"] += res.get("nat_metrics", 0)
        summary_stats["route_metrics"] += res.get("route_metrics", 0)
        summary_stats["device_details"].append(res)

    t_end = time.perf_counter()
    summary_stats["duration_ms"] = max(1, int((t_end - t_start) * 1000))
    return summary_stats


async def collector_loop() -> None:
    """Async background task executing telemetry collection every COLLECTOR_INTERVAL_SECONDS."""
    logger.info(f"Starting AIOps Background Telemetry Collector (interval={settings.COLLECTOR_INTERVAL_SECONDS}s)...")
    
    hosts_to_collect = []
    if settings.MIKROTIK_ROUTER1_HOST:
        hosts_to_collect.append(settings.MIKROTIK_ROUTER1_HOST)
    if settings.MIKROTIK_ROUTER2_HOST and settings.MIKROTIK_ROUTER2_HOST != settings.MIKROTIK_ROUTER1_HOST:
        hosts_to_collect.append(settings.MIKROTIK_ROUTER2_HOST)
    if not hosts_to_collect:
        hosts_to_collect.append(settings.MIKROTIK_HOST)

    while True:
        try:
            for target_host in hosts_to_collect:
                # Execute blocking RouterOS polling in thread pool to avoid blocking asyncio event loop
                await asyncio.to_thread(collect_device_telemetry, target_host)
        except Exception as e:
            logger.error(f"Error in background collector loop: {e}")
        
        await asyncio.sleep(settings.COLLECTOR_INTERVAL_SECONDS)
