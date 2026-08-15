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


def collect_device_telemetry(host: str) -> None:
    """
    Polls MikroTik router via RouterOS API, persists historical metrics into SQLite,
    and runs deterministic anomaly detection and event correlation.
    """
    device_id = host
    logger.info(f"Collecting AIOps telemetry for device {device_id}...")

    try:
        with get_routeros_client(host=host) as api:
            # 1. System Health
            sys_info = parse_system_resource(api)
            db.upsert_device(DeviceRecord(
                device_id=device_id,
                name=sys_info.identity or f"Router-{device_id}",
                ip_address=host,
                version=sys_info.version,
                status="ONLINE"
            ))

            cpu_val = float(sys_info.cpu_load or 0.0)
            mem_pct = float(sys_info.memory_used_percent or 0.0)
            uptime_sec = int(sys_info.uptime_seconds or 0)

            db.insert_device_metric(DeviceMetricRecord(
                device_id=device_id,
                cpu_percent=cpu_val,
                memory_percent=mem_pct,
                uptime_seconds=uptime_sec
            ))

            # Fetch recent CPU/Memory history for baseline checks
            cpu_hist = [r["cpu_percent"] for r in db.get_recent_device_metrics(device_id, limit=50)]
            mem_hist = [r["memory_percent"] for r in db.get_recent_device_metrics(device_id, limit=50)]

            events: List[EventRecord] = []
            events.extend(AnomalyDetector.check_device_cpu_memory(device_id, cpu_val, mem_pct, cpu_hist, mem_hist))

            # 2. Interfaces
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
                        rx_drops=iface.rx_drops,
                        tx_drops=iface.tx_drops
                    ))

                    # Check previous state & traffic drop
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

            # 3. BGP Peers
            bgp_data = parse_bgp_peers_data(api, details=True)
            if bgp_data.details:
                for peer in bgp_data.details:
                    db.insert_bgp_metric(BgpMetricRecord(
                        device_id=device_id,
                        peer=peer.name,
                        remote_address=peer.remote_address,
                        established=peer.established,
                        uptime=peer.uptime,
                        prefix_count=peer.prefix_count
                    ))

                    bgp_hist = db.get_recent_bgp_metrics(device_id, peer.name, limit=10)
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

            # 4. OSPF Neighbors
            ospf_data = parse_ospf_neighbors_data(api, details=True)
            if ospf_data.neighbors:
                for nbr in ospf_data.neighbors:
                    db.insert_ospf_metric(OspfMetricRecord(
                        device_id=device_id,
                        neighbor=nbr.neighbor,
                        router_id=nbr.router_id,
                        state=nbr.state
                    ))

                    ospf_hist = db.get_recent_ospf_metrics(device_id, nbr.neighbor, limit=10)
                    prev_st = str(ospf_hist[1]["state"]) if len(ospf_hist) > 1 else None

                    events.extend(AnomalyDetector.check_ospf_status(
                        device_id=device_id,
                        neighbor=nbr.neighbor,
                        current_state=nbr.state,
                        prev_state=prev_st
                    ))

            # 5. Static Routes (Default Route Check)
            routes_data = parse_static_routes_data(api, details=True)
            if routes_data.routes:
                def_route = next((r for r in routes_data.routes if r.destination == "0.0.0.0/0"), None)
                if def_route:
                    db.insert_route_metric(RouteMetricRecord(
                        device_id=device_id,
                        destination="0.0.0.0/0",
                        gateway=def_route.gateway,
                        active=def_route.active,
                        distance=def_route.distance
                    ))
                    # Check route history
                    with db.get_connection() as conn:
                        rows = conn.execute("SELECT * FROM route_metrics WHERE device_id = ? AND destination = '0.0.0.0/0' ORDER BY id DESC LIMIT 2", (device_id,)).fetchall()
                        prev_act = bool(rows[1]["active"]) if len(rows) > 1 else None
                        events.extend(AnomalyDetector.check_default_route_status(device_id, def_route.active, prev_act))

            # 6. Process all detected events via Correlation Engine
            if events:
                CorrelationEngine.process_events(events)

    except RouterOSError as e:
        logger.warning(f"Telemetry collection failed for {device_id}: {e}")
        db.upsert_device(DeviceRecord(device_id=device_id, ip_address=host, status="OFFLINE"))
    except Exception as e:
        logger.error(f"Unexpected error during telemetry collection for {device_id}: {e}")


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
