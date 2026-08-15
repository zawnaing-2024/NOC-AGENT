import logging
import socket
from contextlib import contextmanager
from typing import Any, Generator, Dict, List, Optional
import librouteros
from librouteros.exceptions import LibRouterosError, ProtocolError, TrapError
from langchain_core.tools import tool

from app.config import settings
from app.schemas.network import (
    SystemHealth,
    InterfaceInfo,
    InterfaceSummary,
    InterfacesResponse,
    InterfaceDetail,
    LogEvent,
    InterfaceLogsResponse,
    InterfaceTrafficResponse,
    BgpPeerInfo,
    BgpSummary,
    BgpPeersResponse,
)

logger = logging.getLogger("mikrotik_noc_agent.routeros")


class RouterOSError(Exception):
    """Base exception for RouterOS operations."""
    pass


class RouterOSConnectionError(RouterOSError):
    """Raised when unable to connect to MikroTik device."""
    pass


class RouterOSAuthError(RouterOSError):
    """Raised when authentication fails."""
    pass


class RouterOSTimeoutError(RouterOSError):
    """Raised when connection/operation times out."""
    pass


class RouterOSApiError(RouterOSError):
    """Raised when RouterOS API returns an error or unexpected response."""
    pass


@contextmanager
def get_routeros_client(
    host: str | None = None,
    port: int | None = None,
    username: str | None = None,
    password: str | None = None,
    timeout: int = 10,
) -> Generator[Any, None, None]:
    """
    Context manager establishing a safe, short-lived RouterOS API connection.
    Guarantees clean connection teardown and structured exception handling.
    Never logs credentials.
    """
    target_host = host or settings.MIKROTIK_HOST
    target_port = port or settings.MIKROTIK_PORT
    target_username = username or settings.MIKROTIK_USERNAME
    target_password = password or settings.MIKROTIK_PASSWORD

    logger.info(f"Connecting to MikroTik RouterOS at {target_host}:{target_port}")
    api = None
    try:
        api = librouteros.connect(
            host=target_host,
            port=target_port,
            username=target_username,
            password=target_password,
            timeout=timeout,
        )
        yield api
    except (socket.timeout, TimeoutError) as e:
        logger.error(f"Timeout connecting to MikroTik at {target_host}:{target_port}")
        raise RouterOSTimeoutError(f"Connection timeout to MikroTik device at {target_host}:{target_port}") from e
    except (ConnectionRefusedError, socket.error, OSError) as e:
        logger.error(f"Failed to connect to MikroTik at {target_host}:{target_port}: {e}")
        raise RouterOSConnectionError(f"Unable to reach MikroTik device at {target_host}:{target_port}") from e
    except ProtocolError as e:
        logger.error(f"Authentication error or protocol error for MikroTik user on {target_host}:{target_port}")
        raise RouterOSAuthError("Authentication failed for MikroTik router.") from e
    except TrapError as e:
        logger.error(f"RouterOS API Trap error on connect: {e}")
        raise RouterOSApiError(f"RouterOS API Trap Error: {str(e)}") from e
    except LibRouterosError as e:
        logger.error(f"LibRouteros error on connect: {e}")
        raise RouterOSApiError(f"RouterOS API Error: {str(e)}") from e
    except Exception as e:
        logger.error(f"Unexpected connection error connecting to MikroTik: {e}")
        raise RouterOSConnectionError(f"Unexpected connection failure: {str(e)}") from e
    finally:
        if api:
            try:
                api.close()
                logger.info(f"Closed RouterOS connection to {target_host}:{target_port}")
            except Exception as close_err:
                logger.warning(f"Error closing RouterOS connection: {close_err}")


def parse_int_safe(val: Any, default: int = 0) -> int:
    try:
        if val is None:
            return default
        return int(val)
    except (ValueError, TypeError):
        return default


def parse_int_optional(val: Any) -> Optional[int]:
    try:
        if val is None:
            return None
        return int(val)
    except (ValueError, TypeError):
        return None


def parse_bool_safe(val: Any, default: bool = False) -> bool:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ("true", "yes", "1")
    return bool(val) if val is not None else default


def parse_system_resource(api_client: Any) -> SystemHealth:
    """Queries /system/resource and /system/identity to build structured SystemHealth."""
    try:
        resource_tuple = api_client.path("/system/resource")
        resource_list = list(resource_tuple)
        resource_data: Dict[str, Any] = resource_list[0] if resource_list else {}
    except Exception as e:
        logger.error(f"Error querying /system/resource: {e}")
        raise RouterOSApiError(f"Failed to fetch system resource: {e}") from e

    identity_str = "MikroTik"
    try:
        identity_tuple = api_client.path("/system/identity")
        identity_list = list(identity_tuple)
        if identity_list and "name" in identity_list[0]:
            identity_str = str(identity_list[0]["name"])
    except Exception as e:
        logger.warning(f"Unable to fetch /system/identity, fallback to 'MikroTik': {e}")

    board_name = str(resource_data.get("board-name", resource_data.get("platform", "RouterOS")))
    version = str(resource_data.get("version", "unknown"))
    uptime = str(resource_data.get("uptime", "unknown"))
    cpu_load = parse_int_safe(resource_data.get("cpu-load"), 0)
    total_memory = parse_int_safe(resource_data.get("total-memory"), 0)
    free_memory = parse_int_safe(resource_data.get("free-memory"), 0)

    if total_memory > 0:
        used_memory = total_memory - free_memory
        memory_usage_percent = round((used_memory / total_memory) * 100.0, 2)
    else:
        memory_usage_percent = 0.0

    if cpu_load > 90 or memory_usage_percent > 90:
        status = "CRITICAL"
    elif cpu_load > 75 or memory_usage_percent > 80:
        status = "WARNING"
    else:
        status = "HEALTHY"

    return SystemHealth(
        device=identity_str,
        identity=identity_str,
        board_name=board_name,
        routeros_version=version,
        uptime=uptime,
        cpu_load_percent=cpu_load,
        total_memory=total_memory,
        free_memory=free_memory,
        memory_usage_percent=memory_usage_percent,
        status=status,
    )


def parse_interfaces_data(
    api_client: Any,
    details: bool = False,
    interface_name: Optional[str] = None
) -> InterfacesResponse:
    """
    Queries /interface and executes traffic-history deterministic status classification:
    - DISABLED: disabled=true (Admin disabled; no fault inferred)
    - UNCONNECTED: disabled=false, running=false, rx_bytes==0 & tx_bytes==0 (Unplugged port, 0 traffic; NOT an incident)
    - LINK_DOWN: disabled=false, running=false, rx_bytes>0 or tx_bytes>0 (Previously active link dropped; fault requiring investigation)
    - ERROR: running=true with rx_errors > 0 or tx_errors > 0 (Active link experiencing errors)
    - ACTIVE: running=true with normal counters (Healthy active link)

    Supports targeted filtering via interface_name parameter for token-efficient Stage 2 investigation.
    """
    try:
        iface_tuple = api_client.path("/interface")
        iface_list = list(iface_tuple)
    except Exception as e:
        logger.error(f"Error querying /interface: {e}")
        raise RouterOSApiError(f"Failed to fetch interfaces: {e}") from e

    detailed_interfaces: List[InterfaceInfo] = []
    active_cnt = 0
    disabled_cnt = 0
    unconnected_cnt = 0
    link_down_cnt = 0
    error_cnt = 0
    link_down_ifaces: List[str] = []
    error_ifaces: List[str] = []

    for item in iface_list:
        name = str(item.get("name", "unknown"))
        iface_type = str(item.get("type", "ether"))
        running = parse_bool_safe(item.get("running"), False)
        disabled = parse_bool_safe(item.get("disabled"), False)

        rx_bytes = parse_int_safe(item.get("rx-byte", item.get("rx-bytes", 0)))
        tx_bytes = parse_int_safe(item.get("tx-byte", item.get("tx-bytes", 0)))
        rx_packets = parse_int_safe(item.get("rx-packet", item.get("rx-packets", 0)))
        tx_packets = parse_int_safe(item.get("tx-packet", item.get("tx-packets", 0)))
        rx_errors = parse_int_safe(item.get("rx-error", item.get("rx-errors", 0)))
        tx_errors = parse_int_safe(item.get("tx-error", item.get("tx-errors", 0)))

        # Deterministic Classification Rule Engine
        if disabled:
            status_tag = "DISABLED"
            disabled_cnt += 1
        elif not running:
            if rx_bytes == 0 and tx_bytes == 0:
                status_tag = "UNCONNECTED"  # Unplugged copper port with zero traffic; NOT a fault
                unconnected_cnt += 1
            else:
                status_tag = "LINK_DOWN"  # Previously active port that dropped link; FAULT
                link_down_cnt += 1
                link_down_ifaces.append(name)
        elif rx_errors > 0 or tx_errors > 0:
            status_tag = "ERROR"
            error_cnt += 1
            error_ifaces.append(name)
            active_cnt += 1
        else:
            status_tag = "ACTIVE"
            active_cnt += 1

        # Include in detailed output if details=True and (no filter or name matches)
        if details:
            if interface_name is None or name.lower() == interface_name.lower():
                detailed_interfaces.append(
                    InterfaceInfo(
                        name=name,
                        type=iface_type,
                        running=running,
                        disabled=disabled,
                        status_tag=status_tag,
                        rx_bytes=rx_bytes,
                        tx_bytes=tx_bytes,
                        rx_packets=rx_packets,
                        tx_packets=tx_packets,
                        rx_errors=rx_errors,
                        tx_errors=tx_errors,
                    )
                )

    summary = InterfaceSummary(
        total=len(iface_list),
        active=active_cnt,
        disabled=disabled_cnt,
        unconnected=unconnected_cnt,
        link_down=link_down_cnt,
        errors=error_cnt,
        link_down_interfaces=link_down_ifaces,
        error_interfaces=error_ifaces,
    )

    return InterfacesResponse(
        summary=summary,
        details=detailed_interfaces if details else None
    )


# --- MVP-2 Targeted Interface Data Parsers ---

def parse_single_interface_detail(api_client: Any, interface_name: str) -> InterfaceDetail:
    """Queries /interface for a specific target interface and returns normalized InterfaceDetail."""
    try:
        iface_tuple = api_client.path("/interface")
        iface_list = list(iface_tuple)
    except Exception as e:
        logger.error(f"Error querying /interface for single interface {interface_name}: {e}")
        raise RouterOSApiError(f"Failed to fetch interface detail for {interface_name}: {e}") from e

    match_item = None
    for item in iface_list:
        if str(item.get("name", "")).lower() == interface_name.lower():
            match_item = item
            break

    if not match_item:
        logger.warning(f"Interface {interface_name} not found in RouterOS list, returning default detail structure.")
        return InterfaceDetail(name=interface_name)

    name = str(match_item.get("name", interface_name))
    iface_type = str(match_item.get("type", "ether"))
    running = parse_bool_safe(match_item.get("running"), False)
    disabled = parse_bool_safe(match_item.get("disabled"), False)
    mtu = parse_int_optional(match_item.get("mtu"))
    actual_mtu = parse_int_optional(match_item.get("actual-mtu", match_item.get("mtu")))
    mac_address = match_item.get("mac-address")
    if mac_address is not None:
        mac_address = str(mac_address)

    rx_bytes = parse_int_safe(match_item.get("rx-byte", match_item.get("rx-bytes", 0)))
    tx_bytes = parse_int_safe(match_item.get("tx-byte", match_item.get("tx-bytes", 0)))
    rx_packets = parse_int_safe(match_item.get("rx-packet", match_item.get("rx-packets", 0)))
    tx_packets = parse_int_safe(match_item.get("tx-packet", match_item.get("tx-packets", 0)))
    rx_errors = parse_int_safe(match_item.get("rx-error", match_item.get("rx-errors", 0)))
    tx_errors = parse_int_safe(match_item.get("tx-error", match_item.get("tx-errors", 0)))
    rx_drops = parse_int_safe(match_item.get("rx-drop", match_item.get("rx-drops", 0)))
    tx_drops = parse_int_safe(match_item.get("tx-drop", match_item.get("tx-drops", 0)))
    link_downs = parse_int_optional(match_item.get("link-downs", match_item.get("link-down-count")))

    return InterfaceDetail(
        name=name,
        type=iface_type,
        running=running,
        disabled=disabled,
        mtu=mtu,
        actual_mtu=actual_mtu,
        mac_address=mac_address,
        rx_bytes=rx_bytes,
        tx_bytes=tx_bytes,
        rx_packets=rx_packets,
        tx_packets=tx_packets,
        rx_errors=rx_errors,
        tx_errors=tx_errors,
        rx_drops=rx_drops,
        tx_drops=tx_drops,
        link_downs=link_downs,
    )


def parse_interface_logs(api_client: Any, interface_name: str) -> InterfaceLogsResponse:
    """Queries /log and filters timestamped events matching interface_name."""
    events: List[LogEvent] = []
    try:
        log_tuple = api_client.path("/log")
        log_list = list(log_tuple)
        
        target_str = interface_name.lower()
        for item in log_list:
            msg = str(item.get("message", ""))
            topics = str(item.get("topics", ""))
            time_str = str(item.get("time", item.get("timestamp", "")))

            if target_str in msg.lower() or target_str in topics.lower():
                events.append(LogEvent(timestamp=time_str, message=msg))

    except Exception as e:
        logger.warning(f"Unable to fetch /log or search for {interface_name}: {e}")

    return InterfaceLogsResponse(interface=interface_name, events=events)


def parse_interface_traffic(api_client: Any, interface_name: str) -> InterfaceTrafficResponse:
    """Queries current real-time traffic and error counters for interface_name."""
    try:
        iface_tuple = api_client.path("/interface")
        iface_list = list(iface_tuple)
    except Exception as e:
        logger.error(f"Error querying /interface traffic for {interface_name}: {e}")
        raise RouterOSApiError(f"Failed to fetch traffic for {interface_name}: {e}") from e

    match_item = None
    for item in iface_list:
        if str(item.get("name", "")).lower() == interface_name.lower():
            match_item = item
            break

    if not match_item:
        return InterfaceTrafficResponse(interface=interface_name)

    rx_bytes = parse_int_safe(match_item.get("rx-byte", match_item.get("rx-bytes", 0)))
    tx_bytes = parse_int_safe(match_item.get("tx-byte", match_item.get("tx-bytes", 0)))
    rx_packets = parse_int_safe(match_item.get("rx-packet", match_item.get("rx-packets", 0)))
    tx_packets = parse_int_safe(match_item.get("tx-packet", match_item.get("tx-packets", 0)))
    rx_errors = parse_int_safe(match_item.get("rx-error", match_item.get("rx-errors", 0)))
    tx_errors = parse_int_safe(match_item.get("tx-error", match_item.get("tx-errors", 0)))
    rx_drops = parse_int_safe(match_item.get("rx-drop", match_item.get("rx-drops", 0)))
    tx_drops = parse_int_safe(match_item.get("tx-drop", match_item.get("tx-drops", 0)))

    return InterfaceTrafficResponse(
        interface=interface_name,
        rx_bytes=rx_bytes,
        tx_bytes=tx_bytes,
        rx_packets=rx_packets,
        tx_packets=tx_packets,
        rx_errors=rx_errors,
        tx_errors=tx_errors,
        rx_drops=rx_drops,
        tx_drops=tx_drops,
    )


def parse_bgp_peers_data(api_client: Any, details: bool = False) -> BgpPeersResponse:
    """
    Queries BGP sessions/peers compatible with RouterOS 7 and 6.
    Returns compact summary by default, full peer details if details=True.
    """
    peer_list: List[Dict[str, Any]] = []

    try:
        session_path = api_client.path("/routing/bgp/session")
        peer_list = list(session_path)
    except Exception:
        try:
            peer_path = api_client.path("/routing/bgp/peer")
            peer_list = list(peer_path)
        except Exception as e:
            logger.warning(f"BGP paths unavailable or BGP not configured on device: {e}")
            summary = BgpSummary(total=0, established=0, down=0, down_peers=[])
            return BgpPeersResponse(summary=summary, details=[] if details else None)

    detailed_peers: List[BgpPeerInfo] = []
    established_cnt = 0
    down_cnt = 0
    down_peers_list: List[str] = []

    for item in peer_list:
        name = str(item.get("name", item.get("remote.as", "bgp-peer")))
        remote_address = str(
            item.get("remote.address", item.get("remote-address", item.get("address", "unknown")))
        )
        local_address = str(item.get("local.address", item.get("local-address", "")))
        state = str(item.get("state", item.get("session-state", "unknown"))).lower()
        uptime = str(item.get("uptime", item.get("established-time", "")))
        
        established = (state == "established") or parse_bool_safe(item.get("established"), False)

        if established:
            established_cnt += 1
        else:
            down_cnt += 1
            down_peers_list.append(name)

        if details:
            prefix_count = parse_int_safe(
                item.get("prefix-count", item.get("remote.prefix-count", item.get("prefix-count-rx", 0)))
            )
            remote_as = str(item.get("remote.as", item.get("remote-as", "")))
            local_as = str(item.get("local.as", item.get("local-as", "")))

            detailed_peers.append(
                BgpPeerInfo(
                    name=name,
                    remote_address=remote_address,
                    local_address=local_address,
                    state=state,
                    uptime=uptime,
                    established=established,
                    prefix_count=prefix_count,
                    remote_as=remote_as,
                    local_as=local_as,
                )
            )

    summary = BgpSummary(
        total=len(peer_list),
        established=established_cnt,
        down=down_cnt,
        down_peers=down_peers_list,
    )

    return BgpPeersResponse(
        summary=summary,
        details=detailed_peers if details else None
    )


# --- LangChain Read-Only Tool Definitions ---

@tool
def get_system_health() -> str:
    """
    Inspects MikroTik router system health including identity, version, CPU load, uptime, and memory usage.
    Returns compact structured JSON. Use this tool ONLY when system health or CPU/RAM metrics are requested.
    """
    logger.info("Executing tool: get_system_health")
    with get_routeros_client() as api:
        health_data = parse_system_resource(api)
        return health_data.model_dump_json()


@tool
def get_interfaces(details: bool = False, interface_name: Optional[str] = None) -> str:
    """
    Inspects interface counts and status tags (DISABLED, UNCONNECTED, LINK_DOWN, ERROR, ACTIVE).
    Use details=True and specify interface_name (e.g. interface_name='ether8') ONLY when investigating a specific LINK_DOWN or ERROR interface anomaly.
    """
    logger.info(f"Executing tool: get_interfaces (details={details}, interface_name={interface_name})")
    with get_routeros_client() as api:
        iface_data = parse_interfaces_data(api, details=details, interface_name=interface_name)
        return iface_data.model_dump_json(exclude_none=True)


@tool
def get_interface_detail(interface_name: str) -> str:
    """
    Retrieves detailed parameters (MTU, MAC address, link downs, error/drop counters) for ONE specific target interface.
    """
    logger.info(f"Executing tool: get_interface_detail (interface_name={interface_name})")
    with get_routeros_client() as api:
        detail_data = parse_single_interface_detail(api, interface_name=interface_name)
        return detail_data.model_dump_json()


@tool
def get_interface_logs(interface_name: str) -> str:
    """
    Retrieves timestamped RouterOS event logs related to ONE specific target interface.
    """
    logger.info(f"Executing tool: get_interface_logs (interface_name={interface_name})")
    with get_routeros_client() as api:
        log_data = parse_interface_logs(api, interface_name=interface_name)
        return log_data.model_dump_json()


@tool
def get_interface_traffic(interface_name: str) -> str:
    """
    Retrieves current real-time traffic and error counters for ONE specific target interface.
    """
    logger.info(f"Executing tool: get_interface_traffic (interface_name={interface_name})")
    with get_routeros_client() as api:
        traffic_data = parse_interface_traffic(api, interface_name=interface_name)
        return traffic_data.model_dump_json()


@tool
def get_bgp_peers(details: bool = False) -> str:
    """
    Inspects BGP session summary (total, established, down).
    Use this tool ONLY when BGP sessions or BGP peer health are explicitly requested.
    Set details=True ONLY if investigating specific non-established BGP session anomalies.
    """
    logger.info(f"Executing tool: get_bgp_peers (details={details})")
    with get_routeros_client() as api:
        bgp_data = parse_bgp_peers_data(api, details=details)
        return bgp_data.model_dump_json(exclude_none=True)
