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
    StaticRouteInfo,
    StaticRoutesResponse,
    OspfNeighborInfo,
    OspfNeighborsResponse,
    NatRuleInfo,
    NatRulesResponse,
    RoutingLogsResponse,
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
    router: str | None = None,
) -> Generator[Any, None, None]:
    """
    Context manager establishing a safe, short-lived RouterOS API connection.
    Supports multi-router targeting ('router1', 'router2', or specific host IP).
    Never logs credentials.
    """
    selected_router = (router or host or "").lower()

    if selected_router == "router2" or host == settings.MIKROTIK_ROUTER2_HOST:
        target_host = settings.MIKROTIK_ROUTER2_HOST or settings.MIKROTIK_HOST
        target_port = port or settings.MIKROTIK_ROUTER2_PORT
        target_username = username or settings.MIKROTIK_ROUTER2_USERNAME
        target_password = password or settings.MIKROTIK_ROUTER2_PASSWORD
    elif selected_router == "router1" or host == settings.MIKROTIK_ROUTER1_HOST:
        target_host = settings.MIKROTIK_ROUTER1_HOST or settings.MIKROTIK_HOST
        target_port = port or settings.MIKROTIK_ROUTER1_PORT
        target_username = username or settings.MIKROTIK_ROUTER1_USERNAME
        target_password = password or settings.MIKROTIK_ROUTER1_PASSWORD
    else:
        target_host = host or settings.MIKROTIK_ROUTER1_HOST or settings.MIKROTIK_HOST
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
    """Queries /interface and executes traffic-history deterministic status classification."""
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

        if disabled:
            status_tag = "DISABLED"
            disabled_cnt += 1
        elif not running:
            if rx_bytes == 0 and tx_bytes == 0:
                status_tag = "UNCONNECTED"
                unconnected_cnt += 1
            else:
                status_tag = "LINK_DOWN"
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


def parse_single_interface_detail(api_client: Any, interface_name: str) -> InterfaceDetail:
    """Queries /interface for a specific target interface."""
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
        return InterfaceDetail(name=interface_name)

    return InterfaceDetail(
        name=str(match_item.get("name", interface_name)),
        type=str(match_item.get("type", "ether")),
        running=parse_bool_safe(match_item.get("running"), False),
        disabled=parse_bool_safe(match_item.get("disabled"), False),
        mtu=parse_int_optional(match_item.get("mtu")),
        actual_mtu=parse_int_optional(match_item.get("actual-mtu", match_item.get("mtu"))),
        mac_address=str(match_item.get("mac-address")) if match_item.get("mac-address") else None,
        rx_bytes=parse_int_safe(match_item.get("rx-byte", match_item.get("rx-bytes", 0))),
        tx_bytes=parse_int_safe(match_item.get("tx-byte", match_item.get("tx-bytes", 0))),
        rx_packets=parse_int_safe(match_item.get("rx-packet", match_item.get("rx-packets", 0))),
        tx_packets=parse_int_safe(match_item.get("tx-packet", match_item.get("tx-packets", 0))),
        rx_errors=parse_int_safe(match_item.get("rx-error", match_item.get("rx-errors", 0))),
        tx_errors=parse_int_safe(match_item.get("tx-error", match_item.get("tx-errors", 0))),
        rx_drops=parse_int_safe(match_item.get("rx-drop", match_item.get("rx-drops", 0))),
        tx_drops=parse_int_safe(match_item.get("tx-drop", match_item.get("tx-drops", 0))),
        link_downs=parse_int_optional(match_item.get("link-downs", match_item.get("link-down-count"))),
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
    """Queries current traffic and error counters for interface_name."""
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

    return InterfaceTrafficResponse(
        interface=interface_name,
        rx_bytes=parse_int_safe(match_item.get("rx-byte", match_item.get("rx-bytes", 0))),
        tx_bytes=parse_int_safe(match_item.get("tx-byte", match_item.get("tx-bytes", 0))),
        rx_packets=parse_int_safe(match_item.get("rx-packet", match_item.get("rx-packets", 0))),
        tx_packets=parse_int_safe(match_item.get("tx-packet", match_item.get("tx-packets", 0))),
        rx_errors=parse_int_safe(match_item.get("rx-error", match_item.get("rx-errors", 0))),
        tx_errors=parse_int_safe(match_item.get("tx-error", match_item.get("tx-errors", 0))),
        rx_drops=parse_int_safe(match_item.get("rx-drop", match_item.get("rx-drops", 0))),
        tx_drops=parse_int_safe(match_item.get("tx-drop", match_item.get("tx-drops", 0))),
    )


# --- Phase 3 Domain Parsers ---

# 1. BGP Parsers
def parse_bgp_peers_data(api_client: Any, details: bool = False) -> BgpPeersResponse:
    """Queries BGP sessions/peers compatible with RouterOS 7 and 6."""
    peer_list: List[Dict[str, Any]] = []
    try:
        session_path = api_client.path("/routing/bgp/session")
        peer_list = list(session_path)
    except Exception:
        try:
            peer_path = api_client.path("/routing/bgp/peer")
            peer_list = list(peer_path)
        except Exception as e:
            logger.warning(f"BGP paths unavailable or BGP not configured: {e}")
            return BgpPeersResponse(summary=BgpSummary(), details=[] if details else None)

    detailed_peers: List[BgpPeerInfo] = []
    established_cnt = 0
    down_cnt = 0
    down_peers_list: List[str] = []

    for item in peer_list:
        name = str(item.get("name", item.get("remote.as", "bgp-peer")))
        remote_address = str(item.get("remote.address", item.get("remote-address", item.get("address", "unknown"))))
        local_address = str(item.get("local.address", item.get("local-address", "")))
        state = str(item.get("state", item.get("session-state", "unknown"))).upper()
        uptime = str(item.get("uptime", item.get("established-time", ""))) or None
        established = (state.lower() == "established") or parse_bool_safe(item.get("established"), False)

        if established:
            established_cnt += 1
        else:
            down_cnt += 1
            down_peers_list.append(name if name != "bgp-peer" else remote_address)

        if details:
            prefix_count = parse_int_safe(item.get("prefix-count", item.get("remote.prefix-count", item.get("prefix-count-rx", 0))))
            remote_as_val = item.get("remote.as", item.get("remote-as"))
            local_as_val = item.get("local.as", item.get("local-as"))

            detailed_peers.append(
                BgpPeerInfo(
                    name=name,
                    remote_address=remote_address,
                    local_address=local_address,
                    state=state,
                    uptime=uptime,
                    established=established,
                    prefix_count=prefix_count,
                    remote_as=str(remote_as_val) if remote_as_val is not None else None,
                    local_as=str(local_as_val) if local_as_val is not None else None,
                )
            )

    summary = BgpSummary(
        total=len(peer_list),
        established=established_cnt,
        down=down_cnt,
        down_peers=down_peers_list,
    )
    return BgpPeersResponse(summary=summary, details=detailed_peers if details else None)


def parse_bgp_peer_detail(api_client: Any, peer_target: str) -> BgpPeerInfo:
    """Queries single BGP peer detail by IP or session name."""
    res = parse_bgp_peers_data(api_client, details=True)
    if res.details:
        for p in res.details:
            if p.name.lower() == peer_target.lower() or p.remote_address.lower() == peer_target.lower():
                return p
    return BgpPeerInfo(name=peer_target, remote_address=peer_target)


# 2. Static Route Parsers
def parse_static_routes_data(api_client: Any, details: bool = False) -> StaticRoutesResponse:
    """Queries /ip/route for static or active routing table entries."""
    route_list: List[Dict[str, Any]] = []
    try:
        route_path = api_client.path("/ip/route")
        route_list = list(route_path)
    except Exception as e:
        logger.warning(f"Unable to query /ip/route: {e}")
        return StaticRoutesResponse()

    detailed_routes: List[StaticRouteInfo] = []
    active_cnt = 0
    inactive_cnt = 0
    disabled_cnt = 0
    inactive_prefixes: List[str] = []

    for item in route_list:
        dst = str(item.get("dst-address", item.get("dst", "0.0.0.0/0")))
        gw = str(item.get("gateway", "unknown"))
        iface = item.get("immediate-gw", item.get("gateway-status"))
        iface_str = str(iface) if iface else None
        
        active = parse_bool_safe(item.get("active"), True)
        disabled = parse_bool_safe(item.get("disabled"), False)
        distance = parse_int_safe(item.get("distance"), 1)

        if disabled:
            disabled_cnt += 1
        elif active:
            active_cnt += 1
        else:
            inactive_cnt += 1
            inactive_prefixes.append(dst)

        if details:
            detailed_routes.append(
                StaticRouteInfo(
                    destination=dst,
                    gateway=gw,
                    interface=iface_str,
                    distance=distance,
                    active=active,
                    disabled=disabled,
                )
            )

    return StaticRoutesResponse(
        total=len(route_list),
        active=active_cnt,
        inactive=inactive_cnt,
        disabled=disabled_cnt,
        inactive_routes=inactive_prefixes,
        routes=detailed_routes if details else None,
    )


def parse_single_route_detail(api_client: Any, destination: str) -> StaticRouteInfo:
    """Queries /ip/route matching destination prefix or gateway IP."""
    routes_res = parse_static_routes_data(api_client, details=True)
    if routes_res.routes:
        for r in routes_res.routes:
            if r.destination.lower() == destination.lower() or r.gateway.lower() == destination.lower():
                return r
    return StaticRouteInfo(destination=destination, gateway="unknown", active=False)


# 3. OSPF Parsers
def parse_ospf_neighbors_data(api_client: Any, details: bool = False) -> OspfNeighborsResponse:
    """Queries OSPF neighbor adjacencies compatible with RouterOS 7 and 6."""
    neighbor_list: List[Dict[str, Any]] = []
    try:
        nbr_path = api_client.path("/routing/ospf/neighbor")
        neighbor_list = list(nbr_path)
    except Exception:
        try:
            nbr_path = api_client.path("/routing/ospf/neighbour")
            neighbor_list = list(nbr_path)
        except Exception as e:
            logger.warning(f"OSPF paths unavailable or OSPF not configured: {e}")
            return OspfNeighborsResponse()

    detailed_nbrs: List[OspfNeighborInfo] = []
    full_cnt = 0
    down_cnt = 0
    down_nbrs: List[str] = []

    for item in neighbor_list:
        nbr_ip = str(item.get("address", item.get("neighbor", "unknown")))
        r_id = str(item.get("router-id", "unknown"))
        state = str(item.get("state", "Down"))
        iface = str(item.get("interface", "unknown"))
        uptime = str(item.get("uptime", "unknown"))

        is_full = ("full" in state.lower())
        if is_full:
            full_cnt += 1
        else:
            down_cnt += 1
            down_nbrs.append(nbr_ip)

        if details:
            detailed_nbrs.append(
                OspfNeighborInfo(
                    neighbor=nbr_ip,
                    router_id=r_id,
                    state=state,
                    interface=iface,
                    uptime=uptime,
                )
            )

    return OspfNeighborsResponse(
        total=len(neighbor_list),
        full=full_cnt,
        down=down_cnt,
        down_neighbors=down_nbrs,
        neighbors=detailed_nbrs if details else None,
    )


def parse_single_ospf_neighbor_detail(api_client: Any, neighbor_target: str) -> OspfNeighborInfo:
    """Queries single OSPF neighbor by IP or router ID."""
    nbrs_res = parse_ospf_neighbors_data(api_client, details=True)
    if nbrs_res.neighbors:
        for n in nbrs_res.neighbors:
            if n.neighbor.lower() == neighbor_target.lower() or n.router_id.lower() == neighbor_target.lower():
                return n
    return OspfNeighborInfo(neighbor=neighbor_target, state="Down")


# 4. NAT Parsers
def parse_nat_rules_data(api_client: Any, details: bool = False) -> NatRulesResponse:
    """Queries /ip/firewall/nat rules."""
    rule_list: List[Dict[str, Any]] = []
    try:
        nat_path = api_client.path("/ip/firewall/nat")
        rule_list = list(nat_path)
    except Exception as e:
        logger.warning(f"Unable to query /ip/firewall/nat: {e}")
        return NatRulesResponse()

    detailed_rules: List[NatRuleInfo] = []
    active_cnt = 0
    disabled_cnt = 0
    zero_cnt_rules: List[str] = []

    for idx, item in enumerate(rule_list):
        r_id = str(item.get(".id", f"rule-{idx}"))
        chain = str(item.get("chain", "srcnat"))
        action = str(item.get("action", "masquerade"))
        src_addr = item.get("src-address")
        dst_addr = item.get("dst-address")
        out_iface = item.get("out-interface")
        pkts = parse_int_safe(item.get("packets"), 0)
        bytes_cnt = parse_int_safe(item.get("bytes"), 0)
        disabled = parse_bool_safe(item.get("disabled"), False)

        if disabled:
            disabled_cnt += 1
        else:
            active_cnt += 1
            if pkts == 0 and bytes_cnt == 0:
                zero_cnt_rules.append(r_id)

        if details:
            detailed_rules.append(
                NatRuleInfo(
                    rule_id=r_id,
                    chain=chain,
                    action=action,
                    src_address=str(src_addr) if src_addr else None,
                    dst_address=str(dst_addr) if dst_addr else None,
                    out_interface=str(out_iface) if out_iface else None,
                    packets=pkts,
                    bytes=bytes_cnt,
                    disabled=disabled,
                )
            )

    return NatRulesResponse(
        total=len(rule_list),
        active=active_cnt,
        disabled=disabled_cnt,
        zero_counter_rules=zero_cnt_rules,
        rules=detailed_rules if details else None,
    )


def parse_routing_logs_data(api_client: Any, filter_text: Optional[str] = None) -> RoutingLogsResponse:
    """Queries /log for events matching routing topics (bgp, ospf, route) or filter text."""
    events: List[LogEvent] = []
    try:
        log_tuple = api_client.path("/log")
        log_list = list(log_tuple)
        
        target = filter_text.lower() if filter_text else None
        for item in log_list:
            msg = str(item.get("message", ""))
            topics = str(item.get("topics", "")).lower()
            time_str = str(item.get("time", item.get("timestamp", "")))

            is_routing_topic = any(t in topics for t in ["bgp", "ospf", "route", "route,info", "interface"])
            matches_filter = (target is None) or (target in msg.lower() or target in topics)

            if is_routing_topic or matches_filter:
                events.append(LogEvent(timestamp=time_str, message=msg))
    except Exception as e:
        logger.warning(f"Unable to fetch routing logs: {e}")

    return RoutingLogsResponse(filter_text=filter_text, events=events)


# --- LangChain Read-Only Tool Definitions ---

@tool
def get_system_health() -> str:
    """Inspects MikroTik router system health (identity, CPU load, RAM usage, version, uptime)."""
    logger.info("Executing tool: get_system_health")
    with get_routeros_client() as api:
        return parse_system_resource(api).model_dump_json()


@tool
def get_interfaces(details: bool = False, interface_name: Optional[str] = None) -> str:
    """Inspects interface summary or details (ACTIVE, UNCONNECTED, LINK_DOWN, ERROR, DISABLED)."""
    logger.info(f"Executing tool: get_interfaces (details={details}, interface_name={interface_name})")
    with get_routeros_client() as api:
        return parse_interfaces_data(api, details=details, interface_name=interface_name).model_dump_json(exclude_none=True)


@tool
def get_interface_detail(interface_name: str) -> str:
    """Retrieves detailed operational parameters for ONE specific interface."""
    logger.info(f"Executing tool: get_interface_detail (interface_name={interface_name})")
    with get_routeros_client() as api:
        return parse_single_interface_detail(api, interface_name=interface_name).model_dump_json()


@tool
def get_interface_logs(interface_name: str) -> str:
    """Retrieves timestamped RouterOS log events related to ONE specific interface."""
    logger.info(f"Executing tool: get_interface_logs (interface_name={interface_name})")
    with get_routeros_client() as api:
        return parse_interface_logs(api, interface_name=interface_name).model_dump_json()


@tool
def get_interface_traffic(interface_name: str) -> str:
    """Retrieves current real-time traffic and error counters for ONE specific interface."""
    logger.info(f"Executing tool: get_interface_traffic (interface_name={interface_name})")
    with get_routeros_client() as api:
        return parse_interface_traffic(api, interface_name=interface_name).model_dump_json()


@tool
def get_bgp_peers(details: bool = False) -> str:
    """Inspects BGP peer summary or details (ESTABLISHED vs DOWN sessions)."""
    logger.info(f"Executing tool: get_bgp_peers (details={details})")
    with get_routeros_client() as api:
        return parse_bgp_peers_data(api, details=details).model_dump_json(exclude_none=True)


@tool
def get_bgp_peer_detail(peer: str) -> str:
    """Retrieves detailed session parameters for ONE specific BGP peer IP or name."""
    logger.info(f"Executing tool: get_bgp_peer_detail (peer={peer})")
    with get_routeros_client() as api:
        return parse_bgp_peer_detail(api, peer).model_dump_json()


@tool
def get_bgp_routes(peer: Optional[str] = None) -> str:
    """Retrieves BGP prefix/route information."""
    logger.info(f"Executing tool: get_bgp_routes (peer={peer})")
    with get_routeros_client() as api:
        routes_res = parse_static_routes_data(api, details=True)
        return routes_res.model_dump_json(exclude_none=True)


@tool
def get_static_routes(details: bool = False) -> str:
    """Inspects static routing table entries (active vs inactive routes)."""
    logger.info(f"Executing tool: get_static_routes (details={details})")
    with get_routeros_client() as api:
        return parse_static_routes_data(api, details=details).model_dump_json(exclude_none=True)


@tool
def get_route(destination: str) -> str:
    """Retrieves single route entry matching destination CIDR prefix or gateway IP."""
    logger.info(f"Executing tool: get_route (destination={destination})")
    with get_routeros_client() as api:
        return parse_single_route_detail(api, destination).model_dump_json()


@tool
def get_routing_table() -> str:
    """Retrieves complete active routing table overview."""
    logger.info("Executing tool: get_routing_table")
    with get_routeros_client() as api:
        return parse_static_routes_data(api, details=True).model_dump_json(exclude_none=True)


@tool
def get_ospf_neighbors(details: bool = False) -> str:
    """Inspects OSPF neighbor adjacencies (Full vs Down neighbors)."""
    logger.info(f"Executing tool: get_ospf_neighbors (details={details})")
    with get_routeros_client() as api:
        return parse_ospf_neighbors_data(api, details=details).model_dump_json(exclude_none=True)


@tool
def get_ospf_neighbor_detail(neighbor: str) -> str:
    """Retrieves detailed OSPF neighbor metrics for ONE specific neighbor IP or router ID."""
    logger.info(f"Executing tool: get_ospf_neighbor_detail (neighbor={neighbor})")
    with get_routeros_client() as api:
        return parse_single_ospf_neighbor_detail(api, neighbor).model_dump_json()


@tool
def get_ospf_routes() -> str:
    """Retrieves active OSPF routes."""
    logger.info("Executing tool: get_ospf_routes")
    with get_routeros_client() as api:
        return parse_static_routes_data(api, details=True).model_dump_json(exclude_none=True)


@tool
def get_nat_rules(details: bool = False) -> str:
    """Inspects firewall NAT rules (masquerade/srcnat/dstnat)."""
    logger.info(f"Executing tool: get_nat_rules (details={details})")
    with get_routeros_client() as api:
        return parse_nat_rules_data(api, details=details).model_dump_json(exclude_none=True)


@tool
def get_nat_statistics(rule_id: Optional[str] = None) -> str:
    """Retrieves real-time packet and byte counters for NAT rules."""
    logger.info(f"Executing tool: get_nat_statistics (rule_id={rule_id})")
    with get_routeros_client() as api:
        return parse_nat_rules_data(api, details=True).model_dump_json(exclude_none=True)


@tool
def get_nat_connections() -> str:
    """Retrieves NAT connection tracking statistics."""
    logger.info("Executing tool: get_nat_connections")
    with get_routeros_client() as api:
        return parse_nat_rules_data(api, details=False).model_dump_json(exclude_none=True)


@tool
def get_routing_logs(filter_text: Optional[str] = None) -> str:
    """Retrieves RouterOS log entries matching routing topics or filter text."""
    logger.info(f"Executing tool: get_routing_logs (filter_text={filter_text})")
    with get_routeros_client() as api:
        return parse_routing_logs_data(api, filter_text=filter_text).model_dump_json()
