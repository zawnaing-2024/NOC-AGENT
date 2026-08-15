import os
import json
import sqlite3
import logging
from typing import List, Optional, Dict, Any
from pathlib import Path

from app.config import settings
from app.db.schemas import (
    DeviceRecord,
    DeviceMetricRecord,
    InterfaceMetricRecord,
    BgpMetricRecord,
    OspfMetricRecord,
    NatMetricRecord,
    RouteMetricRecord,
    EventRecord,
    IncidentRecord,
    AlertRecord,
)

logger = logging.getLogger("mikrotik_noc_agent.db")


class DatabaseManager:
    """Manages SQLite database connections, schema migrations, and metric/event persistence."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or settings.DATABASE_PATH
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Initializes all 10 SQLite database tables for Phase 4 AIOps telemetry."""
        logger.info(f"Initializing Phase 4 SQLite Database at '{self.db_path}'...")
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # 1. Devices
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    device_id TEXT PRIMARY KEY,
                    name TEXT,
                    ip_address TEXT,
                    model TEXT,
                    version TEXT,
                    status TEXT,
                    updated_at TEXT
                )
            """)

            # 2. Device Metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS device_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    device_id TEXT,
                    cpu_percent REAL,
                    memory_percent REAL,
                    uptime_seconds INTEGER
                )
            """)

            # 3. Interface Metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS interface_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    device_id TEXT,
                    interface_name TEXT,
                    running INTEGER,
                    disabled INTEGER,
                    rx_bps REAL,
                    tx_bps REAL,
                    rx_packets INTEGER,
                    tx_packets INTEGER,
                    rx_errors INTEGER,
                    tx_errors INTEGER,
                    rx_drops INTEGER,
                    tx_drops INTEGER
                )
            """)

            # 4. BGP Metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS bgp_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    device_id TEXT,
                    peer TEXT,
                    remote_address TEXT,
                    established INTEGER,
                    uptime TEXT,
                    prefix_count INTEGER
                )
            """)

            # 5. OSPF Metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ospf_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    device_id TEXT,
                    neighbor TEXT,
                    router_id TEXT,
                    state TEXT
                )
            """)

            # 6. NAT Metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS nat_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    device_id TEXT,
                    rule_id TEXT,
                    enabled INTEGER,
                    packets INTEGER,
                    bytes INTEGER,
                    interface_dependency TEXT
                )
            """)

            # 7. Route Metrics
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS route_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    device_id TEXT,
                    destination TEXT,
                    gateway TEXT,
                    active INTEGER,
                    distance INTEGER,
                    routing_table TEXT
                )
            """)

            # 8. Events
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    device_id TEXT,
                    timestamp TEXT,
                    type TEXT,
                    severity TEXT,
                    source TEXT,
                    entity TEXT,
                    evidence TEXT,
                    fingerprint TEXT
                )
            """)

            # 9. Incidents
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS incidents (
                    incident_id TEXT PRIMARY KEY,
                    device_id TEXT,
                    created_at TEXT,
                    updated_at TEXT,
                    severity TEXT,
                    status TEXT,
                    root_event_id TEXT,
                    correlated_event_ids TEXT,
                    confidence TEXT,
                    summary TEXT,
                    llm_status TEXT
                )
            """)

            # 10. Alerts
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    alert_id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    device_id TEXT,
                    timestamp TEXT,
                    type TEXT,
                    status TEXT,
                    message TEXT
                )
            """)
            conn.commit()

    # --- INSERTS & QUERIES ---

    def upsert_device(self, record: DeviceRecord) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO devices (device_id, name, ip_address, model, version, status, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    name=excluded.name,
                    ip_address=excluded.ip_address,
                    model=excluded.model,
                    version=excluded.version,
                    status=excluded.status,
                    updated_at=excluded.updated_at
            """, (record.device_id, record.name, record.ip_address, record.model, record.version, record.status, record.updated_at))
            conn.commit()

    def insert_device_metric(self, m: DeviceMetricRecord) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO device_metrics (timestamp, device_id, cpu_percent, memory_percent, uptime_seconds)
                VALUES (?, ?, ?, ?, ?)
            """, (m.timestamp, m.device_id, m.cpu_percent, m.memory_percent, m.uptime_seconds))
            conn.commit()

    def insert_interface_metric(self, m: InterfaceMetricRecord) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO interface_metrics (timestamp, device_id, interface_name, running, disabled, rx_bps, tx_bps, rx_packets, tx_packets, rx_errors, tx_errors, rx_drops, tx_drops)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (m.timestamp, m.device_id, m.interface_name, int(m.running), int(m.disabled), m.rx_bps, m.tx_bps, m.rx_packets, m.tx_packets, m.rx_errors, m.tx_errors, m.rx_drops, m.tx_drops))
            conn.commit()

    def insert_bgp_metric(self, m: BgpMetricRecord) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO bgp_metrics (timestamp, device_id, peer, remote_address, established, uptime, prefix_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (m.timestamp, m.device_id, m.peer, m.remote_address, int(m.established), m.uptime, m.prefix_count))
            conn.commit()

    def insert_ospf_metric(self, m: OspfMetricRecord) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO ospf_metrics (timestamp, device_id, neighbor, router_id, state)
                VALUES (?, ?, ?, ?, ?)
            """, (m.timestamp, m.device_id, m.neighbor, m.router_id, m.state))
            conn.commit()

    def insert_nat_metric(self, m: NatMetricRecord) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO nat_metrics (timestamp, device_id, rule_id, enabled, packets, bytes, interface_dependency)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (m.timestamp, m.device_id, m.rule_id, int(m.enabled), m.packets, m.bytes, m.interface_dependency))
            conn.commit()

    def insert_route_metric(self, m: RouteMetricRecord) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO route_metrics (timestamp, device_id, destination, gateway, active, distance, routing_table)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (m.timestamp, m.device_id, m.destination, m.gateway, int(m.active), m.distance, m.routing_table))
            conn.commit()

    def insert_event(self, e: EventRecord) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT OR IGNORE INTO events (event_id, device_id, timestamp, type, severity, source, entity, evidence, fingerprint)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (e.event_id, e.device_id, e.timestamp, e.type, e.severity, e.source, e.entity, json.dumps(e.evidence), e.fingerprint))
            conn.commit()

    def upsert_incident(self, inc: IncidentRecord) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO incidents (incident_id, device_id, created_at, updated_at, severity, status, root_event_id, correlated_event_ids, confidence, summary, llm_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    severity=excluded.severity,
                    status=excluded.status,
                    correlated_event_ids=excluded.correlated_event_ids,
                    confidence=excluded.confidence,
                    summary=excluded.summary,
                    llm_status=excluded.llm_status
            """, (inc.incident_id, inc.device_id, inc.created_at, inc.updated_at, inc.severity, inc.status, inc.root_event_id, json.dumps(inc.correlated_event_ids), inc.confidence, inc.summary, inc.llm_status))
            conn.commit()

    # --- QUERY METHODS FOR BASELINE & API ---

    def get_devices(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM devices ORDER BY device_id").fetchall()
            return [dict(r) for r in rows]

    def get_recent_device_metrics(self, device_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM device_metrics WHERE device_id = ? ORDER BY id DESC LIMIT ?
            """, (device_id, limit)).fetchall()
            return [dict(r) for r in rows]

    def get_recent_interface_metrics(self, device_id: str, interface_name: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM interface_metrics WHERE device_id = ? AND interface_name = ? ORDER BY id DESC LIMIT ?
            """, (device_id, interface_name, limit)).fetchall()
            return [dict(r) for r in rows]

    def get_recent_bgp_metrics(self, device_id: str, peer: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM bgp_metrics WHERE device_id = ? AND (peer = ? OR remote_address = ?) ORDER BY id DESC LIMIT ?
            """, (device_id, peer, peer, limit)).fetchall()
            return [dict(r) for r in rows]

    def get_recent_ospf_metrics(self, device_id: str, neighbor: str, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM ospf_metrics WHERE device_id = ? AND (neighbor = ? OR router_id = ?) ORDER BY id DESC LIMIT ?
            """, (device_id, neighbor, neighbor, limit)).fetchall()
            return [dict(r) for r in rows]

    def get_events(self, limit: int = 100, device_id: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            if device_id:
                rows = conn.execute("SELECT * FROM events WHERE device_id = ? ORDER BY timestamp DESC LIMIT ?", (device_id, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)).fetchall()
            
            res = []
            for r in rows:
                d = dict(r)
                if d.get("evidence"):
                    try:
                        d["evidence"] = json.loads(d["evidence"])
                    except Exception:
                        pass
                res.append(d)
            return res

    def get_event_by_id(self, event_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("evidence"):
                try:
                    d["evidence"] = json.loads(d["evidence"])
                except Exception:
                    pass
            return d

    def get_open_incident_by_fingerprint(self, device_id: str, fingerprint: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("""
                SELECT * FROM incidents WHERE device_id = ? AND status != 'RESOLVED' ORDER BY created_at DESC
            """, (device_id,)).fetchall()
            for r in rows:
                d = dict(r)
                corr_ids = json.loads(d.get("correlated_event_ids", "[]"))
                all_eids = set([d["root_event_id"]] + corr_ids)
                for eid in all_eids:
                    evt = self.get_event_by_id(eid)
                    if evt and evt.get("fingerprint") == fingerprint:
                        return d
            return None

    def get_incidents(self, limit: int = 50, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            if status:
                rows = conn.execute("SELECT * FROM incidents WHERE status = ? ORDER BY created_at DESC LIMIT ?", (status, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM incidents ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
            
            res = []
            for r in rows:
                d = dict(r)
                if d.get("correlated_event_ids"):
                    try:
                        d["correlated_event_ids"] = json.loads(d["correlated_event_ids"])
                    except Exception:
                        pass
                res.append(d)
            return res

    def get_incident_by_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("correlated_event_ids"):
                try:
                    d["correlated_event_ids"] = json.loads(d["correlated_event_ids"])
                except Exception:
                    pass
            return d


db = DatabaseManager()
