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
                    first_seen TEXT,
                    last_seen TEXT,
                    occurrence_count INTEGER DEFAULT 1,
                    status TEXT DEFAULT 'ACTIVE',
                    type TEXT,
                    severity TEXT,
                    source TEXT,
                    entity TEXT,
                    evidence TEXT,
                    fingerprint TEXT
                )
            """)

            # Schema migration for events
            event_cols = [c[1] for c in cursor.execute("PRAGMA table_info(events)").fetchall()]
            if "first_seen" not in event_cols:
                cursor.execute("ALTER TABLE events ADD COLUMN first_seen TEXT")
            if "last_seen" not in event_cols:
                cursor.execute("ALTER TABLE events ADD COLUMN last_seen TEXT")
            if "occurrence_count" not in event_cols:
                cursor.execute("ALTER TABLE events ADD COLUMN occurrence_count INTEGER DEFAULT 1")
            if "status" not in event_cols:
                cursor.execute("ALTER TABLE events ADD COLUMN status TEXT DEFAULT 'ACTIVE'")

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
                    event_count INTEGER DEFAULT 1,
                    occurrence_count INTEGER DEFAULT 1,
                    confidence TEXT,
                    facts TEXT,
                    summary TEXT,
                    llm_status TEXT
                )
            """)

            # Schema migration for incidents
            inc_cols = [c[1] for c in cursor.execute("PRAGMA table_info(incidents)").fetchall()]
            if "event_count" not in inc_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN event_count INTEGER DEFAULT 1")
            if "occurrence_count" not in inc_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN occurrence_count INTEGER DEFAULT 1")
            if "facts" not in inc_cols:
                cursor.execute("ALTER TABLE incidents ADD COLUMN facts TEXT")

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

    def get_active_event_by_fingerprint(self, device_id: str, fingerprint: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            row = conn.execute("""
                SELECT * FROM events WHERE device_id = ? AND fingerprint = ? AND status = 'ACTIVE' ORDER BY timestamp DESC LIMIT 1
            """, (device_id, fingerprint)).fetchone()
            if not row:
                return None
            d = dict(row)
            if d.get("evidence"):
                try:
                    d["evidence"] = json.loads(d["evidence"])
                except Exception:
                    pass
            return d

    def upsert_active_event(self, e: EventRecord) -> str:
        """
        Deduplicates events cleanly:
        If an ACTIVE event with matching fingerprint exists, updates last_seen, occurrence_count (+1), and evidence in-place.
        Otherwise, inserts a new event row. Returns event_id.
        """
        existing = self.get_active_event_by_fingerprint(e.device_id, e.fingerprint)
        with self.get_connection() as conn:
            if existing:
                evt_id = existing["event_id"]
                new_occ = existing.get("occurrence_count", 1) + 1
                conn.execute("""
                    UPDATE events SET
                        last_seen = ?,
                        occurrence_count = ?,
                        evidence = ?,
                        status = ?
                    WHERE event_id = ?
                """, (e.last_seen, new_occ, json.dumps(e.evidence), e.status, evt_id))
                conn.commit()
                return evt_id
            else:
                conn.execute("""
                    INSERT INTO events (event_id, device_id, timestamp, first_seen, last_seen, occurrence_count, status, type, severity, source, entity, evidence, fingerprint)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (e.event_id, e.device_id, e.timestamp, e.first_seen, e.last_seen, e.occurrence_count, e.status, e.type, e.severity, e.source, e.entity, json.dumps(e.evidence), e.fingerprint))
                conn.commit()
                return e.event_id

    def update_event_status(self, event_id: str, status: str) -> None:
        with self.get_connection() as conn:
            conn.execute("UPDATE events SET status = ? WHERE event_id = ?", (status, event_id))
            conn.commit()

    def upsert_incident(self, inc: IncidentRecord) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO incidents (incident_id, device_id, created_at, updated_at, severity, status, root_event_id, correlated_event_ids, event_count, occurrence_count, confidence, facts, summary, llm_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(incident_id) DO UPDATE SET
                    updated_at=excluded.updated_at,
                    severity=excluded.severity,
                    status=excluded.status,
                    correlated_event_ids=excluded.correlated_event_ids,
                    event_count=excluded.event_count,
                    occurrence_count=excluded.occurrence_count,
                    confidence=excluded.confidence,
                    facts=excluded.facts,
                    summary=excluded.summary,
                    llm_status=excluded.llm_status
            """, (inc.incident_id, inc.device_id, inc.created_at, inc.updated_at, inc.severity, inc.status, inc.root_event_id, json.dumps(inc.correlated_event_ids), inc.event_count, inc.occurrence_count, inc.confidence, json.dumps(inc.facts), inc.summary, inc.llm_status))
            conn.commit()

    # --- QUERY METHODS FOR BASELINE & API ---

    def get_database_status(self) -> Dict[str, Any]:
        """Returns database path, existence, file size, table list, and table row counts."""
        db_path_obj = Path(self.db_path)
        exists = db_path_obj.exists()
        size_bytes = db_path_obj.stat().st_size if exists else 0

        tables = ["devices", "device_metrics", "interface_metrics", "bgp_metrics", "ospf_metrics", "nat_metrics", "route_metrics", "events", "incidents", "alerts"]
        row_counts = {}

        if exists:
            with self.get_connection() as conn:
                for t in tables:
                    try:
                        row_counts[t] = conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                    except Exception:
                        row_counts[t] = 0

        return {
            "database_path": str(self.db_path),
            "exists": exists,
            "size_bytes": size_bytes,
            "row_counts": row_counts
        }

    def get_devices(self) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            rows = conn.execute("SELECT * FROM devices ORDER BY device_id").fetchall()
            return [dict(r) for r in rows]

    def get_recent_device_metrics(self, device_id: str, limit: int = 100, lookback_minutes: Optional[int] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            if lookback_minutes:
                from datetime import datetime, timezone, timedelta
                cutoff = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat()
                rows = conn.execute("""
                    SELECT * FROM device_metrics WHERE device_id = ? AND timestamp >= ? ORDER BY id DESC LIMIT ?
                """, (device_id, cutoff, limit)).fetchall()
                if rows:
                    return [dict(r) for r in rows]
            rows = conn.execute("""
                SELECT * FROM device_metrics WHERE device_id = ? ORDER BY id DESC LIMIT ?
            """, (device_id, limit)).fetchall()
            return [dict(r) for r in rows]

    def purge_old_metrics(self, retention_hours: Optional[int] = None) -> Dict[str, int]:
        """Purges historical metrics older than the configured retention period (default 168 hours = 7 days)."""
        hours = retention_hours or settings.METRIC_RETENTION_HOURS
        from datetime import datetime, timezone, timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        purged = {}
        with self.get_connection() as conn:
            for table in ["device_metrics", "interface_metrics", "bgp_metrics", "ospf_metrics", "nat_metrics", "route_metrics"]:
                cur = conn.execute(f"DELETE FROM {table} WHERE timestamp < ?", (cutoff,))
                purged[table] = cur.rowcount
            conn.commit()
        logger.info(f"Purged historical metrics older than {hours}h ({cutoff}): {purged}")
        return purged

    def get_recent_interface_metrics(self, device_id: Optional[str] = None, interface_name: str = "", limit: int = 100, lookback_minutes: Optional[int] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            if lookback_minutes:
                from datetime import datetime, timezone, timedelta
                cutoff = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat()
                if device_id:
                    rows = conn.execute("""
                        SELECT * FROM interface_metrics WHERE device_id = ? AND interface_name = ? AND timestamp >= ? ORDER BY id DESC LIMIT ?
                    """, (device_id, interface_name, cutoff, limit)).fetchall()
                else:
                    rows = conn.execute("""
                        SELECT * FROM interface_metrics WHERE interface_name = ? AND timestamp >= ? ORDER BY id DESC LIMIT ?
                    """, (interface_name, cutoff, limit)).fetchall()
                if rows:
                    return [dict(r) for r in rows]
            if device_id:
                rows = conn.execute("""
                    SELECT * FROM interface_metrics WHERE device_id = ? AND interface_name = ? ORDER BY id DESC LIMIT ?
                """, (device_id, interface_name, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM interface_metrics WHERE interface_name = ? ORDER BY id DESC LIMIT ?
                """, (interface_name, limit)).fetchall()
            return [dict(r) for r in rows]

    def get_recent_bgp_metrics(self, device_id: Optional[str] = None, peer: str = "", limit: int = 100, lookback_minutes: Optional[int] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            if lookback_minutes:
                from datetime import datetime, timezone, timedelta
                cutoff = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat()
                if device_id:
                    rows = conn.execute("""
                        SELECT * FROM bgp_metrics WHERE device_id = ? AND (peer = ? OR remote_address = ?) AND timestamp >= ? ORDER BY id DESC LIMIT ?
                    """, (device_id, peer, peer, cutoff, limit)).fetchall()
                else:
                    rows = conn.execute("""
                        SELECT * FROM bgp_metrics WHERE (peer = ? OR remote_address = ?) AND timestamp >= ? ORDER BY id DESC LIMIT ?
                    """, (peer, peer, cutoff, limit)).fetchall()
                if rows:
                    return [dict(r) for r in rows]
            if device_id:
                rows = conn.execute("""
                    SELECT * FROM bgp_metrics WHERE device_id = ? AND (peer = ? OR remote_address = ?) ORDER BY id DESC LIMIT ?
                """, (device_id, peer, peer, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM bgp_metrics WHERE peer = ? OR remote_address = ? ORDER BY id DESC LIMIT ?
                """, (peer, peer, limit)).fetchall()
            return [dict(r) for r in rows]

    def get_recent_ospf_metrics(self, device_id: Optional[str] = None, neighbor: str = "", limit: int = 100, lookback_minutes: Optional[int] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            if lookback_minutes:
                from datetime import datetime, timezone, timedelta
                cutoff = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat()
                if device_id:
                    rows = conn.execute("""
                        SELECT * FROM ospf_metrics WHERE device_id = ? AND (neighbor = ? OR router_id = ?) AND timestamp >= ? ORDER BY id DESC LIMIT ?
                    """, (device_id, neighbor, neighbor, cutoff, limit)).fetchall()
                else:
                    rows = conn.execute("""
                        SELECT * FROM ospf_metrics WHERE (neighbor = ? OR router_id = ?) AND timestamp >= ? ORDER BY id DESC LIMIT ?
                    """, (neighbor, neighbor, cutoff, limit)).fetchall()
                if rows:
                    return [dict(r) for r in rows]
            if device_id:
                rows = conn.execute("""
                    SELECT * FROM ospf_metrics WHERE device_id = ? AND (neighbor = ? OR router_id = ?) ORDER BY id DESC LIMIT ?
                """, (device_id, neighbor, neighbor, limit)).fetchall()
            else:
                rows = conn.execute("""
                    SELECT * FROM ospf_metrics WHERE neighbor = ? OR router_id = ? ORDER BY id DESC LIMIT ?
                """, (neighbor, neighbor, limit)).fetchall()
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
                SELECT * FROM incidents WHERE device_id = ? AND status IN ('OPEN', 'ACKNOWLEDGED') ORDER BY created_at DESC
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
                if d.get("facts"):
                    try:
                        d["facts"] = json.loads(d["facts"])
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
            if d.get("facts"):
                try:
                    d["facts"] = json.loads(d["facts"])
                except Exception:
                    pass
            return d


db = DatabaseManager()
