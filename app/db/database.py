import os
import json
import sqlite3
import logging
from typing import List, Optional, Dict, Any, Union
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
    AIAnalysisRecord,
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
                    description TEXT DEFAULT '',
                    location TEXT DEFAULT '',
                    role TEXT DEFAULT 'Router',
                    api_protocol TEXT DEFAULT 'api',
                    api_port INTEGER DEFAULT 8728,
                    username TEXT DEFAULT 'admin',
                    password TEXT DEFAULT '',
                    monitoring_enabled INTEGER DEFAULT 1,
                    collection_interval INTEGER DEFAULT 30,
                    monitoring_profile TEXT DEFAULT 'Standard',
                    model TEXT,
                    version TEXT,
                    status TEXT DEFAULT 'HEALTHY',
                    last_seen TEXT,
                    is_deleted INTEGER DEFAULT 0,
                    updated_at TEXT
                )
            """)

            # Auto-migrate devices table columns if missing
            device_cols = [
                ("description", "TEXT DEFAULT ''"),
                ("location", "TEXT DEFAULT ''"),
                ("role", "TEXT DEFAULT 'Router'"),
                ("api_protocol", "TEXT DEFAULT 'api'"),
                ("api_port", "INTEGER DEFAULT 8728"),
                ("username", "TEXT DEFAULT 'admin'"),
                ("password", "TEXT DEFAULT ''"),
                ("monitoring_enabled", "INTEGER DEFAULT 1"),
                ("collection_interval", "INTEGER DEFAULT 30"),
                ("monitoring_profile", "TEXT DEFAULT 'Standard'"),
                ("last_seen", "TEXT"),
                ("is_deleted", "INTEGER DEFAULT 0"),
            ]
            for col_name, col_type in device_cols:
                try:
                    cursor.execute(f"ALTER TABLE devices ADD COLUMN {col_name} {col_type}")
                except Exception:
                    pass

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
                    tx_drops INTEGER,
                    rx_bytes_raw REAL DEFAULT 0.0,
                    tx_bytes_raw REAL DEFAULT 0.0,
                    telemetry_valid INTEGER DEFAULT 1,
                    validation_reason TEXT DEFAULT 'VALID',
                    counter_reset INTEGER DEFAULT 0
                )
            """)

            # Auto-migrate interface_metrics table columns if missing
            try:
                cursor.execute("ALTER TABLE interface_metrics ADD COLUMN rx_bytes_raw REAL DEFAULT 0.0")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE interface_metrics ADD COLUMN tx_bytes_raw REAL DEFAULT 0.0")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE interface_metrics ADD COLUMN telemetry_valid INTEGER DEFAULT 1")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE interface_metrics ADD COLUMN validation_reason TEXT DEFAULT 'VALID'")
            except Exception:
                pass
            try:
                cursor.execute("ALTER TABLE interface_metrics ADD COLUMN counter_reset INTEGER DEFAULT 0")
            except Exception:
                pass

            # Phase 6.4 Cleanup Migration: Flag existing corrupted rows (>800 Gbps) as telemetry_valid = 0
            try:
                cursor.execute("""
                    UPDATE interface_metrics
                    SET telemetry_valid = 0, validation_reason = 'CORRUPTED_CUMULATIVE_BYTE_COUNTER'
                    WHERE (rx_bps > 800000000000.0 OR tx_bps > 800000000000.0) AND (telemetry_valid IS NULL OR telemetry_valid = 1)
                """)
            except Exception as e:
                logger.warning(f"Failed to auto-clean corrupted traffic metrics: {e}")

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

            # 11. AI Analyses (Phase 5 RCA Persistence)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS ai_analyses (
                    analysis_id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    device_id TEXT,
                    created_at TEXT,
                    model TEXT,
                    prompt_version TEXT,
                    status TEXT,
                    summary TEXT,
                    root_cause_json TEXT,
                    impact_json TEXT,
                    recommended_checks_json TEXT,
                    next_actions_json TEXT,
                    full_response_json TEXT,
                    confidence TEXT,
                    latency_ms INTEGER,
                    error_message TEXT
                )
            """)

            # 12. Deep NOC Investigations (Phase 6 Investigation Engine Persistence)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS investigations (
                    investigation_id TEXT PRIMARY KEY,
                    incident_id TEXT,
                    device_id TEXT,
                    created_at TEXT,
                    status TEXT,
                    primary_failure TEXT,
                    secondary_symptoms_json TEXT,
                    evidence_json TEXT,
                    recommendations_json TEXT,
                    visualization_flow_json TEXT
                )
            """)

            # Database Performance Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_device_metrics_dev_ts ON device_metrics (device_id, timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_interface_metrics_dev_if_ts ON interface_metrics (device_id, interface_name, timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_investigations_incident ON investigations (incident_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_bgp_metrics_dev_peer_ts ON bgp_metrics (device_id, peer, timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ospf_metrics_dev_nbr_ts ON ospf_metrics (device_id, neighbor, timestamp)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_fingerprint ON events (fingerprint, status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_analyses_incident ON ai_analyses (incident_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_ai_analyses_device ON ai_analyses (device_id)")

            # Auto-resolve stale DEFAULT_ROUTE_DOWN events where active default route is verified
            try:
                cursor.execute("""
                    UPDATE events SET status = 'RESOLVED'
                    WHERE type = 'DEFAULT_ROUTE_DOWN'
                    AND status IN ('ACTIVE', 'OPEN')
                    AND device_id IN (
                        SELECT DISTINCT device_id FROM route_metrics WHERE destination = '0.0.0.0/0' AND active = 1
                    )
                """)
            except Exception:
                pass

            conn.commit()

    # --- INSERTS & QUERIES ---

    def upsert_device(self, record: DeviceRecord) -> None:
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO devices (
                    device_id, name, ip_address, description, location, role,
                    api_protocol, api_port, username, password, monitoring_enabled,
                    collection_interval, monitoring_profile, model, version, status,
                    last_seen, is_deleted, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(device_id) DO UPDATE SET
                    name=excluded.name,
                    ip_address=excluded.ip_address,
                    description=excluded.description,
                    location=excluded.location,
                    role=excluded.role,
                    api_protocol=excluded.api_protocol,
                    api_port=excluded.api_port,
                    username=CASE WHEN excluded.username IS NOT NULL AND excluded.username != '' THEN excluded.username ELSE devices.username END,
                    password=CASE WHEN excluded.password IS NOT NULL AND excluded.password != '' AND excluded.password != '[REDACTED]' THEN excluded.password ELSE devices.password END,
                    monitoring_enabled=excluded.monitoring_enabled,
                    collection_interval=excluded.collection_interval,
                    monitoring_profile=excluded.monitoring_profile,
                    model=COALESCE(excluded.model, devices.model),
                    version=COALESCE(excluded.version, devices.version),
                    status=excluded.status,
                    last_seen=COALESCE(excluded.last_seen, devices.last_seen),
                    is_deleted=excluded.is_deleted,
                    updated_at=excluded.updated_at
            """, (
                record.device_id, record.name, record.ip_address, record.description or "", record.location or "",
                record.role or "Router", record.api_protocol or "api", record.api_port or 8728, record.username,
                record.password, int(record.monitoring_enabled), record.collection_interval or 30,
                record.monitoring_profile or "Standard", record.model, record.version, record.status or "HEALTHY",
                record.last_seen, int(record.is_deleted), record.updated_at
            ))
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
                INSERT INTO interface_metrics (
                    timestamp, device_id, interface_name, running, disabled,
                    rx_bps, tx_bps, rx_packets, tx_packets, rx_errors, tx_errors,
                    rx_drops, tx_drops, rx_bytes_raw, tx_bytes_raw,
                    telemetry_valid, validation_reason, counter_reset
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                m.timestamp, m.device_id, m.interface_name, int(m.running), int(m.disabled),
                m.rx_bps, m.tx_bps, m.rx_packets, m.tx_packets, m.rx_errors, m.tx_errors,
                m.rx_drops, m.tx_drops, m.rx_bytes_raw, m.tx_bytes_raw,
                int(m.telemetry_valid), m.validation_reason, int(m.counter_reset)
            ))
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

    def get_devices(self, include_deleted: bool = False, redact_password: bool = True) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            if include_deleted:
                rows = conn.execute("SELECT * FROM devices ORDER BY name, device_id").fetchall()
            else:
                rows = conn.execute("SELECT * FROM devices WHERE is_deleted = 0 OR is_deleted IS NULL ORDER BY name, device_id").fetchall()
            res = []
            for r in rows:
                d = dict(r)
                if redact_password:
                    d["password"] = "[REDACTED]" if d.get("password") else ""
                res.append(d)
            return res

    def get_device_by_id(self, device_id: str, redact_password: bool = True) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            row = conn.execute("SELECT * FROM devices WHERE device_id = ? OR ip_address = ?", (device_id, device_id)).fetchone()
            if not row:
                return None
            d = dict(row)
            if redact_password:
                d["password"] = "[REDACTED]" if d.get("password") else ""
            return d

    def soft_delete_device(self, device_id: str) -> bool:
        """Removes device from active inventory without deleting historical telemetry."""
        from datetime import datetime, timezone
        with self.get_connection() as conn:
            cur = conn.execute("""
                UPDATE devices SET is_deleted = 1, monitoring_enabled = 0, status = 'DISABLED', updated_at = ?
                WHERE device_id = ? OR ip_address = ?
            """, (datetime.now(timezone.utc).isoformat(), device_id, device_id))
            conn.commit()
            return cur.rowcount > 0

    def set_device_monitoring(self, device_id: str, enabled: bool) -> bool:
        """Enables or disables monitoring for a device."""
        from datetime import datetime, timezone
        with self.get_connection() as conn:
            cur = conn.execute("""
                UPDATE devices SET monitoring_enabled = ?, status = CASE WHEN ? = 0 THEN 'DISABLED' ELSE 'HEALTHY' END, updated_at = ?
                WHERE device_id = ? OR ip_address = ?
            """, (int(enabled), int(enabled), datetime.now(timezone.utc).isoformat(), device_id, device_id))
            conn.commit()
            return cur.rowcount > 0

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

    def save_event(self, event_data: Union[Dict[str, Any], Any]) -> str:
        """Helper to save or upsert an event record from dict or model."""
        import uuid
        if isinstance(event_data, dict):
            e_id = event_data.get("event_id") or f"evt-{uuid.uuid4().hex[:8]}"
            dev_id = event_data.get("device_id") or "103.59.163.7"
            ts = event_data.get("timestamp") or datetime.now(timezone.utc).isoformat()
            fs = event_data.get("first_seen") or ts
            ls = event_data.get("last_seen") or ts
            occ = event_data.get("occurrence_count", 1)
            st = event_data.get("status", "ACTIVE")
            tp = event_data.get("type") or event_data.get("event_type") or "ANOMALY"
            sev = event_data.get("severity", "WARNING")
            src = event_data.get("source", "NOC Agent")
            ent = event_data.get("entity", "system")
            ev = event_data.get("evidence", {})
            fp = event_data.get("fingerprint") or f"{dev_id}:{tp}:{ent}"
            rec = EventRecord(
                event_id=e_id, device_id=dev_id, timestamp=ts, first_seen=fs,
                last_seen=ls, occurrence_count=occ, status=st, type=tp,
                severity=sev, source=src, entity=ent, evidence=ev, fingerprint=fp
            )
            return self.upsert_active_event(rec)
        elif hasattr(event_data, "event_id"):
            return self.upsert_active_event(event_data)
        else:
            raise ValueError("Invalid event_data format.")

    def save_interface_metric(self, metric_data: Union[Dict[str, Any], Any]) -> None:
        """Helper to insert an interface metric record from dict or model."""
        if isinstance(metric_data, dict):
            rec = InterfaceMetricRecord(
                timestamp=metric_data.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                device_id=metric_data.get("device_id", "103.59.163.7"),
                interface_name=metric_data.get("interface_name", "ether1"),
                running=bool(metric_data.get("running", True)),
                disabled=bool(metric_data.get("disabled", False)),
                rx_bps=float(metric_data.get("rx_bps", 0.0)),
                tx_bps=float(metric_data.get("tx_bps", 0.0)),
                rx_packets=int(metric_data.get("rx_packets", 0)),
                tx_packets=int(metric_data.get("tx_packets", 0)),
                rx_errors=int(metric_data.get("rx_errors", 0)),
                tx_errors=int(metric_data.get("tx_errors", 0)),
                rx_drops=int(metric_data.get("rx_drops", 0)),
                tx_drops=int(metric_data.get("tx_drops", 0)),
                rx_bytes_raw=int(metric_data.get("rx_bytes_raw", 0)),
                tx_bytes_raw=int(metric_data.get("tx_bytes_raw", 0)),
                telemetry_valid=bool(metric_data.get("telemetry_valid", True)),
                validation_reason=metric_data.get("validation_reason", "VALID"),
                counter_reset=bool(metric_data.get("counter_reset", False))
            )
            self.insert_interface_metric(rec)
        elif hasattr(metric_data, "device_id"):
            self.insert_interface_metric(metric_data)
        else:
            raise ValueError("Invalid metric_data format.")

    def get_recent_interface_metrics(
        self,
        device_id: Optional[str] = None,
        interface_name: str = "",
        limit: int = 100,
        lookback_minutes: Optional[int] = None,
        valid_only: bool = False
    ) -> List[Dict[str, Any]]:
        valid_clause = " AND (telemetry_valid IS NULL OR telemetry_valid = 1)" if valid_only else ""
        with self.get_connection() as conn:
            if device_id and not interface_name:
                sql = f"SELECT * FROM interface_metrics WHERE device_id = ?{valid_clause} ORDER BY id DESC LIMIT ?"
                rows = conn.execute(sql, (device_id, limit)).fetchall()
                return [dict(r) for r in rows]
            if lookback_minutes:
                from datetime import datetime, timezone, timedelta
                cutoff = (datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)).isoformat()
                if device_id:
                    sql = f"SELECT * FROM interface_metrics WHERE device_id = ? AND interface_name = ? AND timestamp >= ?{valid_clause} ORDER BY id DESC LIMIT ?"
                    rows = conn.execute(sql, (device_id, interface_name, cutoff, limit)).fetchall()
                else:
                    sql = f"SELECT * FROM interface_metrics WHERE interface_name = ? AND timestamp >= ?{valid_clause} ORDER BY id DESC LIMIT ?"
                    rows = conn.execute(sql, (interface_name, cutoff, limit)).fetchall()
                if rows:
                    return [dict(r) for r in rows]
            if device_id:
                sql = f"SELECT * FROM interface_metrics WHERE device_id = ? AND interface_name = ?{valid_clause} ORDER BY id DESC LIMIT ?"
                rows = conn.execute(sql, (device_id, interface_name, limit)).fetchall()
            else:
                sql = f"SELECT * FROM interface_metrics WHERE interface_name = ?{valid_clause} ORDER BY id DESC LIMIT ?"
                rows = conn.execute(sql, (interface_name, limit)).fetchall()
            return [dict(r) for r in rows]

    def get_recent_route_metrics(self, device_id: Optional[str] = None, limit: int = 1000) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            if device_id:
                rows = conn.execute("SELECT * FROM route_metrics WHERE device_id = ? ORDER BY id DESC LIMIT ?", (device_id, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM route_metrics ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def get_device_route_count(self, device_id: str) -> int:
        """Retrieves count of distinct physical route destinations monitored for device_id."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT COUNT(DISTINCT destination) FROM route_metrics WHERE device_id = ?", (device_id,)).fetchone()
            return row[0] if row else 0

    def get_recent_nat_metrics(self, device_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            if device_id:
                rows = conn.execute("SELECT * FROM nat_metrics WHERE device_id = ? ORDER BY id DESC LIMIT ?", (device_id, limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM nat_metrics ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
            return [dict(r) for r in rows]

    def get_device_nat_count(self, device_id: str) -> int:
        """Retrieves count of distinct physical NAT rules monitored for device_id."""
        with self.get_connection() as conn:
            row = conn.execute("SELECT COUNT(DISTINCT rule_id) FROM nat_metrics WHERE device_id = ?", (device_id,)).fetchone()
            return row[0] if row else 0

    def get_recent_bgp_metrics(self, device_id: Optional[str] = None, peer: str = "", limit: int = 100, lookback_minutes: Optional[int] = None) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            if not peer:
                if device_id:
                    rows = conn.execute("SELECT * FROM bgp_metrics WHERE device_id = ? ORDER BY id DESC LIMIT ?", (device_id, limit)).fetchall()
                else:
                    rows = conn.execute("SELECT * FROM bgp_metrics ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
                return [dict(r) for r in rows]

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
            if not neighbor:
                if device_id:
                    rows = conn.execute("SELECT * FROM ospf_metrics WHERE device_id = ? ORDER BY id DESC LIMIT ?", (device_id, limit)).fetchall()
                else:
                    rows = conn.execute("SELECT * FROM ospf_metrics ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
                return [dict(r) for r in rows]

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

    def get_events(
        self,
        limit: int = 100,
        device_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        event_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM events WHERE 1=1"
        params: List[Any] = []
        if device_id:
            query += " AND device_id = ?"
            params.append(device_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if event_type:
            query += " AND type = ?"
            params.append(event_type)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
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
                SELECT * FROM incidents WHERE device_id = ? AND status IN ('OPEN', 'ACKNOWLEDGED', 'INVESTIGATING', 'IDENTIFIED', 'MITIGATING') ORDER BY created_at DESC
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

    def get_incidents(
        self,
        limit: int = 50,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        device_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        query = "SELECT * FROM incidents WHERE 1=1"
        params: List[Any] = []
        if status:
            query += " AND status = ?"
            params.append(status)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if device_id:
            query += " AND device_id = ?"
            params.append(device_id)

        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self.get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
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

    def resolve_incident(self, incident_id: str, summary: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Resolves an open incident, updates status to RESOLVED, and sets updated_at timestamp."""
        from datetime import datetime, timezone
        now_ts = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            inc = self.get_incident_by_id(incident_id)
            if not inc:
                return None
            conn.execute("""
                UPDATE incidents SET status = 'RESOLVED', updated_at = ?, summary = COALESCE(?, summary) WHERE incident_id = ?
            """, (now_ts, summary, incident_id))
            conn.commit()
            return self.get_incident_by_id(incident_id)

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

    # --- PHASE 5 AI ANALYSIS PERSISTENCE & QUERIES ---

    def upsert_ai_analysis(self, record: AIAnalysisRecord) -> None:
        """Persists or updates an AI analysis record in SQLite."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO ai_analyses (
                    analysis_id, incident_id, device_id, created_at, model, prompt_version,
                    status, summary, root_cause_json, impact_json, recommended_checks_json,
                    next_actions_json, full_response_json, confidence, latency_ms, error_message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(analysis_id) DO UPDATE SET
                    status=excluded.status,
                    summary=excluded.summary,
                    root_cause_json=excluded.root_cause_json,
                    impact_json=excluded.impact_json,
                    recommended_checks_json=excluded.recommended_checks_json,
                    next_actions_json=excluded.next_actions_json,
                    full_response_json=excluded.full_response_json,
                    confidence=excluded.confidence,
                    latency_ms=excluded.latency_ms,
                    error_message=excluded.error_message
            """, (
                record.analysis_id, record.incident_id, record.device_id, record.created_at,
                record.model, record.prompt_version, record.status, record.summary,
                json.dumps(record.root_cause_json), json.dumps(record.impact_json),
                json.dumps(record.recommended_checks_json), json.dumps(record.next_actions_json),
                json.dumps(record.full_response_json), record.confidence, record.latency_ms, record.error_message
            ))
            conn.commit()

    def get_ai_analysis_by_incident_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the latest AI RCA analysis record for an incident."""
        with self.get_connection() as conn:
            row = conn.execute("""
                SELECT * FROM ai_analyses WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1
            """, (incident_id,)).fetchone()
            if not row:
                return None
            return self._parse_ai_analysis_row(row)

    def get_ai_analysis_by_device_id(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves the latest AI health analysis record for a device."""
        with self.get_connection() as conn:
            row = conn.execute("""
                SELECT * FROM ai_analyses WHERE device_id = ? ORDER BY created_at DESC LIMIT 1
            """, (device_id,)).fetchone()
            if not row:
                return None
            return self._parse_ai_analysis_row(row)

    def _parse_ai_analysis_row(self, row: sqlite3.Row) -> Dict[str, Any]:
        """Deserializes JSON fields in an ai_analyses row."""
        d = dict(row)
        for json_field in ["root_cause_json", "impact_json", "recommended_checks_json", "next_actions_json", "full_response_json"]:
            if d.get(json_field):
                try:
                    d[json_field] = json.loads(d[json_field])
                except Exception:
                    pass
        return d

    def upsert_investigation(self, inv: Dict[str, Any]) -> None:
        """Upserts a deep NOC investigation record into SQLite database."""
        with self.get_connection() as conn:
            conn.execute("""
                INSERT INTO investigations (
                    investigation_id, incident_id, device_id, created_at, status,
                    primary_failure, secondary_symptoms_json, evidence_json,
                    recommendations_json, visualization_flow_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(investigation_id) DO UPDATE SET
                    status=excluded.status,
                    primary_failure=excluded.primary_failure,
                    secondary_symptoms_json=excluded.secondary_symptoms_json,
                    evidence_json=excluded.evidence_json,
                    recommendations_json=excluded.recommendations_json,
                    visualization_flow_json=excluded.visualization_flow_json
            """, (
                inv["investigation_id"], inv["incident_id"], inv["device_id"], inv["created_at"], inv["status"],
                inv["primary_failure"], json.dumps(inv.get("secondary_symptoms", [])),
                json.dumps(inv.get("evidence", [])), json.dumps(inv.get("recommendations", [])),
                json.dumps(inv.get("visualization_flow", []))
            ))
            conn.commit()

    def get_investigation_by_incident_id(self, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves deep NOC investigation record for an incident."""
        with self.get_connection() as conn:
            row = conn.execute("""
                SELECT * FROM investigations WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1
            """, (incident_id,)).fetchone()
            if not row:
                return None
            d = dict(row)
            for f in ["secondary_symptoms_json", "evidence_json", "recommendations_json", "visualization_flow_json"]:
                if d.get(f):
                    try:
                        d[f] = json.loads(d[f])
                    except Exception:
                        pass
            return d


db = DatabaseManager()
