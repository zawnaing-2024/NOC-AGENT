import uuid
import json
import logging
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone

from langchain_core.messages import SystemMessage, HumanMessage

from app.config import settings
from app.db.database import db
from app.db.schemas import EventRecord, IncidentRecord, AlertRecord, current_utc_timestamp
from app.llm import get_llm, OpenRouterTokenCallback

logger = logging.getLogger("mikrotik_noc_agent.correlation")

# Deterministic Root Cause Priority Hierarchy (lower index = higher root priority)
ROOT_CAUSE_HIERARCHY = [
    "INTERFACE_DOWN",
    "NAT_DEPENDENCY_DOWN",
    "BGP_SESSION_DOWN",
    "OSPF_NEIGHBOR_DOWN",
    "DEFAULT_ROUTE_DOWN",
    "BGP_PREFIX_DROP",
    "TRAFFIC_DROP",
    "CPU_SPIKE",
    "MEMORY_SPIKE",
]


def determine_root_event(events: List[EventRecord]) -> EventRecord:
    """Deterministically selects root event from event list using priority hierarchy."""
    if not events:
        raise ValueError("Cannot determine root event from empty list")

    best_event = events[0]
    best_priority = 999

    for e in events:
        p = 999
        if e.type in ROOT_CAUSE_HIERARCHY:
            p = ROOT_CAUSE_HIERARCHY.index(e.type)
        if p < best_priority:
            best_priority = p
            best_event = e

    return best_event


def calculate_incident_severity(events: List[EventRecord]) -> str:
    """Calculates overall incident severity from event list."""
    severities = [e.severity for e in events]
    if "CRITICAL" in severities:
        return "CRITICAL"
    if "MAJOR" in severities:
        return "MAJOR"
    if "MINOR" in severities:
        return "MINOR"
    if "WARNING" in severities:
        return "WARNING"
    return "INFO"


def generate_llm_incident_summary(incident: IncidentRecord, root_event: EventRecord, correlated_events: List[EventRecord]) -> Tuple[str, str]:
    """
    Executes SINGLE OpenRouter LLM call to summarize incident deterministically.
    Rule 9: LLM receives immutable deterministic facts and MUST NOT alter numerical facts or counts.
    Returns (summary_text, llm_status: 'SUCCESS' or 'FAILED').
    """
    try:
        token_callback = OpenRouterTokenCallback()
        llm = get_llm(callbacks=[token_callback], max_tokens=300)

        prompt_payload = {
            "incident_id": incident.incident_id,
            "device_id": incident.device_id,
            "severity": incident.severity,
            "status": incident.status,
            "event_count": incident.event_count,
            "occurrence_count": incident.occurrence_count,
            "facts": incident.facts,
            "root_cause_event": root_event.model_dump(),
            "correlated_events": [e.model_dump() for e in correlated_events],
        }

        sys_prompt = (
            "You are an ISP NOC AIOps engineer.\n"
            "Summarize the correlated network incident based ONLY on supplied deterministic evidence and immutable facts.\n"
            "Do not invent topology, event counts, occurrence counts, timestamps, or severity.\n"
            "Explain the root cause and impact in 2-3 concise bullet points."
        )

        messages = [
            SystemMessage(content=sys_prompt),
            HumanMessage(content=f"Deterministic Incident Evidence:\n{json.dumps(prompt_payload, indent=2)}"),
        ]

        logger.info(f"Generating LLM summary for incident {incident.incident_id}...")
        response = llm.invoke(messages)
        summary_text = response.content if hasattr(response, "content") else str(response)
        return summary_text, "SUCCESS"
    except Exception as e:
        logger.error(f"OpenRouter LLM incident summary generation failed: {e}")
        fallback_summary = (
            f"Incident {incident.incident_id} for {incident.device_id}. "
            f"Root Cause: {root_event.type} on {root_event.entity}. "
            f"Distinct Event Types: {incident.event_count}, Cumulative Occurrences: {incident.occurrence_count}."
        )
        return fallback_summary, "FAILED"


class CorrelationEngine:
    """Correlates events, manages incidents, performs in-place deduplication, and handles recovery."""

    @staticmethod
    def process_events(events: List[EventRecord]) -> Optional[str]:
        if not events:
            return None

        last_inc_id = None
        for event in events:
            # 1. Check if recovery event
            if "RECOVERED" in event.type:
                CorrelationEngine._handle_recovery_event(event)
                continue

            # 2. Upsert active event in DB (in-place deduplication: updates last_seen & occurrence_count)
            actual_event_id = db.upsert_active_event(event)
            if isinstance(actual_event_id, str):
                event.event_id = actual_event_id

            # 3. Correlate active event into Incident
            inc_id = CorrelationEngine._correlate_anomaly_event(event)
            if inc_id:
                last_inc_id = inc_id

        return last_inc_id

    @staticmethod
    def _handle_recovery_event(recovery_event: EventRecord) -> None:
        """Handles recovery event by marking corresponding active event RECOVERED and incident RESOLVED."""
        device_id = recovery_event.device_id
        entity = recovery_event.entity
        base_type = recovery_event.type.replace("_RECOVERED", "_DOWN").replace("_RECOVERED", "_DROP")

        # Mark matching active events as RESOLVED in database
        with db.get_connection() as conn:
            conn.execute(
                "UPDATE events SET status = 'RESOLVED' WHERE device_id = ? AND type = ? AND status IN ('ACTIVE', 'OPEN')",
                (device_id, base_type)
            )

        open_inc = db.get_open_incident_by_fingerprint(device_id, f"{device_id}:{base_type}:{entity}")

        if open_inc:
            logger.info(f"Recovery event {recovery_event.type} detected for {entity}. Resolving incident {open_inc['incident_id']}...")
            facts = json.loads(open_inc["facts"]) if isinstance(open_inc.get("facts"), str) else open_inc.get("facts", {})
            facts["resolved_at"] = current_utc_timestamp()

            inc_record = IncidentRecord(
                incident_id=open_inc["incident_id"],
                device_id=open_inc["device_id"],
                created_at=open_inc["created_at"],
                updated_at=current_utc_timestamp(),
                severity=open_inc["severity"],
                status="RESOLVED",
                root_event_id=open_inc["root_event_id"],
                correlated_event_ids=json.loads(open_inc["correlated_event_ids"]) if isinstance(open_inc["correlated_event_ids"], str) else open_inc["correlated_event_ids"],
                event_count=open_inc.get("event_count", 1),
                occurrence_count=open_inc.get("occurrence_count", 1),
                confidence=open_inc["confidence"],
                facts=facts,
                summary=(open_inc.get("summary") or "") + "\n\n[RECOVERY DETECTED]: Fault recovered naturally. Incident RESOLVED.",
                llm_status=open_inc["llm_status"]
            )
            db.upsert_incident(inc_record)

    @staticmethod
    def _correlate_anomaly_event(event: EventRecord) -> str:
        """Correlates active anomaly event into existing open incident within correlation window or creates new incident."""
        device_id = event.device_id
        open_incidents = db.get_incidents(limit=10, status="OPEN")
        matching_inc = None

        # Check for open incident within 5-minute correlation window for same device
        for inc in open_incidents:
            if inc["device_id"] == device_id:
                matching_inc = inc
                break

        if matching_inc:
            corr_ids = matching_inc.get("correlated_event_ids", [])
            if isinstance(corr_ids, str):
                corr_ids = json.loads(corr_ids)
            
            if event.event_id not in corr_ids:
                corr_ids.append(event.event_id)

            # Retrieve full event objects
            event_objs: List[EventRecord] = []
            cum_occurrences = 0
            for eid in corr_ids:
                edata = db.get_event_by_id(eid)
                if edata:
                    e_rec = EventRecord(**edata)
                    event_objs.append(e_rec)
                    cum_occurrences += e_rec.occurrence_count

            root_e = determine_root_event(event_objs)
            sev = calculate_incident_severity(event_objs)

            facts = {
                "device_id": device_id,
                "entity": root_e.entity,
                "event_type": root_e.type,
                "severity": sev,
                "occurrence_count": cum_occurrences,
                "first_seen": root_e.first_seen,
                "last_seen": root_e.last_seen,
                "evidence": root_e.evidence
            }

            inc_obj = IncidentRecord(
                incident_id=matching_inc["incident_id"],
                device_id=device_id,
                created_at=matching_inc["created_at"],
                updated_at=current_utc_timestamp(),
                severity=sev,
                status="OPEN",
                root_event_id=root_e.event_id,
                correlated_event_ids=corr_ids,
                event_count=len(corr_ids),
                occurrence_count=cum_occurrences,
                confidence="HIGH",
                facts=facts,
                summary=matching_inc.get("summary"),
                llm_status=matching_inc.get("llm_status", "SUCCESS")
            )

            # Update LLM explanation
            summary, llm_status = generate_llm_incident_summary(inc_obj, root_e, event_objs)
            inc_obj.summary = summary
            inc_obj.llm_status = llm_status

            db.upsert_incident(inc_obj)
            logger.info(f"Correlated active event {event.type} ({event.entity}) into existing incident {inc_obj.incident_id} (Occurrences={cum_occurrences}).")
            return inc_obj.incident_id
        else:
            # Create new Incident
            inc_id = str(uuid.uuid4())
            event_objs = [event]
            sev = calculate_incident_severity(event_objs)

            facts = {
                "device_id": device_id,
                "entity": event.entity,
                "event_type": event.type,
                "severity": sev,
                "occurrence_count": event.occurrence_count,
                "first_seen": event.first_seen,
                "last_seen": event.last_seen,
                "evidence": event.evidence
            }

            inc_obj = IncidentRecord(
                incident_id=inc_id,
                device_id=device_id,
                created_at=current_utc_timestamp(),
                updated_at=current_utc_timestamp(),
                severity=sev,
                status="OPEN",
                root_event_id=event.event_id,
                correlated_event_ids=[event.event_id],
                event_count=1,
                occurrence_count=event.occurrence_count,
                confidence="HIGH",
                facts=facts,
                summary=None,
                llm_status="SUCCESS"
            )

            summary, llm_status = generate_llm_incident_summary(inc_obj, event, event_objs)
            inc_obj.summary = summary
            inc_obj.llm_status = llm_status

            db.upsert_incident(inc_obj)

            # Create Alert entry
            alert_rec = AlertRecord(
                alert_id=str(uuid.uuid4()),
                incident_id=inc_id,
                device_id=device_id,
                timestamp=current_utc_timestamp(),
                type=event.type,
                status="OPEN",
                message=f"Alert: {event.type} on {event.entity} ({sev})"
            )
            with db.get_connection() as conn:
                conn.execute("""
                    INSERT INTO alerts (alert_id, incident_id, device_id, timestamp, type, status, message)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (alert_rec.alert_id, alert_rec.incident_id, alert_rec.device_id, alert_rec.timestamp, alert_rec.type, alert_rec.status, alert_rec.message))
                conn.commit()

            logger.info(f"Created new incident {inc_id} for device {device_id} (Root: {event.type} on {event.entity}).")
            return inc_id
