import uuid
import time
import json
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timezone

from app.config import settings
from app.db.database import db
from app.db.schemas import AIAnalysisRecord, AIAnalysisResponse
from app.services.evidence_builder import EvidenceBuilder, EvidenceBuilderError
from app.services.llm_client import generate_lm_studio_completion, LMStudioClientError

logger = logging.getLogger("mikrotik_noc_agent.ai_analyzer")

SYSTEM_PROMPT = """You are an ISP NOC senior network engineer assistant.
You analyze MikroTik RouterOS network telemetry.
You must ONLY use facts provided in the evidence payload.

Never invent telemetry, interfaces, routes, BGP peers, IP addresses, traffic values, CPU/RAM values, configuration, or device state.
If evidence is insufficient to prove a root cause, explicitly set status to INSUFFICIENT_EVIDENCE or confidence to LOW.
You distinguish confirmed facts from hypotheses.

You must NEVER execute commands or perform configuration changes.
You may recommend read-only RouterOS diagnostic commands (e.g. /interface print detail, /routing/bgp/session/print detail).

Return ONLY valid JSON matching the requested schema. Never return Markdown blocks or conversational prose outside the JSON object.
"""


def format_evidence_prompt_for_incident(evidence: Dict[str, Any]) -> str:
    """Formats incident evidence payload into structured prompt text."""
    return f"""Please perform Root Cause Analysis (RCA) on the following NOC incident based strictly on the provided evidence:

EVIDENCE PAYLOAD:
{json.dumps(evidence, indent=2)}

Ensure your response is valid JSON matching this exact structure:
{{
  "incident_id": "{evidence['incident']['incident_id']}",
  "assessment": {{
    "summary": "High-level summary of operational issue",
    "confidence": "HIGH"
  }},
  "root_cause": {{
    "category": "Category name (e.g. TRAFFIC_ANOMALY, INTERFACE_DOWN)",
    "finding": "Specific root cause finding grounded in evidence",
    "confidence": "HIGH",
    "evidence": ["Statement 1 referencing exact evidence values", "Statement 2"]
  }},
  "impact": {{
    "severity": "CRITICAL|MAJOR|WARNING|INFO",
    "description": "Operational impact description",
    "affected_device": "{evidence['incident']['device_id']}",
    "affected_entity": "{evidence['root_event']['entity']}"
  }},
  "contributing_factors": [
    {{
      "factor": "Contributing factor description",
      "evidence": "Supporting evidence statement"
    }}
  ],
  "recommended_checks": [
    {{
      "priority": 1,
      "check": "Description of diagnostic check to perform",
      "reason": "Technical rationale for the check",
      "command": "/read-only-routeros-command"
    }}
  ],
  "next_actions": [
    {{
      "priority": 1,
      "action": "Actionable troubleshooting recommendation",
      "reason": "Technical rationale for action"
    }}
  ],
  "customer_impact": {{
    "status": "UNKNOWN|NONE|POSSIBLE|LIKELY|CONFIRMED",
    "description": "Customer impact assessment description"
  }},
  "limitations": [
    "Limitation statement if evidence cannot prove physical hardware failure"
  ]
}}
"""


def format_evidence_prompt_for_device(evidence: Dict[str, Any]) -> str:
    """Formats device health evidence payload into structured prompt text."""
    return f"""Please perform a comprehensive NOC health and risk assessment for device '{evidence['device'].get('device_id')}' based strictly on the provided evidence:

EVIDENCE PAYLOAD:
{json.dumps(evidence, indent=2)}

Return valid JSON matching the requested schema with device_id='{evidence['device'].get('device_id')}'.
"""


class AINocAnalyzer:
    """AI NOC Intelligence & RCA Analyzer service using local LM Studio OpenAI-compatible API."""

    @staticmethod
    def analyze_incident(incident_id: str) -> Dict[str, Any]:
        """
        Gathers deterministic evidence for an incident, queries LM Studio for RCA, validates JSON response,
        persists result in SQLite ai_analyses table, and returns structured result.
        """
        analysis_id = str(uuid.uuid4())
        logger.info(f"AI_REQUEST_STARTED analysis_id={analysis_id} incident_id={incident_id}")
        t_start = time.perf_counter()

        try:
            evidence = EvidenceBuilder.build_incident_evidence(incident_id)
        except EvidenceBuilderError as e:
            logger.error(f"Evidence building failed for incident {incident_id}: {e}")
            return {
                "analysis_id": analysis_id,
                "incident_id": incident_id,
                "status": "FAILED",
                "error": str(e)
            }

        prompt = format_evidence_prompt_for_incident(evidence)
        messages = [{"role": "user", "content": prompt}]

        raw_content = ""
        latency_ms = 0
        model_used = settings.LM_STUDIO_MODEL

        try:
            raw_content, latency_ms, model_used = generate_lm_studio_completion(
                messages=messages,
                system_prompt=SYSTEM_PROMPT,
                json_mode=True
            )
        except LMStudioClientError as e:
            logger.warning(f"LM Studio API unavailable for incident {incident_id}: {e}")
            rec = AIAnalysisRecord(
                analysis_id=analysis_id,
                incident_id=incident_id,
                device_id=evidence["incident"]["device_id"],
                model=settings.LM_STUDIO_MODEL,
                prompt_version=settings.PROMPT_VERSION,
                status="AI_UNAVAILABLE",
                summary="LM Studio AI service is currently unavailable.",
                error_message=str(e)
            )
            db.upsert_ai_analysis(rec)
            return {
                "analysis_id": analysis_id,
                "incident_id": incident_id,
                "status": "AI_UNAVAILABLE",
                "error": str(e)
            }

        # Validate JSON response using Pydantic AIAnalysisResponse
        validated_resp: Optional[AIAnalysisResponse] = None
        try:
            validated_resp = AIAnalysisResponse.model_validate_json(raw_content)
        except Exception as parse_err:
            logger.warning(f"JSON validation failure on first attempt: {parse_err}. Attempting correction retry...")
            retry_messages = messages + [
                {"role": "assistant", "content": raw_content},
                {"role": "user", "content": f"Your previous output was invalid JSON ({parse_err}). Please return ONLY valid JSON matching the exact schema."}
            ]
            try:
                retry_content, retry_latency, model_used = generate_lm_studio_completion(
                    messages=retry_messages,
                    system_prompt=SYSTEM_PROMPT,
                    json_mode=True
                )
                latency_ms += retry_latency
                raw_content = retry_content
                validated_resp = AIAnalysisResponse.model_validate_json(retry_content)
            except Exception as retry_err:
                logger.error(f"JSON validation failed after retry: {retry_err}")
                rec = AIAnalysisRecord(
                    analysis_id=analysis_id,
                    incident_id=incident_id,
                    device_id=evidence["incident"]["device_id"],
                    model=model_used,
                    prompt_version=settings.PROMPT_VERSION,
                    status="FAILED",
                    summary="AI analysis failed JSON validation.",
                    error_message=str(retry_err)
                )
                db.upsert_ai_analysis(rec)
                return {
                    "analysis_id": analysis_id,
                    "incident_id": incident_id,
                    "status": "FAILED",
                    "error": f"Invalid JSON returned by LM Studio: {retry_err}"
                }

        # Persist Analysis Result
        rec = AIAnalysisRecord(
            analysis_id=analysis_id,
            incident_id=incident_id,
            device_id=evidence["incident"]["device_id"],
            model=model_used,
            prompt_version=settings.PROMPT_VERSION,
            status="COMPLETED",
            summary=validated_resp.assessment.summary,
            root_cause_json=validated_resp.root_cause.model_dump(),
            impact_json=validated_resp.impact.model_dump(),
            recommended_checks_json=[c.model_dump() for c in validated_resp.recommended_checks],
            next_actions_json=[a.model_dump() for a in validated_resp.next_actions],
            full_response_json=validated_resp.model_dump(),
            confidence=validated_resp.assessment.confidence,
            latency_ms=latency_ms
        )
        db.upsert_ai_analysis(rec)
        logger.info(f"AI_REQUEST_COMPLETED analysis_id={analysis_id} incident_id={incident_id} latency_ms={latency_ms}")

        return {
            "analysis_id": analysis_id,
            "incident_id": incident_id,
            "status": "COMPLETED",
            "latency_ms": latency_ms,
            "model": model_used,
            "prompt_version": settings.PROMPT_VERSION,
            "analysis": validated_resp.model_dump()
        }

    @staticmethod
    def analyze_device(device_id: str) -> Dict[str, Any]:
        """
        Gathers device health evidence, queries LM Studio, validates response, and persists AI device health analysis.
        """
        analysis_id = str(uuid.uuid4())
        logger.info(f"AI_DEVICE_REQUEST_STARTED analysis_id={analysis_id} device_id={device_id}")

        evidence = EvidenceBuilder.build_device_evidence(device_id)
        prompt = format_evidence_prompt_for_device(evidence)
        messages = [{"role": "user", "content": prompt}]

        try:
            raw_content, latency_ms, model_used = generate_lm_studio_completion(
                messages=messages,
                system_prompt=SYSTEM_PROMPT,
                json_mode=True
            )
            validated_resp = AIAnalysisResponse.model_validate_json(raw_content)
            rec = AIAnalysisRecord(
                analysis_id=analysis_id,
                device_id=device_id,
                model=model_used,
                prompt_version=settings.PROMPT_VERSION,
                status="COMPLETED",
                summary=validated_resp.assessment.summary,
                root_cause_json=validated_resp.root_cause.model_dump(),
                impact_json=validated_resp.impact.model_dump(),
                recommended_checks_json=[c.model_dump() for c in validated_resp.recommended_checks],
                next_actions_json=[a.model_dump() for a in validated_resp.next_actions],
                full_response_json=validated_resp.model_dump(),
                confidence=validated_resp.assessment.confidence,
                latency_ms=latency_ms
            )
            db.upsert_ai_analysis(rec)
            return {
                "analysis_id": analysis_id,
                "device_id": device_id,
                "status": "COMPLETED",
                "latency_ms": latency_ms,
                "model": model_used,
                "analysis": validated_resp.model_dump()
            }
        except Exception as e:
            logger.warning(f"Device AI analysis failed for {device_id}: {e}")
            return {
                "analysis_id": analysis_id,
                "device_id": device_id,
                "status": "AI_UNAVAILABLE",
                "error": str(e)
            }
