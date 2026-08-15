import uuid
import time
import json
import logging
from typing import Dict, Any, Optional, List

from app.config import settings
from app.db.database import db
from app.db.schemas import AIAnalysisRecord
from app.ai.prompts import NOC_SYSTEM_PROMPT
from app.ai.schemas import AIIncidentAnalysisResponse
from app.ai.context_builder import ContextBuilder
from app.ai.openrouter_client import generate_openrouter_completion, get_openrouter_status, OpenRouterClientError

logger = logging.getLogger("mikrotik_noc_agent.ai_agent")


class AIAgentService:
    """AI NOC Engineer Agent service executing OpenRouter API analysis, validation, and persistence."""

    @staticmethod
    def analyze_incident(incident_id: str) -> Dict[str, Any]:
        """
        Executes AI-assisted RCA on a correlated incident using OpenRouter API.
        Validates response, grounds facts in evidence, persists result, and returns structured result.
        """
        analysis_id = str(uuid.uuid4())
        logger.info(f"OPENROUTER_AI_REQUEST_STARTED analysis_id={analysis_id} incident_id={incident_id}")

        try:
            context = ContextBuilder.build_incident_context(incident_id)
        except Exception as e:
            logger.error(f"Failed to build incident context for {incident_id}: {e}")
            return {"success": False, "error": f"Incident not found: {str(e)}"}

        # Phase 6.3 Grounding Guardrail
        auth_failed = (context.get("routeros_authenticated") is False or 
                       context.get("evidence_completeness") == "INCOMPLETE" or 
                       context.get("routeros_status") == "FAILED")
        
        grounding_notice = ""
        if auth_failed:
            grounding_notice = """\nCRITICAL GROUNDING MANDATE:
RouterOS evidence collection failed. Do not infer or fabricate device state, physical media type, optical telemetry, or ping reachability.
You MUST set root_cause.description to 'INSUFFICIENT_EVIDENCE' and confidence to 'LOW'.
Summary MUST explicitly state: 'The traffic level is significantly below historical baseline, but RouterOS authentication failed during investigation. Physical media type, interface state, IP configuration and connectivity could not be verified.'\n"""

        prompt = f"""Please perform Root Cause Analysis (RCA) on the following NOC incident based strictly on the provided evidence payload:
{grounding_notice}
EVIDENCE & TIMELINE PAYLOAD:
{json.dumps(context, indent=2)}

Ensure your response is valid JSON matching this exact structure:
{{
  "summary": "High-level incident analysis summary",
  "root_cause": {{
    "description": "Technical description of primary root cause grounded in evidence",
    "confidence": "HIGH"
  }},
  "impact": {{
    "description": "Description of network operational impact",
    "scope": "INTERFACE"
  }},
  "evidence": [
    {{"fact": "Factual statement referencing exact evidence payload value", "source": "event"}}
  ],
  "hypotheses": [
    {{"description": "Correlated analytical hypothesis", "confidence": "MEDIUM"}}
  ],
  "recommended_actions": [
    {{"step": 1, "action": "Actionable troubleshooting step", "reason": "Technical rationale"}}
  ],
  "verification_steps": [
    "Verification check statement"
  ],
  "customer_impact": "UNKNOWN"
}}
"""

        messages = [{"role": "user", "content": prompt}]
        res = generate_openrouter_completion(
            messages=messages,
            system_prompt=NOC_SYSTEM_PROMPT,
            json_mode=True
        )

        if not res["success"]:
            err_msg = str(res.get("error", "Unknown OpenRouter API error"))
            logger.warning(f"OpenRouter API analysis failed for incident {incident_id}: {err_msg}")
            rec = AIAnalysisRecord(
                analysis_id=analysis_id,
                incident_id=incident_id,
                device_id=context["incident"]["device_id"],
                model=settings.OPENROUTER_MODEL,
                prompt_version=settings.PROMPT_VERSION,
                status="AI_UNAVAILABLE",
                summary=f"OpenRouter AI request failed: {err_msg}",
                error_message=err_msg
            )
            db.upsert_ai_analysis(rec)
            return {
                "success": False,
                "analysis_id": analysis_id,
                "incident_id": incident_id,
                "status": "AI_UNAVAILABLE",
                "summary": f"OpenRouter API Error: {err_msg}",
                "error": "AI_PROVIDER_UNAVAILABLE",
                "details": err_msg
            }

        # Validate JSON Response with Pydantic AIIncidentAnalysisResponse
        raw_content = res["content"]
        try:
            validated_resp = AIIncidentAnalysisResponse.model_validate_json(raw_content)
        except Exception as parse_err:
            logger.warning(f"OpenRouter JSON validation failure: {parse_err}. Attempting correction retry...")
            retry_messages = messages + [
                {"role": "assistant", "content": raw_content},
                {"role": "user", "content": f"Your previous output was invalid JSON ({parse_err}). Return ONLY valid JSON matching the requested schema."}
            ]
            retry_res = generate_openrouter_completion(
                messages=retry_messages,
                system_prompt=NOC_SYSTEM_PROMPT,
                json_mode=True
            )
            if retry_res["success"]:
                try:
                    raw_content = retry_res["content"]
                    validated_resp = AIIncidentAnalysisResponse.model_validate_json(raw_content)
                except Exception as retry_parse_err:
                    logger.error(f"OpenRouter JSON validation failed after retry: {retry_parse_err}")
                    return {"success": False, "error": f"Invalid JSON returned: {retry_parse_err}"}
            else:
                return {"success": False, "error": "AI_PROVIDER_UNAVAILABLE"}

        # Persist Result to SQLite
        rec = AIAnalysisRecord(
            analysis_id=analysis_id,
            incident_id=incident_id,
            device_id=context["incident"]["device_id"],
            model=res["model"],
            prompt_version=settings.PROMPT_VERSION,
            status="COMPLETED",
            summary=validated_resp.summary,
            root_cause_json=validated_resp.root_cause.model_dump(),
            impact_json=validated_resp.impact.model_dump(),
            recommended_checks_json=[a.model_dump() for a in validated_resp.recommended_actions],
            next_actions_json=[{"verification": v} for v in validated_resp.verification_steps],
            full_response_json=validated_resp.model_dump(),
            confidence=validated_resp.root_cause.confidence,
            latency_ms=res["latency_ms"]
        )
        db.upsert_ai_analysis(rec)
        logger.info(f"OPENROUTER_AI_REQUEST_COMPLETED analysis_id={analysis_id} incident_id={incident_id}")

        return {
            "success": True,
            "analysis_id": analysis_id,
            "incident_id": incident_id,
            "model": res["model"],
            "latency_ms": res["latency_ms"],
            "analysis": validated_resp.model_dump()
        }

    @staticmethod
    def get_incident_analyses(incident_id: str) -> List[Dict[str, Any]]:
        """Retrieves history of AI analyses for an incident."""
        with db.get_connection() as conn:
            rows = conn.execute("SELECT * FROM ai_analyses WHERE incident_id = ? ORDER BY created_at DESC", (incident_id,)).fetchall()
            return [db._parse_ai_analysis_row(r) for r in rows]

    @staticmethod
    def get_analysis_by_id(analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single AI analysis record by analysis_id."""
        with db.get_connection() as conn:
            row = conn.execute("SELECT * FROM ai_analyses WHERE analysis_id = ?", (analysis_id,)).fetchone()
            return db._parse_ai_analysis_row(row) if row else None
