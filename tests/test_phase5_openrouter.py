import json
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import db
from app.db.schemas import EventRecord, IncidentRecord
from app.ai.openrouter_client import get_openrouter_status, generate_openrouter_completion
from app.ai.context_builder import ContextBuilder
from app.tools.noc_tools import execute_noc_tool, READONLY_NOC_TOOLS_SCHEMA
from app.ai.agent import AIAgentService

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    db.init_db()
    with db.get_connection() as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM incidents")
        conn.execute("DELETE FROM ai_analyses")
        conn.commit()
    yield


VALID_OPENROUTER_RCA_JSON = json.dumps({
    "summary": "Traffic on sfp-sfpplus1 has dropped significantly from historical baseline.",
    "root_cause": {
        "description": "Traffic drop of 98.6% observed on sfp-sfpplus1 compared to historical moving average.",
        "confidence": "HIGH"
    },
    "impact": {
        "description": "Substantial traffic reduction on sfp-sfpplus1.",
        "scope": "INTERFACE"
    },
    "evidence": [
        {"fact": "current_bps=4144", "source": "metric"},
        {"fact": "moving_average_bps=296061.82", "source": "metric"}
    ],
    "hypotheses": [
        {"description": "Interface link degradation or upstream traffic shift", "confidence": "MEDIUM"}
    ],
    "recommended_actions": [
        {"step": 1, "action": "Verify interface operational state", "reason": "Inspect link state"}
    ],
    "verification_steps": [
        "Verify /interface print detail output"
    ],
    "customer_impact": "UNKNOWN"
})


def test_openrouter_status_endpoint():
    """Test GET /api/ai/status returns OpenRouter provider configuration."""
    response = client.get("/api/ai/status")
    assert response.status_code == 200
    data = response.json()
    assert data["provider"] == "openrouter"
    assert "model" in data


def test_readonly_noc_tools_security():
    """Test read-only NOC tool execution enforces security and prohibits write commands."""
    # Test valid read-only execution
    res = execute_noc_tool("get_database_status", {})
    assert "exists" in res

    # Test prohibited tool execution
    res_err = execute_noc_tool("reboot_router", {})
    assert "error" in res_err


def test_context_builder_timeline_and_priority():
    """Test ContextBuilder ranks evidence and constructs timeline correctly."""
    db.upsert_active_event(EventRecord(
        event_id="evt-timeline-1",
        device_id="103.59.163.7",
        type="INTERFACE_DOWN",
        severity="MAJOR",
        entity="sfp-sfpplus1",
        fingerprint="103.59.163.7:INTERFACE_DOWN:sfp-sfpplus1"
    ))
    db.upsert_incident(IncidentRecord(
        incident_id="inc-context-101",
        device_id="103.59.163.7",
        severity="MAJOR",
        status="OPEN",
        root_event_id="evt-timeline-1",
        correlated_event_ids=["evt-timeline-1"]
    ))

    context = ContextBuilder.build_incident_context("inc-context-101")
    assert context["incident"]["incident_id"] == "inc-context-101"
    assert context["root_cause_candidate"]["priority_rank"] == 2
    assert len(context["timeline"]) == 1


def test_openrouter_ai_incident_analysis_mocked():
    """Test AIAgentService.analyze_incident using mocked OpenRouter API response."""
    db.upsert_active_event(EventRecord(
        event_id="evt-root-or",
        device_id="103.59.163.7",
        type="TRAFFIC_DROP",
        severity="MAJOR",
        entity="sfp-sfpplus1",
        fingerprint="103.59.163.7:TRAFFIC_DROP:sfp-sfpplus1"
    ))
    db.upsert_incident(IncidentRecord(
        incident_id="inc-openrouter-202",
        device_id="103.59.163.7",
        severity="MAJOR",
        status="OPEN",
        root_event_id="evt-root-or",
        correlated_event_ids=["evt-root-or"]
    ))

    mock_openrouter_res = {
        "success": True,
        "model": "meta-llama/llama-3.3-70b-instruct",
        "content": VALID_OPENROUTER_RCA_JSON,
        "latency_ms": 210,
        "error": None
    }

    with patch("app.ai.agent.generate_openrouter_completion", return_value=mock_openrouter_res):
        res = AIAgentService.analyze_incident("inc-openrouter-202")
        assert res["success"] is True
        assert res["analysis"]["root_cause"]["confidence"] == "HIGH"

        # Verify SQLite Persistence
        analyses = AIAgentService.get_incident_analyses("inc-openrouter-202")
        assert len(analyses) >= 1
        assert analyses[0]["status"] == "COMPLETED"


def test_openrouter_failure_handling():
    """Test AIAgentService returns graceful AI_PROVIDER_UNAVAILABLE when OpenRouter is down."""
    db.upsert_active_event(EventRecord(
        event_id="evt-root-or",
        device_id="103.59.163.7",
        type="CPU_SPIKE",
        severity="MAJOR",
        entity="system",
        fingerprint="103.59.163.7:CPU_SPIKE:system"
    ))
    db.upsert_incident(IncidentRecord(
        incident_id="inc-fail-303",
        device_id="103.59.163.7",
        severity="MAJOR",
        status="OPEN",
        root_event_id="evt-root-or",
        correlated_event_ids=["evt-root-or"]
    ))

    mock_fail = {
        "success": False,
        "model": "meta-llama/llama-3.3-70b-instruct",
        "content": "",
        "latency_ms": 0,
        "error": "OpenRouter API connection timeout"
    }

    with patch("app.ai.agent.generate_openrouter_completion", return_value=mock_fail):
        res = AIAgentService.analyze_incident("inc-fail-303")
        assert res["success"] is False
        assert res["error"] == "AI_PROVIDER_UNAVAILABLE"

        analyses = AIAgentService.get_incident_analyses("inc-fail-303")
        assert len(analyses) >= 1
        assert analyses[0]["status"] == "AI_UNAVAILABLE"
