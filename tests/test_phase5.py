import json
import pytest
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

from app.main import app
from app.db.database import db
from app.db.schemas import EventRecord, IncidentRecord, AIAnalysisRecord, AIAnalysisResponse
from app.services.evidence_builder import EvidenceBuilder
from app.services.llm_client import check_lm_studio_health, generate_lm_studio_completion, LMStudioClientError
from app.services.ai_analyzer import AINocAnalyzer

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_db():
    db.init_db()
    with db.get_connection() as conn:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM incidents")
        conn.execute("DELETE FROM ai_analyses")
        conn.execute("DELETE FROM device_metrics")
        conn.execute("DELETE FROM interface_metrics")
        conn.commit()
    yield


# Mock LM Studio Response
VALID_LM_STUDIO_RCA_JSON = json.dumps({
    "incident_id": "inc-test-123",
    "assessment": {
        "summary": "Traffic on sfp-sfpplus1 has dropped significantly from historical baseline.",
        "confidence": "HIGH"
    },
    "root_cause": {
        "category": "TRAFFIC_ANOMALY",
        "finding": "Traffic drop of 98.6% observed on sfp-sfpplus1 compared to historical moving average.",
        "confidence": "HIGH",
        "evidence": ["current_bps=4144", "moving_average_bps=296061.82", "drop_percentage=98.6"]
    },
    "impact": {
        "severity": "MAJOR",
        "description": "Substantial traffic reduction on sfp-sfpplus1.",
        "affected_device": "103.59.163.7",
        "affected_entity": "sfp-sfpplus1"
    },
    "contributing_factors": [
        {"factor": "Link operational change", "evidence": "Interface link state change observed"}
    ],
    "recommended_checks": [
        {"priority": 1, "check": "Verify interface operational state", "reason": "Inspect link state", "command": "/interface print detail"}
    ],
    "next_actions": [
        {"priority": 1, "action": "Inspect upstream link connectivity", "reason": "Traffic is 98.6% below baseline"}
    ],
    "customer_impact": {
        "status": "UNKNOWN",
        "description": "Customer impact cannot be confirmed from available evidence."
    },
    "limitations": [
        "Supplied evidence does not prove physical fiber cable failure."
    ]
})


def test_lm_studio_health_check_healthy():
    """Test LM Studio health check when LM Studio API is available."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"data": [{"id": "llama-3-8b"}]}

    with patch("requests.get", return_value=mock_resp):
        res = check_lm_studio_health()
        assert res["status"] == "healthy"
        assert res["provider"] == "lm_studio"
        assert res["model"] == "llama-3-8b"
        assert res["latency_ms"] >= 0


def test_lm_studio_health_check_unavailable():
    """Test LM Studio health check when LM Studio API is unreachable."""
    with patch("requests.get", side_effect=Exception("Connection refused")):
        res = check_lm_studio_health()
        assert res["status"] == "unavailable"
        assert "Connection refused" in res["error"]


def test_evidence_builder_incident():
    """Test EvidenceBuilder.build_incident_evidence correctly collects deterministic evidence."""
    db.upsert_active_event(EventRecord(
        event_id="evt-root-1",
        device_id="103.59.163.7",
        type="TRAFFIC_DROP",
        severity="MAJOR",
        entity="sfp-sfpplus1",
        evidence={"drop_percentage": 98.6, "current_bps": 4144},
        fingerprint="103.59.163.7:TRAFFIC_DROP:sfp-sfpplus1"
    ))
    db.upsert_incident(IncidentRecord(
        incident_id="inc-test-123",
        device_id="103.59.163.7",
        severity="MAJOR",
        status="OPEN",
        root_event_id="evt-root-1",
        correlated_event_ids=["evt-root-1"]
    ))

    evidence = EvidenceBuilder.build_incident_evidence("inc-test-123")
    assert evidence["incident"]["incident_id"] == "inc-test-123"
    assert evidence["root_event"]["type"] == "TRAFFIC_DROP"
    assert evidence["root_event"]["entity"] == "sfp-sfpplus1"
    assert "deterministic_findings" in evidence


def test_ai_incident_analysis_success():
    """Test AINocAnalyzer.analyze_incident executes RCA, validates Pydantic JSON, and persists result."""
    db.upsert_active_event(EventRecord(
        event_id="evt-root-1",
        device_id="103.59.163.7",
        type="TRAFFIC_DROP",
        severity="MAJOR",
        entity="sfp-sfpplus1",
        evidence={"drop_percentage": 98.6},
        fingerprint="103.59.163.7:TRAFFIC_DROP:sfp-sfpplus1"
    ))
    db.upsert_incident(IncidentRecord(
        incident_id="inc-test-123",
        device_id="103.59.163.7",
        severity="MAJOR",
        status="OPEN",
        root_event_id="evt-root-1",
        correlated_event_ids=["evt-root-1"]
    ))

    with patch("app.services.ai_analyzer.generate_lm_studio_completion", return_value=(VALID_LM_STUDIO_RCA_JSON, 120, "local-model")):
        res = AINocAnalyzer.analyze_incident("inc-test-123")
        assert res["status"] == "COMPLETED"
        assert res["analysis"]["root_cause"]["category"] == "TRAFFIC_ANOMALY"
        assert res["analysis"]["customer_impact"]["status"] == "UNKNOWN"

        # Verify SQLite Persistence
        saved = db.get_ai_analysis_by_incident_id("inc-test-123")
        assert saved is not None
        assert saved["status"] == "COMPLETED"
        assert saved["summary"] == "Traffic on sfp-sfpplus1 has dropped significantly from historical baseline."


def test_ai_incident_analysis_json_retry():
    """Test AINocAnalyzer retries upon receiving initial invalid JSON."""
    db.upsert_active_event(EventRecord(
        event_id="evt-root-1",
        device_id="103.59.163.7",
        type="INTERFACE_DOWN",
        severity="MAJOR",
        entity="sfp-sfpplus1",
        fingerprint="103.59.163.7:INTERFACE_DOWN:sfp-sfpplus1"
    ))
    db.upsert_incident(IncidentRecord(
        incident_id="inc-test-456",
        device_id="103.59.163.7",
        severity="MAJOR",
        status="OPEN",
        root_event_id="evt-root-1",
        correlated_event_ids=["evt-root-1"]
    ))

    invalid_json = "{ invalid json content }"
    mock_completions = [
        (invalid_json, 100, "local-model"),
        (VALID_LM_STUDIO_RCA_JSON, 150, "local-model")
    ]

    with patch("app.services.ai_analyzer.generate_lm_studio_completion", side_effect=mock_completions):
        res = AINocAnalyzer.analyze_incident("inc-test-456")
        assert res["status"] == "COMPLETED"
        assert res["analysis"]["root_cause"]["category"] == "TRAFFIC_ANOMALY"


def test_ai_incident_analysis_unavailable():
    """Test AINocAnalyzer handles LM Studio service unavailability gracefully."""
    db.upsert_active_event(EventRecord(
        event_id="evt-root-1",
        device_id="103.59.163.7",
        type="INTERFACE_DOWN",
        severity="MAJOR",
        entity="sfp-sfpplus1",
        fingerprint="103.59.163.7:INTERFACE_DOWN:sfp-sfpplus1"
    ))
    db.upsert_incident(IncidentRecord(
        incident_id="inc-test-789",
        device_id="103.59.163.7",
        severity="MAJOR",
        status="OPEN",
        root_event_id="evt-root-1",
        correlated_event_ids=["evt-root-1"]
    ))

    with patch("app.services.ai_analyzer.generate_lm_studio_completion", side_effect=LMStudioClientError("LM Studio offline")):
        res = AINocAnalyzer.analyze_incident("inc-test-789")
        assert res["status"] == "AI_UNAVAILABLE"
        assert "LM Studio offline" in res["error"]

        saved = db.get_ai_analysis_by_incident_id("inc-test-789")
        assert saved["status"] == "AI_UNAVAILABLE"


def test_ai_analysis_api_endpoints():
    """Integration test for Phase 5 REST endpoints."""
    # 1. Health Endpoint
    mock_health = {"status": "healthy", "provider": "lm_studio", "model": "local-model", "latency_ms": 15}
    with patch("app.api.endpoints.check_lm_studio_health", return_value=mock_health):
        response = client.get("/api/ai/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"

    # 2. Analyze Incident 404 test
    response = client.post("/api/ai/incidents/nonexistent-id/analyze")
    assert response.status_code == 404

    # 3. Analyze Incident Success
    db.upsert_active_event(EventRecord(
        event_id="evt-root-api",
        device_id="103.59.163.7",
        type="CPU_SPIKE",
        severity="MAJOR",
        entity="system",
        fingerprint="103.59.163.7:CPU_SPIKE:system"
    ))
    db.upsert_incident(IncidentRecord(
        incident_id="inc-api-101",
        device_id="103.59.163.7",
        severity="MAJOR",
        status="OPEN",
        root_event_id="evt-root-api",
        correlated_event_ids=["evt-root-api"]
    ))

    with patch("app.services.ai_analyzer.generate_lm_studio_completion", return_value=(VALID_LM_STUDIO_RCA_JSON, 90, "local-model")):
        response = client.post("/api/ai/incidents/inc-api-101/analyze")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "COMPLETED"

        # 4. Get Incident AI Analysis
        get_resp = client.get("/api/ai/incidents/inc-api-101")
        assert get_resp.status_code == 200
        assert get_resp.json()["analysis_status"] == "COMPLETED"
