from unittest.mock import patch
from fastapi.testclient import TestClient
from app.main import app
from app.schemas.network import TokenUsage

client = TestClient(app)


def test_get_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@patch("app.main.run_noc_agent")
def test_agent_chat_endpoint_success(mock_run_agent):
    mock_run_agent.return_value = (
        "OBSERVATION\nInspected system health.\nEVIDENCE\nCPU load is 0%.\nNORMAL CONDITIONS\nMemory usage normal.\nANOMALIES\nNone detected.\nUNCERTAINTIES\nNone.\nPOSSIBLE CAUSES\nN/A\nIMPACT\nNone\nCONFIDENCE\nHigh\nRECOMMENDED NEXT CHECKS\nNone",
        ["get_system_health"],
        TokenUsage(model="meta-llama/llama-3.3-70b-instruct", prompt_tokens=150, completion_tokens=80, total_tokens=230, latency_ms=1200)
    )

    response = client.post("/agent/chat", json={"message": "Check MikroTik health."})
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data
    assert data["tools_used"] == ["get_system_health"]
    assert data["usage"]["total_tokens"] == 230
    assert "OBSERVATION" in data["answer"]


@patch("app.main.run_noc_agent")
def test_agent_chat_endpoint_llm_unavailable(mock_run_agent):
    mock_run_agent.side_effect = Exception("OpenRouter connection timeout")

    response = client.post("/agent/chat", json={"message": "Check health"})
    assert response.status_code == 503
    data = response.json()
    assert data["success"] is False
    assert data["error"]["type"] == "LLM_UNAVAILABLE"
    assert data["error"]["message"] == "OpenRouter LLM is unavailable."
