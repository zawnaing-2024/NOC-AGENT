# MikroTik NOC Engineer Agent — Pure OpenRouter Architecture

A production-grade, strict **READ-ONLY** Network Operations Center (NOC) AI Agent designed to inspect MikroTik RouterOS devices using controlled RouterOS API tools and analyze network evidence via remote LLM models through **OpenRouter API**.

---

## 1. Architecture

```
               MikroTik Router
                     │
              RouterOS API (Port 8728)
                     │
                     ▼
          Python RouterOS Client
                     │
                     ▼
          Python Evidence Engine
    (Compact Summary / Two-Stage Filtering)
                     │
                     ▼
             LangGraph Agent
                     │
                     ▼
           OpenRouter API Client
        (Retries + Timeouts + Cost Tracking)
                     │
                     ▼
         Configurable OpenRouter LLM
       (via OPENROUTER_MODEL env var)
                     │
                     ▼
          NOC Report Output
```

### Security Boundaries
- **Strict Read-Only Enforcement**: The LLM NEVER receives router credentials, raw connection objects, or arbitrary command execution privileges.
- **Controlled Tool Layer**: The LLM can ONLY request explicitly registered read-only Pydantic tools (`get_system_health`, `get_interfaces`, `get_bgp_peers`).
- **No Credential Exposure**: Passwords, secrets, and OpenRouter API keys are stripped from log files and error responses.

---

## 2. Requirements

- **Docker Desktop** (or Docker Engine 24.0+)
- **OpenRouter API Key** (`OPENROUTER_API_KEY`)
- **MikroTik RouterOS** device (physical, CHR, or VM) with API service enabled on port `8728` (`/ip service enable api`)

---

## 3. Environment Configuration (`.env`)

Copy `.env.example` to `.env` and fill in your configuration:

```bash
cp .env.example .env
```

Example `.env`:
```env
OPENROUTER_API_KEY=sk-or-v1-your-key-here
OPENROUTER_MODEL=meta-llama/llama-3.3-70b-instruct
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_TIMEOUT=30
OPENROUTER_MAX_RETRIES=2

MIKROTIK_HOST=37.111.52.51
MIKROTIK_PORT=8728
MIKROTIK_USERNAME=noc
MIKROTIK_PASSWORD=NOC@2026

APP_HOST=0.0.0.0
APP_PORT=8000
```

> [!TIP]
> You can benchmark or switch LLM models anytime by updating `OPENROUTER_MODEL` in `.env` (e.g. `meta-llama/llama-3.3-70b-instruct`, `openai/gpt-4o-mini`, `google/gemini-2.0-flash-001`, `qwen/qwen-2.5-72b-instruct`) without changing any Python source code!

---

## 4. Deterministic Interface Classification Rules

To prevent false-positive incidents:
- `disabled=true` → `DISABLED` (Admin disabled; no fault inferred)
- `disabled=false` + `running=false` → `DOWN` (Fault; investigate link)
- `running=true` + `errors > 0` → `ERROR` (Fault; framing/CRC error)
- `running=true` + `no errors` → `ACTIVE` (Healthy)

---

## 5. Running the Application via Docker

Build the Docker image:
```bash
docker build -t mikrotik-noc-agent .
```

Run the container:
```bash
docker run -d \
  --name noc-agent \
  -p 8000:8000 \
  --env-file .env \
  mikrotik-noc-agent
```

Verify service status:
```bash
curl http://localhost:8000/health
# Response: {"status":"ok"}
```

---

## 6. Running Unit & API Tests

Run tests inside Docker without requiring a physical router (uses mocked RouterOS API responses):

```bash
docker run --rm mikrotik-noc-agent pytest -v
```

---

## 7. Example API Requests & NOC Investigations

### Request: Check Router Health & Interface State

```bash
curl -X POST http://localhost:8000/agent/chat \
  -H "Content-Type: application/json" \
  -d '{"message": "Check MikroTik router health and interface state."}'
```

### Response Example:
```json
{
  "answer": "OBSERVATION\nThe health and interface state of the MikroTik router were checked using read-only tools.\n\nEVIDENCE\n- Identity: R2_MGKBN-CW-CGNAT01\n- RouterOS: 7.7 (stable)\n- Uptime: 1 week, 1 hour\n- CPU Load: 0%, Memory Usage: 2.48%\n- Interfaces Summary: 20 Total, 11 Active, 0 Disabled, 9 Down, 0 Errors\n\nNORMAL CONDITIONS\n- CPU and memory utilization are well within normal operating thresholds.\n- 11 active interfaces are operating without errors.\n\nANOMALIES\n- 9 interfaces (ether2-ether6, ether8, ether10, ether12) are in DOWN state.\n\nUNCERTAINTIES\n- Physical cable status for DOWN interfaces is unverified.\n\nPOSSIBLE CAUSES\n- Cables disconnected or link partners powered off on DOWN interfaces.\n\nIMPACT\n- Traffic routes normally over active SFP+ fibers and PPPoE interfaces.\n\nCONFIDENCE\nHigh - Retrieved directly via RouterOS API.\n\nRECOMMENDED NEXT CHECKS\nVerify physical layer cabling on down interfaces.",
  "tools_used": [
    "get_system_health",
    "get_interfaces"
  ],
  "usage": {
    "model": "meta-llama/llama-3.3-70b-instruct",
    "prompt_tokens": 420,
    "completion_tokens": 210,
    "total_tokens": 630,
    "latency_ms": 1450
  }
}
```

---

## 8. Security & Cost Protection

1. **Read-Only Scope**: The agent cannot execute commands, modify configurations, change IP addresses, or reboot devices.
2. **Zero Credential Exposure**: Passwords and API keys are kept strictly within backend `.env` variables and NEVER sent to OpenRouter or included in API error responses.
3. **Structured Fallback**: If OpenRouter is unavailable or times out, FastAPI remains operational and returns `{ "success": false, "error_type": "LLM_UNAVAILABLE", "message": "OpenRouter LLM is unavailable." }`.
