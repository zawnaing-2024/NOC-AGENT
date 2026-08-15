import time
import json
import logging
import requests
from typing import List, Dict, Any, Tuple, Optional

from app.config import settings

logger = logging.getLogger("mikrotik_noc_agent.llm_client")


class LMStudioClientError(Exception):
    """Exception raised for LM Studio client communication or payload validation errors."""
    pass


def check_lm_studio_health() -> Dict[str, Any]:
    """
    Performs health check against LM Studio OpenAI-compatible API endpoint GET /v1/models.
    Returns provider status, active model, and response latency in milliseconds.
    """
    url = f"{settings.LM_STUDIO_BASE_URL.rstrip('/')}/models"
    t_start = time.perf_counter()
    try:
        resp = requests.get(url, timeout=5)
        t_end = time.perf_counter()
        latency_ms = int((t_end - t_start) * 1000)

        if resp.status_code == 200:
            data = resp.json()
            models = data.get("data", [])
            model_id = models[0]["id"] if models else settings.LM_STUDIO_MODEL
            return {
                "status": "healthy",
                "provider": "lm_studio",
                "base_url": settings.LM_STUDIO_BASE_URL,
                "model": model_id,
                "latency_ms": latency_ms
            }
        else:
            return {
                "status": "unavailable",
                "provider": "lm_studio",
                "base_url": settings.LM_STUDIO_BASE_URL,
                "error": f"HTTP {resp.status_code}: {resp.text[:100]}"
            }
    except Exception as e:
        logger.warning(f"LM Studio health check failed at {url}: {e}")
        return {
            "status": "unavailable",
            "provider": "lm_studio",
            "base_url": settings.LM_STUDIO_BASE_URL,
            "error": str(e)
        }


def generate_lm_studio_completion(
    messages: List[Dict[str, str]],
    system_prompt: Optional[str] = None,
    json_mode: bool = True,
    temperature: float = 0.1,
) -> Tuple[str, int, str]:
    """
    Sends chat completion request to local LM Studio OpenAI-compatible POST /v1/chat/completions.
    Returns (response_text, latency_ms, model_used).
    """
    url = f"{settings.LM_STUDIO_BASE_URL.rstrip('/')}/chat/completions"

    full_messages = []
    if system_prompt:
        full_messages.append({"role": "system", "content": system_prompt})
    full_messages.extend(messages)

    payload = {
        "model": settings.LM_STUDIO_MODEL,
        "messages": full_messages,
        "temperature": temperature,
        "max_tokens": 1500,
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}

    headers = {"Content-Type": "application/json"}

    logger.info(f"Sending request to LM Studio at {url} (model={settings.LM_STUDIO_MODEL})...")
    t_start = time.perf_counter()

    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=settings.LM_STUDIO_TIMEOUT)
        t_end = time.perf_counter()
        latency_ms = int((t_end - t_start) * 1000)

        if resp.status_code != 200:
            raise LMStudioClientError(f"LM Studio API returned HTTP {resp.status_code}: {resp.text[:200]}")

        res_json = resp.json()
        model_used = res_json.get("model", settings.LM_STUDIO_MODEL)
        choices = res_json.get("choices", [])
        if not choices:
            raise LMStudioClientError("LM Studio returned empty choices in response payload.")

        content = choices[0]["message"]["content"]
        logger.info(f"Received LM Studio completion in {latency_ms}ms (model={model_used}).")
        return content, latency_ms, model_used

    except requests.exceptions.RequestException as e:
        logger.error(f"LM Studio communication error: {e}")
        raise LMStudioClientError(f"LM Studio unavailable: {e}")
