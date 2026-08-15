import time
import json
import logging
import requests
from typing import List, Dict, Any, Optional

from app.config import settings

logger = logging.getLogger("mikrotik_noc_agent.openrouter_client")


class OpenRouterClientError(Exception):
    """Exception raised for OpenRouter API communication or payload errors."""
    pass


def get_openrouter_status() -> Dict[str, Any]:
    """
    Returns OpenRouter client status configuration (without exposing API keys).
    """
    configured = bool(settings.OPENROUTER_API_KEY)
    return {
        "provider": "openrouter",
        "configured": configured,
        "model": settings.OPENROUTER_MODEL,
        "base_url": settings.OPENROUTER_BASE_URL,
        "status": "healthy" if configured else "unconfigured"
    }


def generate_openrouter_completion(
    messages: List[Dict[str, Any]],
    system_prompt: Optional[str] = None,
    json_mode: bool = True,
    temperature: float = 0.1,
    tools: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Sends chat completion request to OpenRouter API endpoint.
    Returns normalized internal response dictionary.
    """
    if not settings.OPENROUTER_API_KEY:
        raise OpenRouterClientError("OPENROUTER_API_KEY environment variable is not configured.")

    url = f"{settings.OPENROUTER_BASE_URL.rstrip('/')}/chat/completions"

    full_messages = []
    if system_prompt:
        full_messages.append({"role": "system", "content": system_prompt})
    full_messages.extend(messages)

    headers = {
        "Authorization": f"Bearer {settings.OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/zawnaing-2024/NOC-AGENT",
        "X-Title": "MikroTik ISP NOC Agent"
    }

    fallback_models = [settings.OPENROUTER_MODEL, "liquid/lfm-2.5-2.6b:free"]
    target_models = []
    for m in fallback_models:
        if m and m not in target_models:
            target_models.append(m)

    last_error = ""
    for model_name in target_models:
        payload: Dict[str, Any] = {
            "model": model_name,
            "messages": full_messages,
            "temperature": temperature,
            "max_tokens": 1500,
        }

        if json_mode and not tools and not model_name.endswith(":free"):
            payload["response_format"] = {"type": "json_object"}

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        logger.info(f"Sending request to OpenRouter API (model={model_name})...")
        t_start = time.perf_counter()

        try:
            resp = requests.post(url, json=payload, headers=headers, timeout=settings.OPENROUTER_TIMEOUT)
            t_end = time.perf_counter()
            latency_ms = int((t_end - t_start) * 1000)

            if resp.status_code == 200:
                res_json = resp.json()
                choices = res_json.get("choices", [])
                if choices:
                    msg = choices[0].get("message", {})
                    content = msg.get("content", "") or ""
                    tool_calls = msg.get("tool_calls", [])
                    usage = res_json.get("usage", {})
                    model_used = res_json.get("model", model_name)

                    logger.info(f"OpenRouter completion successful in {latency_ms}ms (model={model_used}).")
                    return {
                        "success": True,
                        "model": model_used,
                        "content": content,
                        "tool_calls": tool_calls,
                        "usage": usage,
                        "latency_ms": latency_ms,
                        "error": None
                    }

            last_error = f"HTTP {resp.status_code}: {resp.text[:200]}"
            logger.warning(f"OpenRouter model {model_name} failed: {last_error}. Trying fallback...")
        except Exception as ex:
            last_error = f"Request exception: {str(ex)}"
            logger.warning(f"OpenRouter model {model_name} exception: {last_error}. Trying fallback...")

    return {
        "success": False,
        "model": settings.OPENROUTER_MODEL,
        "content": "",
        "tool_calls": [],
        "usage": {},
        "latency_ms": 0,
        "error": last_error
    }
