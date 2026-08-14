import logging
import time
from typing import Any, Dict, Optional
from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.outputs import LLMResult
from langchain_openai import ChatOpenAI

from app.config import settings
from app.schemas.network import TokenUsage

logger = logging.getLogger("mikrotik_noc_agent.llm")


class OpenRouterTokenCallback(BaseCallbackHandler):
    """Callback handler recording OpenRouter prompt tokens, completion tokens, total tokens, and latency."""

    def __init__(self):
        super().__init__()
        self.start_time: float = 0.0
        self.latency_ms: int = 0
        self.model: str = ""
        self.prompt_tokens: int = 0
        self.completion_tokens: int = 0
        self.total_tokens: int = 0

    def on_llm_start(self, serialized: Dict[str, Any], prompts: list[str], **kwargs: Any) -> None:
        self.start_time = time.time()

    def on_llm_end(self, response: LLMResult, **kwargs: Any) -> None:
        if self.start_time > 0:
            self.latency_ms = int((time.time() - self.start_time) * 1000)

        if response.llm_output and isinstance(response.llm_output, dict):
            token_usage = response.llm_output.get("token_usage", {})
            self.prompt_tokens = token_usage.get("prompt_tokens", 0)
            self.completion_tokens = token_usage.get("completion_tokens", 0)
            self.total_tokens = token_usage.get("total_tokens", 0)
            self.model = response.llm_output.get("model_name", settings.OPENROUTER_MODEL)
            logger.info(
                f"OpenRouter LLM Usage: model={self.model}, prompt_tokens={self.prompt_tokens}, "
                f"completion_tokens={self.completion_tokens}, total_tokens={self.total_tokens}, "
                f"latency={self.latency_ms}ms"
            )

    def get_token_usage(self) -> TokenUsage:
        return TokenUsage(
            model=self.model or settings.OPENROUTER_MODEL,
            prompt_tokens=self.prompt_tokens,
            completion_tokens=self.completion_tokens,
            total_tokens=self.total_tokens,
            latency_ms=self.latency_ms,
        )


def get_llm(callbacks: Optional[list] = None) -> ChatOpenAI:
    """
    Initializes and returns a LangChain ChatOpenAI client connected exclusively to OpenRouter API.
    Enforces configured timeouts, max retries, headers, and temperature=0.0.
    """
    logger.info(
        f"Initializing OpenRouter client at {settings.OPENROUTER_BASE_URL} "
        f"(model={settings.OPENROUTER_MODEL}, timeout={settings.OPENROUTER_TIMEOUT}s, "
        f"max_retries={settings.OPENROUTER_MAX_RETRIES})"
    )

    headers = {
        "HTTP-Referer": "https://github.com/mikrotik-noc-agent",
        "X-Title": "MikroTik NOC Agent",
    }

    return ChatOpenAI(
        base_url=settings.OPENROUTER_BASE_URL,
        api_key=settings.OPENROUTER_API_KEY,
        model=settings.OPENROUTER_MODEL,
        temperature=0.0,
        streaming=False,
        request_timeout=settings.OPENROUTER_TIMEOUT,
        max_retries=settings.OPENROUTER_MAX_RETRIES,
        default_headers=headers,
        callbacks=callbacks or [],
    )
