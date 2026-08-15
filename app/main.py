import asyncio
import logging
import time
from contextlib import asynccontextmanager
from typing import Union
from fastapi import FastAPI, status
from fastapi.responses import JSONResponse

from app.config import settings
from app.schemas.network import ChatRequest, ChatResponse, ErrorResponse, ErrorDetail
from app.agent import run_noc_agent
from app.tools.routeros import RouterOSError
from app.db.database import db
from app.collector.service import collector_loop
from app.api.endpoints import router as api_router

# Configure application logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mikrotik_noc_agent.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting MikroTik NOC Engineer Agent API Service (Phase 4 AIOps Architecture)")
    logger.info(f"Target MikroTik Host: {settings.MIKROTIK_HOST}:{settings.MIKROTIK_PORT}")
    logger.info(f"OpenRouter API URL: {settings.OPENROUTER_BASE_URL} (model={settings.OPENROUTER_MODEL})")
    
    # Initialize Phase 4 SQLite Database
    db.init_db()

    # Start Background Telemetry Collector Task
    collector_task = asyncio.create_task(collector_loop())
    logger.info(f"Started AIOps background collector task (interval={settings.COLLECTOR_INTERVAL_SECONDS}s)")
    
    yield
    
    logger.info("Shutting down background telemetry collector...")
    collector_task.cancel()
    try:
        await collector_task
    except asyncio.CancelledError:
        pass
    logger.info("Shutting down MikroTik NOC Engineer Agent API Service")


app = FastAPI(
    title="MikroTik NOC Engineer Agent API",
    description="Production-grade read-only AI NOC Agent with Phase 4 AIOps Telemetry, Baseline Analysis, Event Correlation & Incident Intelligence.",
    version="4.0.0",
    lifespan=lifespan,
)

# Mount Phase 4 Read-Only AIOps REST API endpoints
app.include_router(api_router)


@app.get("/health", status_code=status.HTTP_200_OK)
def health_check():
    """Service health check endpoint."""
    return {"status": "ok"}


@app.post(
    "/agent/chat",
    response_model=Union[ChatResponse, ErrorResponse],
    status_code=status.HTTP_200_OK,
)
def agent_chat(request: ChatRequest):
    """
    Executes the NOC Agent workflow using OpenRouter API with latency profiling metrics.
    """
    start_time = time.time()
    logger.info(f"Received NOC Agent chat request: '{request.message}'")

    try:
        answer, tools_used, usage, profiling = run_noc_agent(request.message)
        duration = round(time.time() - start_time, 2)
        logger.info(
            f"NOC Agent completed request in {duration}s. Tools: {tools_used}, "
            f"Tokens: {usage.total_tokens if usage else 0}"
        )
        return ChatResponse(answer=answer, tools_used=tools_used, usage=usage, profiling=profiling)

    except RouterOSError as e:
        duration = round(time.time() - start_time, 2)
        logger.error(f"RouterOS error during NOC investigation ({duration}s): {e}")
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=ErrorResponse(
                success=False,
                error=ErrorDetail(
                    type="ROUTER_COMMUNICATION_ERROR",
                    message=f"Unable to inspect MikroTik router: {str(e)}",
                ),
            ).model_dump(),
        )

    except Exception as e:
        duration = round(time.time() - start_time, 2)
        err_msg = str(e)
        logger.error(f"Error in OpenRouter agent execution ({duration}s): {err_msg}")
        
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=ErrorResponse(
                success=False,
                error=ErrorDetail(
                    type="LLM_UNAVAILABLE",
                    message="OpenRouter LLM is unavailable.",
                ),
            ).model_dump(),
        )
