from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration settings for MikroTik NOC Agent with OpenRouter API and Phase 4 AIOps.
    Supports single or multi-router environments.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # Primary Router Default Settings
    MIKROTIK_HOST: str = Field(default="192.168.88.1", description="MikroTik Router IP address")
    MIKROTIK_PORT: int = Field(default=8728, description="MikroTik RouterOS API Port")
    MIKROTIK_USERNAME: str = Field(default="admin", description="MikroTik username")
    MIKROTIK_PASSWORD: str = Field(default="", description="MikroTik password")

    # Multi-Router Environment Settings: Router 1
    MIKROTIK_ROUTER1_HOST: str = Field(default="", description="MikroTik Router 1 IP address")
    MIKROTIK_ROUTER1_PORT: int = Field(default=8728, description="MikroTik Router 1 API Port")
    MIKROTIK_ROUTER1_USERNAME: str = Field(default="", description="MikroTik Router 1 username")
    MIKROTIK_ROUTER1_PASSWORD: str = Field(default="", description="MikroTik Router 1 password")

    # Multi-Router Environment Settings: Router 2
    MIKROTIK_ROUTER2_HOST: str = Field(default="", description="MikroTik Router 2 IP address")
    MIKROTIK_ROUTER2_PORT: int = Field(default=8728, description="MikroTik Router 2 API Port")
    MIKROTIK_ROUTER2_USERNAME: str = Field(default="", description="MikroTik Router 2 username")
    MIKROTIK_ROUTER2_PASSWORD: str = Field(default="", description="MikroTik Router 2 password")

    # OpenRouter API settings
    OPENROUTER_API_KEY: str = Field(default="", description="OpenRouter API Key")
    OPENROUTER_BASE_URL: str = Field(default="https://openrouter.ai/api/v1", description="OpenRouter API Base URL")
    OPENROUTER_MODEL: str = Field(default="meta-llama/llama-3.3-70b-instruct", description="Configurable OpenRouter model identifier")
    OPENROUTER_TIMEOUT: int = Field(default=30, description="OpenRouter API request timeout in seconds")
    OPENROUTER_MAX_RETRIES: int = Field(default=2, description="Maximum retries for transient OpenRouter API errors")

    # Phase 4 AIOps Collector, Database, and Correlation Settings
    DATABASE_PATH: str = Field(default="data/noc_agent.db", description="Path to SQLite historical database")
    COLLECTOR_INTERVAL_SECONDS: int = Field(default=60, description="Background telemetry collection interval in seconds")
    CORRELATION_WINDOW_SECONDS: int = Field(default=300, description="Correlation window for grouping related events into an incident (default 5 min)")

    # Phase 4.4 Time-Aware Lookback Windows and Baseline Threshold Configuration
    ANOMALY_LOOKBACK_MINUTES: int = Field(default=15, description="Lookback window in minutes for system, interface, and route metrics")
    BGP_LOOKBACK_MINUTES: int = Field(default=30, description="Lookback window in minutes for BGP peer metrics")
    MIN_BASELINE_SAMPLES: int = Field(default=10, description="Minimum baseline samples required for baseline anomaly rules")
    TRAFFIC_DROP_PERCENT: float = Field(default=70.0, description="Traffic drop percentage threshold (default 70%)")
    TRAFFIC_SPIKE_THRESHOLD_PERCENT: float = Field(default=200.0, description="Traffic spike percentage threshold over baseline (default 200% = 3x baseline)")
    MIN_BASELINE_BPS: float = Field(default=10000.0, description="Minimum baseline bps threshold to prevent false positives on low-traffic interfaces (default 10 Kbps)")
    PERSISTENCE_SAMPLES: int = Field(default=3, description="Consecutive low samples required to trigger TRAFFIC_DROP (default 3 samples)")
    METRIC_RETENTION_HOURS: int = Field(default=168, description="Historical metric data retention window in hours (default 168h = 7 days)")

    APP_HOST: str = Field(default="0.0.0.0", description="FastAPI host binding")
    APP_PORT: int = Field(default=8000, description="FastAPI port binding")

    def __repr__(self) -> str:
        """Sanitized representation preventing credential and API key logging."""
        return (
            f"Settings(ROUTER1='{self.MIKROTIK_ROUTER1_HOST}', "
            f"ROUTER2='{self.MIKROTIK_ROUTER2_HOST}', "
            f"OPENROUTER_MODEL='{self.OPENROUTER_MODEL}', "
            f"COLLECTOR_INTERVAL={self.COLLECTOR_INTERVAL_SECONDS}s)"
        )


settings = Settings()
