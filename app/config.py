from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration settings for MikroTik NOC Agent with OpenRouter API.
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

    APP_HOST: str = Field(default="0.0.0.0", description="FastAPI host binding")
    APP_PORT: int = Field(default=8000, description="FastAPI port binding")

    def __repr__(self) -> str:
        """Sanitized representation preventing credential and API key logging."""
        return (
            f"Settings(ROUTER1='{self.MIKROTIK_ROUTER1_HOST}', "
            f"ROUTER2='{self.MIKROTIK_ROUTER2_HOST}', "
            f"OPENROUTER_MODEL='{self.OPENROUTER_MODEL}')"
        )


settings = Settings()
