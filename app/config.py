from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Application configuration settings for MikroTik NOC Agent with OpenRouter API.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    MIKROTIK_HOST: str = Field(default="192.168.88.1", description="MikroTik Router IP address")
    MIKROTIK_PORT: int = Field(default=8728, description="MikroTik RouterOS API Port")
    MIKROTIK_USERNAME: str = Field(default="admin", description="MikroTik username")
    MIKROTIK_PASSWORD: str = Field(default="", description="MikroTik password")

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
            f"Settings(MIKROTIK_HOST='{self.MIKROTIK_HOST}', "
            f"MIKROTIK_PORT={self.MIKROTIK_PORT}, "
            f"OPENROUTER_MODEL='{self.OPENROUTER_MODEL}', "
            f"OPENROUTER_TIMEOUT={self.OPENROUTER_TIMEOUT})"
        )


settings = Settings()
