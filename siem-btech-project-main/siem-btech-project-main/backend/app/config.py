from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

BASE_DIR = Path(__file__).resolve().parents[1]


class Settings(BaseSettings):
    app_name: str = "siem-chat-backend"
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    frontend_origin: str = "http://127.0.0.1:3000"
    log_level: str = "INFO"
    gemini_api_key: str | None = Field(default=None, alias="GEMINI_API_KEY")
    database_url: str = Field(alias="DATABASE_URL")

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
