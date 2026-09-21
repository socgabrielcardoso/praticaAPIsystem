from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "praticaAPIsystem"
    app_version: str = "1.0.0"
    user_agent: str = "praticaAPIsystem/1.0 defensive-enrichment"

    virustotal_api_key: SecretStr | None = None
    abuseipdb_api_key: SecretStr | None = None
    urlhaus_auth_key: SecretStr | None = None
    nvd_api_key: SecretStr | None = None

    request_timeout_seconds: float = Field(default=12.0, ge=2.0, le=60.0)
    retry_attempts: int = Field(default=2, ge=0, le=5)
    cache_ttl_seconds: int = Field(default=300, ge=0, le=86400)
    max_batch_size: int = Field(default=25, ge=1, le=100)
    log_level: str = "INFO"


@lru_cache
def get_settings() -> Settings:
    return Settings()
