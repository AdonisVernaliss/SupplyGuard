from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "SupplyGuard API"
    app_version: str = "0.1.0"
    environment: str = "development"
    database_url: str = "sqlite:///./data/supplyguard.db"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    osv_base_url: str = "https://api.osv.dev"
    osv_timeout_seconds: float = 20.0
    max_upload_bytes: int = 5 * 1024 * 1024
    max_scanned_components: int = 200

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SUPPLYGUARD_",
        extra="ignore",
    )

    @property
    def allowed_origins(self) -> list[str]:
        return [origin.strip() for origin in self.cors_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
