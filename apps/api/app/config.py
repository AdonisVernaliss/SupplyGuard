from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

from app.version import APP_VERSION


class Settings(BaseSettings):
    app_name: str = "SupplyGuard API"
    app_version: str = APP_VERSION
    environment: str = "development"
    database_url: str = "sqlite:///./data/supplyguard.db"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"
    osv_base_url: str = "https://api.osv.dev"
    osv_timeout_seconds: float = 20.0
    max_upload_bytes: int = 5 * 1024 * 1024
    max_scanned_components: int = 200
    max_component_count: int = 10_000
    max_component_depth: int = 100
    max_osv_pages: int = 20
    max_osv_details: int = 1_000

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
