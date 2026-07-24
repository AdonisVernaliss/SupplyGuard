from collections.abc import Generator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import JSON, DateTime, String, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import get_settings


class Base(DeclarativeBase):
    pass


class AnalysisRecord(Base):
    __tablename__ = "analyses"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True
    )
    filename: Mapped[str] = mapped_column(String(255))
    provider: Mapped[str] = mapped_column(String(32))
    report: Mapped[dict[str, Any]] = mapped_column(JSON)


def _database_url() -> str:
    url = get_settings().database_url
    if url.startswith("sqlite:///"):
        database_path = Path(url.removeprefix("sqlite:///"))
        if database_path.parent != Path("."):
            database_path.parent.mkdir(parents=True, exist_ok=True)
    return url


DATABASE_URL = _database_url()
CONNECT_ARGS = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
ENGINE_OPTIONS: dict[str, Any] = {
    "connect_args": CONNECT_ARGS,
    "pool_pre_ping": True,
}
if DATABASE_URL == "sqlite://":
    ENGINE_OPTIONS["poolclass"] = StaticPool
engine = create_engine(DATABASE_URL, **ENGINE_OPTIONS)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def create_tables() -> None:
    Base.metadata.create_all(bind=engine)


def get_session() -> Generator[Session]:
    with SessionLocal() as session:
        yield session
