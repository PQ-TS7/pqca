"""Async SQLAlchemy engine on asyncpg."""

from __future__ import annotations

from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from pqca_common.db.settings import DatabaseSettings


def build_url(settings: DatabaseSettings) -> URL:
    # URL.create escapes the password; never build the DSN with string formatting.
    return URL.create(
        "postgresql+asyncpg",
        username=settings.user,
        password=settings.password,
        host=settings.host,
        port=settings.port,
        database=settings.name,
    )


def create_engine(settings: DatabaseSettings) -> AsyncEngine:
    return create_async_engine(
        build_url(settings),
        pool_size=settings.pool_size,
        max_overflow=settings.max_overflow,
        pool_timeout=settings.pool_timeout_s,
        pool_recycle=settings.pool_recycle_s,
        pool_pre_ping=True,
        connect_args={
            "ssl": settings.sslmode,
            "timeout": settings.connect_timeout_s,
            "server_settings": {
                "application_name": settings.app_name,
                "statement_timeout": str(settings.statement_timeout_ms),
                "idle_in_transaction_session_timeout": str(settings.idle_in_transaction_timeout_ms),
            },
        },
    )
