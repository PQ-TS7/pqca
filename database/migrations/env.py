"""Alembic environment for the PQ-CA database.

The schema is owned by SQL (database/init/ and the migrations in versions/).
There are no ORM models to compare against, so `alembic revision --autogenerate`
is deliberately unavailable (target_metadata is None): write each migration by
hand with op.execute(...).

Connection settings come from the same PQCA_DB_* variables the services use
(pqca_common.db.DatabaseSettings), but migrations must run as the schema
owner (e.g. `postgres` in dev). The service logins (gateway_svc, ...) have no
CREATE or ALTER rights and will be refused.
"""

from __future__ import annotations

import asyncio
from logging.config import fileConfig

from alembic import context
from pqca_common.db import DatabaseSettings, build_url
from sqlalchemy import pool
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = None


def run_migrations_offline() -> None:
    """`alembic upgrade head --sql`: print the SQL instead of running it. Needs no database."""
    context.configure(
        dialect_name="postgresql",
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def _create_engine() -> AsyncEngine:
    settings = DatabaseSettings.from_env()
    # Not pqca_common.db.create_engine(): its 30 s statement_timeout and pooling
    # suit request handlers, not a migration that may rebuild a big table.
    return create_async_engine(
        build_url(settings),
        poolclass=pool.NullPool,
        connect_args={
            "ssl": settings.sslmode,
            "timeout": settings.connect_timeout_s,
            "server_settings": {"application_name": "pqca-alembic"},
        },
    )


def _run_migrations(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    engine = _create_engine()
    async with engine.connect() as connection:
        await connection.run_sync(_run_migrations)
    await engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
