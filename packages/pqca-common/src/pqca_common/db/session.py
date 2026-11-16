"""Sessions and transactions.

Every unit of work runs inside `Database.transaction()`. It opens one
transaction, commits when the block exits normally and rolls back on any
exception. Don't call `session.commit()` inside the block.

`actor_id` and `client_ip` are stored with set_config(..., is_local => true),
so they last for this transaction only. audit_log() and the audit triggers
read them (004_audit.sql); because they are transaction-local, a pooled
connection never carries one request's actor into the next.
"""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from pqca_common.db.engine import create_engine
from pqca_common.db.settings import DatabaseSettings

_SET_AUDIT_CONTEXT = text(
    "SELECT set_config('pqca.actor_id', :actor_id, true),"
    "       set_config('pqca.client_ip', :client_ip, true)"
)

IpAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class Database:
    def __init__(self, engine: AsyncEngine) -> None:
        self.engine = engine
        self._sessions = async_sessionmaker(engine, expire_on_commit=False)

    @classmethod
    def from_settings(cls, settings: DatabaseSettings) -> Database:
        return cls(create_engine(settings))

    @classmethod
    def from_env(cls) -> Database:
        return cls.from_settings(DatabaseSettings.from_env())

    @asynccontextmanager
    async def transaction(
        self,
        *,
        actor_id: uuid.UUID | None = None,
        client_ip: IpAddress | str | None = None,
    ) -> AsyncIterator[AsyncSession]:
        async with self._sessions() as session, session.begin():
            if actor_id is not None or client_ip is not None:
                await session.execute(
                    _SET_AUDIT_CONTEXT,
                    {"actor_id": _actor_text(actor_id), "client_ip": _ip_text(client_ip)},
                )
            yield session

    async def ping(self) -> None:
        """Raise if the database is unreachable. For readiness probes."""
        async with self.engine.connect() as conn:
            await conn.execute(text("SELECT 1"))

    async def dispose(self) -> None:
        await self.engine.dispose()


def _actor_text(actor_id: uuid.UUID | None) -> str:
    # '' is what audit_log() treats as "no actor" (nullif(..., '')).
    return "" if actor_id is None else str(uuid.UUID(str(actor_id)))


def _ip_text(client_ip: IpAddress | str | None) -> str:
    # Validate here so a bad X-Forwarded-For fails as ValueError, not as a
    # cast error inside a trigger halfway through the transaction.
    return "" if client_ip is None else str(ipaddress.ip_address(client_ip))
