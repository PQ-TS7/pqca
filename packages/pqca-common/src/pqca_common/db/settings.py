"""Database connection settings, read from the environment.

Every service uses the same variable names; the Kubernetes manifest for each
service points them at that service's own login (gateway_svc, ra_svc, ...).

    PQCA_DB_HOST, PQCA_DB_PORT, PQCA_DB_NAME, PQCA_DB_USER
    PQCA_DB_PASSWORD_FILE   path to a mounted Secret (preferred), or
    PQCA_DB_PASSWORD        the password itself (from secretKeyRef)
    PQCA_DB_SSLMODE         disable | prefer | require | verify-ca | verify-full
    PQCA_DB_APP_NAME        shows up in pg_stat_activity and server logs
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

ENV_PREFIX = "PQCA_DB_"
SSL_MODES = frozenset({"disable", "prefer", "require", "verify-ca", "verify-full"})


class DatabaseConfigError(ValueError):
    """The environment does not describe a usable database connection."""


@dataclass(frozen=True, slots=True)
class DatabaseSettings:
    host: str
    name: str
    user: str
    password: str = field(repr=False)
    port: int = 5432
    sslmode: str = "prefer"
    app_name: str = "pqca"
    pool_size: int = 5
    max_overflow: int = 5
    pool_timeout_s: float = 10.0
    pool_recycle_s: int = 1800
    connect_timeout_s: float = 5.0
    statement_timeout_ms: int = 30_000
    idle_in_transaction_timeout_ms: int = 60_000

    def __post_init__(self) -> None:
        if self.sslmode not in SSL_MODES:
            raise DatabaseConfigError(
                f"{ENV_PREFIX}SSLMODE must be one of {sorted(SSL_MODES)}, got {self.sslmode!r}"
            )

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> DatabaseSettings:
        env = os.environ if env is None else env
        reader = _EnvReader(env)
        return cls(
            host=reader.required("HOST"),
            name=reader.required("NAME"),
            user=reader.required("USER"),
            password=reader.password(),
            port=reader.integer("PORT", 5432),
            sslmode=reader.optional("SSLMODE", "prefer"),
            app_name=reader.optional("APP_NAME", "pqca"),
            pool_size=reader.integer("POOL_SIZE", 5),
            max_overflow=reader.integer("MAX_OVERFLOW", 5),
            pool_timeout_s=reader.number("POOL_TIMEOUT_S", 10.0),
            pool_recycle_s=reader.integer("POOL_RECYCLE_S", 1800),
            connect_timeout_s=reader.number("CONNECT_TIMEOUT_S", 5.0),
            statement_timeout_ms=reader.integer("STATEMENT_TIMEOUT_MS", 30_000),
            idle_in_transaction_timeout_ms=reader.integer("IDLE_IN_TX_TIMEOUT_MS", 60_000),
        )


@dataclass(frozen=True, slots=True)
class _EnvReader:
    env: Mapping[str, str]

    def optional(self, key: str, default: str) -> str:
        return self.env.get(ENV_PREFIX + key, "").strip() or default

    def required(self, key: str) -> str:
        value = self.env.get(ENV_PREFIX + key, "").strip()
        if not value:
            raise DatabaseConfigError(f"{ENV_PREFIX}{key} is not set")
        return value

    def integer(self, key: str, default: int) -> int:
        raw = self.optional(key, str(default))
        try:
            return int(raw)
        except ValueError:
            raise DatabaseConfigError(f"{ENV_PREFIX}{key} must be an integer, got {raw!r}") from None

    def number(self, key: str, default: float) -> float:
        raw = self.optional(key, str(default))
        try:
            return float(raw)
        except ValueError:
            raise DatabaseConfigError(f"{ENV_PREFIX}{key} must be a number, got {raw!r}") from None

    def password(self) -> str:
        # A mounted Secret file wins: it doesn't show up in `kubectl describe pod`
        # or in the process environment.
        path = self.env.get(ENV_PREFIX + "PASSWORD_FILE", "").strip()
        if path:
            try:
                secret = Path(path).read_text(encoding="utf-8").rstrip("\r\n")
            except OSError as exc:
                raise DatabaseConfigError(
                    f"cannot read {ENV_PREFIX}PASSWORD_FILE ({path}): {exc.strerror}"
                ) from None
        else:
            secret = self.env.get(ENV_PREFIX + "PASSWORD", "")
        if not secret:
            raise DatabaseConfigError(f"set {ENV_PREFIX}PASSWORD_FILE or {ENV_PREFIX}PASSWORD")
        return secret
