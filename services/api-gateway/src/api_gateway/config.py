"""Gateway settings, read from PQCA_GATEWAY_* environment variables.

Database connection settings are not here: they are read by
pqca_common.db.DatabaseSettings from PQCA_DB_* (one place, shared by every
service). Secrets never belong in this class; they come from Kubernetes
Secrets as env vars or mounted files.

    PQCA_GATEWAY_ENVIRONMENT            dev | test | prod              (default dev)
    PQCA_GATEWAY_ENABLE_DOCS            true | false                   (default: on unless prod)
    PQCA_GATEWAY_API_PREFIX             URL prefix of the REST API     (default /api/v1)
    PQCA_GATEWAY_CORS_ALLOW_ORIGINS     comma-separated or JSON list   (see below)
    PQCA_GATEWAY_CORS_ALLOW_METHODS     comma-separated or JSON list
    PQCA_GATEWAY_CORS_ALLOW_HEADERS     comma-separated or JSON list
    PQCA_GATEWAY_CORS_ALLOW_CREDENTIALS true | false                   (default false)
    PQCA_GATEWAY_CORS_MAX_AGE_S         preflight cache, seconds       (default 600)

CORS defaults: the SPA is served by Nginx on the same origin as the API, so
no cross-origin access is allowed unless you list origins. The one exception
is ENVIRONMENT=dev with the variable unset, which allows the usual local
frontend dev servers (DEV_CORS_ORIGINS).
"""

from __future__ import annotations

import json
import re
from functools import lru_cache
from typing import Annotated, Literal, Self

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Vite and Create React App / Next.js default dev-server ports.
DEV_CORS_ORIGINS = ("http://localhost:3000", "http://localhost:5173")

# An origin is scheme://host[:port], with no path and no trailing slash.
_ORIGIN = re.compile(r"^https?://[^/\s]+$")

CommaList = Annotated[list[str], NoDecode]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PQCA_GATEWAY_", frozen=True)

    environment: Literal["dev", "test", "prod"] = "dev"
    enable_docs: bool | None = None
    api_prefix: str = "/api/v1"

    cors_allow_origins: CommaList = Field(default_factory=list)
    cors_allow_methods: CommaList = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "PATCH", "DELETE"]
    )
    cors_allow_headers: CommaList = Field(
        default_factory=lambda: ["Authorization", "Content-Type"]
    )
    cors_allow_credentials: bool = False
    cors_max_age_s: int = Field(default=600, ge=0)

    @field_validator("cors_allow_origins", "cors_allow_methods", "cors_allow_headers", mode="before")
    @classmethod
    def _split_list(cls, value: object) -> object:
        # Accept "a,b" as well as '["a","b"]'.
        if not isinstance(value, str):
            return value
        text = value.strip()
        if text.startswith("["):
            return json.loads(text)
        return [item.strip() for item in text.split(",") if item.strip()]

    @field_validator("cors_allow_origins")
    @classmethod
    def _check_origins(cls, origins: list[str]) -> list[str]:
        for origin in origins:
            if origin != "*" and not _ORIGIN.match(origin):
                raise ValueError(
                    f"{origin!r} is not a valid origin: use scheme://host[:port] "
                    "with no path and no trailing slash"
                )
        return origins

    @field_validator("api_prefix")
    @classmethod
    def _check_prefix(cls, prefix: str) -> str:
        if prefix and (not prefix.startswith("/") or prefix.endswith("/")):
            raise ValueError("api_prefix must start with '/' and not end with '/'")
        return prefix

    @model_validator(mode="after")
    def _check_cors(self) -> Self:
        wildcard = "*" in self.cors_allow_origins
        if wildcard and self.cors_allow_credentials:
            raise ValueError("CORS: '*' cannot be combined with allow_credentials; list origins")
        if wildcard and self.environment == "prod":
            raise ValueError("CORS: '*' is not allowed when environment is prod; list origins")
        return self

    @property
    def cors_origins(self) -> list[str]:
        """Origins to allow, after applying the dev default."""
        if "cors_allow_origins" in self.model_fields_set:
            return list(self.cors_allow_origins)
        return list(DEV_CORS_ORIGINS) if self.environment == "dev" else []

    @property
    def docs_enabled(self) -> bool:
        if self.enable_docs is not None:
            return self.enable_docs
        return self.environment != "prod"


@lru_cache
def load_settings() -> Settings:
    return Settings()
