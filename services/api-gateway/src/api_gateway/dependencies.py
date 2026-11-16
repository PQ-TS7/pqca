"""FastAPI dependencies. State is set once in create_app()."""

from __future__ import annotations

from fastapi import Request
from pqca_common.db import Database

from api_gateway.config import Settings


def get_settings(request: Request) -> Settings:
    return request.app.state.settings


def get_db(request: Request) -> Database:
    return request.app.state.db
