"""Application factory.

    uvicorn api_gateway.main:create_app --factory --env-file .env
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pqca_common.db import Database

from api_gateway import __version__
from api_gateway.api.router import api_router
from api_gateway.api.routes import health
from api_gateway.config import Settings, load_settings


def create_app(settings: Settings | None = None, db: Database | None = None) -> FastAPI:
    """Build the app. Tests pass their own settings and database."""
    settings = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Only close a database this app opened itself.
        owns_db = app.state.db is None
        if owns_db:
            app.state.db = Database.from_env()
        try:
            yield
        finally:
            if owns_db:
                await app.state.db.dispose()

    app = FastAPI(
        title="PQ-CA API Gateway",
        version=__version__,
        docs_url="/docs" if settings.docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.docs_enabled else None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.db = db

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.cors_origins,
            allow_methods=settings.cors_allow_methods,
            allow_headers=settings.cors_allow_headers,
            allow_credentials=settings.cors_allow_credentials,
            max_age=settings.cors_max_age_s,
        )

    app.include_router(health.router)
    app.include_router(api_router, prefix=settings.api_prefix)
    return app
