"""The versioned REST API, mounted at Settings.api_prefix.

Feature routers (auth, organizations, certificate requests, ...) get included
here as they are written:

    api_router.include_router(organizations.router, prefix="/organizations")
"""

from __future__ import annotations

from fastapi import APIRouter

api_router = APIRouter()
