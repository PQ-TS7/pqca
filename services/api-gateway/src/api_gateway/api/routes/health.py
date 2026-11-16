"""Probe endpoints for Kubernetes. Unversioned and unauthenticated."""

from __future__ import annotations

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from pqca_common.db import Database

from api_gateway.dependencies import get_db

logger = logging.getLogger(__name__)

router = APIRouter(tags=["health"])


@router.get("/healthz")
async def liveness() -> dict[str, str]:
    """The process is up. Never touches the database, so a DB outage can't restart the pod."""
    return {"status": "ok"}


@router.get("/readyz")
async def readiness(db: Annotated[Database, Depends(get_db)]) -> dict[str, str]:
    """The pod can serve traffic: the database answers."""
    try:
        await db.ping()
    except Exception:
        # Any failure (refused connection, timeout, auth) means "not ready".
        logger.exception("readiness check failed")
        raise HTTPException(status_code=503, detail="database unavailable") from None
    return {"status": "ready"}
