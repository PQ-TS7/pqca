from __future__ import annotations

import uuid

from sqlalchemy import text
from sqlalchemy.orm import Session


def reserve_serial(
    session: Session, request_id: uuid.UUID, issuer_ca_id: uuid.UUID) -> bytes:
    
    result = session.execute(
        text("SELECT reserve_serial(:request_id, :issuer_ca_id)"),
        {"request_id": request_id, "issuer_ca_id": issuer_ca_id},
    )
    return bytes(result.scalar_one())