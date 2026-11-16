"""Declarative base for every PQ-CA ORM model.

The schema is owned by the SQL in database/init/ and database/migrations/.
Models describe tables that already exist; never call metadata.create_all()
or generate migrations from them. Service logins have no CREATE on the
schema anyway.

Columns filled by the database (gen_random_uuid(), now(), identity, triggers)
should be declared with server_default=FetchedValue() or similar, not with a
Python default, so the database stays the source of those values.

A service with INSERT but no SELECT on a table (the support bot on
assistant_feedback) can't use session.add() or a plain insert(): SQLAlchemy
fetches the new primary key, and RETURNING needs SELECT. Use
insert(Model.__table__).inline().values(...) there.
"""

from __future__ import annotations

import datetime
import decimal
import uuid
from typing import Any

from sqlalchemy import Numeric, Text
from sqlalchemy.dialects.postgresql import BYTEA, JSONB, TIMESTAMP, UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    # Python annotation -> column type, matching the types the SQL uses.
    type_annotation_map = {
        str: Text(),
        bytes: BYTEA(),
        uuid.UUID: UUID(as_uuid=True),
        datetime.datetime: TIMESTAMP(timezone=True),
        decimal.Decimal: Numeric(),
        dict[str, Any]: JSONB(),
        list[Any]: JSONB(),
    }
