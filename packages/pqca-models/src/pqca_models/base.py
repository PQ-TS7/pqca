
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
