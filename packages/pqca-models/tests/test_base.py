import datetime
import decimal
import uuid
from typing import Any

from sqlalchemy.dialects import postgresql
from sqlalchemy.orm import Mapped, mapped_column

from pqca_models import Base


class Example(Base):
    __tablename__ = "example"

    example_id: Mapped[uuid.UUID] = mapped_column(primary_key=True)
    label: Mapped[str]
    note: Mapped[str | None]
    digest: Mapped[bytes]
    created_at: Mapped[datetime.datetime]
    confidence: Mapped[decimal.Decimal]
    details: Mapped[dict[str, Any]]
    signals: Mapped[list[Any]]


def _column_types() -> dict[str, str]:
    dialect = postgresql.dialect()
    return {c.name: c.type.compile(dialect=dialect) for c in Example.__table__.columns}


def test_annotations_map_to_the_types_the_schema_uses():
    assert _column_types() == {
        "example_id": "UUID",
        "label": "TEXT",
        "note": "TEXT",
        "digest": "BYTEA",
        "created_at": "TIMESTAMP WITH TIME ZONE",
        "confidence": "NUMERIC",
        "details": "JSONB",
        "signals": "JSONB",
    }


def test_optional_annotation_means_nullable():
    columns = Example.__table__.columns

    assert columns["note"].nullable is True
    assert columns["label"].nullable is False
