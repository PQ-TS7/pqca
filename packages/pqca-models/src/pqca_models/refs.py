"""Minimal models for tables owned by other tickets.

They exist only so that ForeignKey("organizations.organization_id") and
similar references in pki.py resolve. They map just the columns we need.
When the Domain Ownership / RBAC tickets add the full models, delete the
matching class here and import theirs instead.

The tables themselves are created by database/init/001 and 002.
"""

from __future__ import annotations

import datetime
import uuid

from sqlalchemy import FetchedValue
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base


class Organization(Base):
    __tablename__ = "organizations"

    organization_id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=FetchedValue()
    )
    legal_name: Mapped[str]
    ov_status: Mapped[str] = mapped_column(server_default=FetchedValue())


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=FetchedValue()
    )
    email: Mapped[str]
    role: Mapped[str]


class CertificateRequest(Base):
    __tablename__ = "certificate_requests"

    request_id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=FetchedValue()
    )
    organization_id: Mapped[uuid.UUID]
    status: Mapped[str] = mapped_column(server_default=FetchedValue())
    issued_at: Mapped[datetime.datetime | None]