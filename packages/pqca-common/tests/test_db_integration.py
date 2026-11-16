"""Runs against a real database built from database/Dockerfile.

Skipped unless PQCA_TEST_DB_HOST is set. See packages/pqca-common/README.md.
"""

import os
import uuid
from typing import Any

import pytest
from sqlalchemy import BigInteger, Identity, insert, text
from sqlalchemy.exc import ProgrammingError
from sqlalchemy.orm import Mapped, mapped_column

from pqca_common.db import Database, DatabaseSettings

pytestmark = pytest.mark.skipif(
    not os.environ.get("PQCA_TEST_DB_HOST"), reason="PQCA_TEST_DB_HOST not set"
)


def _settings(user: str, password_var: str, **overrides) -> DatabaseSettings:
    return DatabaseSettings(
        host=os.environ["PQCA_TEST_DB_HOST"],
        port=int(os.environ.get("PQCA_TEST_DB_PORT", "5432")),
        name=os.environ.get("PQCA_TEST_DB_NAME", "pqca"),
        user=user,
        password=os.environ[password_var],
        sslmode="disable",
        app_name="pqca-common-tests",
        **overrides,
    )


@pytest.fixture
async def gateway_db():
    # One pooled connection, so consecutive transactions reuse the same backend.
    db = Database.from_settings(
        _settings("gateway_svc", "PQCA_TEST_GATEWAY_PASSWORD", pool_size=1, max_overflow=0)
    )
    yield db
    await db.dispose()


async def test_connects_as_service_login(gateway_db):
    await gateway_db.ping()
    async with gateway_db.transaction() as session:
        row = (await session.execute(text(
            "SELECT session_user, current_setting('application_name'), current_setting('statement_timeout')"
        ))).one()

    assert tuple(row) == ("gateway_svc", "pqca-common-tests", "30s")


async def test_audit_context_reaches_audit_log(gateway_db):
    # audit_logs.actor_id references users, so the actor has to exist.
    async with gateway_db.transaction() as session:
        actor = (await session.execute(
            text("INSERT INTO users (email, full_name, role) VALUES (:email, 'Test Operator', 'ca_operator')"
                 " RETURNING user_id"),
            {"email": f"test-{uuid.uuid4().hex}@example.test"},
        )).scalar_one()

    async with gateway_db.transaction(actor_id=actor, client_ip="203.0.113.7") as session:
        log_id = (await session.execute(text("SELECT audit_log('test.db_session')"))).scalar_one()

    async with gateway_db.transaction() as session:
        row = (await session.execute(
            text("SELECT actor_id, actor_label, host(ip_address) FROM audit_logs WHERE log_id = :id"),
            {"id": log_id},
        )).one()

    assert tuple(row) == (actor, "gateway_svc", "203.0.113.7")


async def test_audit_context_does_not_leak_to_next_transaction(gateway_db):
    # No audit_log() call here, so the actor doesn't need to be a real user.
    async with gateway_db.transaction(actor_id=uuid.uuid4(), client_ip="203.0.113.7") as session:
        pid_first = (await session.execute(text("SELECT pg_backend_pid()"))).scalar_one()

    async with gateway_db.transaction() as session:
        pid_second, actor, ip = (await session.execute(text(
            "SELECT pg_backend_pid(), current_setting('pqca.actor_id', true),"
            "       current_setting('pqca.client_ip', true)"
        ))).one()

    assert pid_second == pid_first
    assert (actor or "", ip or "") == ("", "")


async def test_exception_rolls_back(gateway_db):
    with pytest.raises(RuntimeError):
        async with gateway_db.transaction() as session:
            log_id = (await session.execute(text("SELECT audit_log('test.rollback')"))).scalar_one()
            raise RuntimeError("boom")

    async with gateway_db.transaction() as session:
        found = (await session.execute(
            text("SELECT count(*) FROM audit_logs WHERE log_id = :id"), {"id": log_id}
        )).scalar_one()

    assert found == 0


async def test_rejects_bad_client_ip_before_touching_the_db(gateway_db):
    with pytest.raises(ValueError):
        async with gateway_db.transaction(client_ip="not-an-ip"):
            pass


# ---------------------------------------------------------------------
# pqca_models.Base against the real table, under the support bot's
# INSERT-only grant on assistant_feedback.
# ---------------------------------------------------------------------
pqca_models = pytest.importorskip("pqca_models")


class AssistantFeedback(pqca_models.Base):
    __tablename__ = "assistant_feedback"

    feedback_id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    assistant: Mapped[str]
    question: Mapped[str]
    answer: Mapped[str]
    rating: Mapped[str]
    sources: Mapped[list[Any]]


@pytest.fixture
async def support_bot_db():
    db = Database.from_settings(_settings("support_bot_svc", "PQCA_TEST_SUPPORT_BOT_PASSWORD"))
    yield db
    await db.dispose()


FEEDBACK = {"assistant": "external_support", "question": "q", "answer": "a", "rating": "up"}


async def test_insert_only_grant_works_with_inline_core_insert(support_bot_db):
    # .inline() stops SQLAlchemy fetching the new id (RETURNING or nextval()),
    # so the statement needs nothing beyond INSERT.
    async with support_bot_db.transaction() as session:
        await session.execute(
            insert(AssistantFeedback.__table__).inline().values(**FEEDBACK, sources=[{"doc": "faq"}])
        )


@pytest.mark.parametrize("statement", ["session_add", "orm_insert", "core_insert"])
async def test_insert_only_grant_rejects_inserts_that_fetch_the_id(support_bot_db, statement):
    with pytest.raises(ProgrammingError, match="permission denied"):
        async with support_bot_db.transaction() as session:
            if statement == "session_add":
                session.add(AssistantFeedback(**FEEDBACK, sources=[]))
            elif statement == "orm_insert":
                await session.execute(insert(AssistantFeedback).values(**FEEDBACK, sources=[]))
            else:
                await session.execute(insert(AssistantFeedback.__table__).values(**FEEDBACK, sources=[]))
