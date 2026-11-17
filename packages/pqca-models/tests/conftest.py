from __future__ import annotations

import datetime
import os
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session

DB_URL = os.environ.get("PQCA_TEST_DATABASE_URL")


@dataclass
class Seed:
    user_id: uuid.UUID
    organization_id: uuid.UUID
    request_id: uuid.UUID
    root_ca_id: uuid.UUID
    issuer_ca_id: uuid.UUID
    domain: str


@pytest.fixture(scope="session")
def engine():
    if not DB_URL:
        pytest.skip("PQCA_TEST_DATABASE_URL is not set")
    eng = create_engine(DB_URL)
    yield eng
    eng.dispose()


@pytest.fixture()
def session(engine):
    """A session inside one outer transaction that is always rolled back."""
    conn = engine.connect()
    outer = conn.begin()
    sess = Session(bind=conn, join_transaction_mode="create_savepoint")
    try:
        yield sess
    finally:
        sess.close()
        outer.rollback()
        conn.close()


@pytest.fixture()
def seed(session) -> Seed:
    """A request that already passed both issuance gates.

    Seeds with triggers and foreign keys switched off (replica mode),
    then switches them back on so the code under test runs the real rules.
    """
    s = Seed(
        user_id=uuid.uuid4(),
        organization_id=uuid.uuid4(),
        request_id=uuid.uuid4(),
        root_ca_id=uuid.uuid4(),
        issuer_ca_id=uuid.uuid4(),
        domain="example.com",
    )
    challenge_id = uuid.uuid4()
    now = datetime.datetime.now(datetime.timezone.utc)
    ten_years = now + datetime.timedelta(days=3650)
    token = "A" * 43

    session.execute(text("SET LOCAL session_replication_role = replica"))

    session.execute(
        text(
            "INSERT INTO users (user_id, email, full_name, role) "
            "VALUES (:id, :email, 'Test Admin', 'super_admin')"
        ),
        {"id": s.user_id, "email": f"admin-{s.user_id}@test.local"},
    )
    session.execute(
        text(
            "INSERT INTO organizations "
            "(organization_id, legal_name, registration_no, country, ov_status) "
            "VALUES (:id, 'Test Org', :reg, 'EG', 'accepted')"
        ),
        {"id": s.organization_id, "reg": f"REG-{s.organization_id}"},
    )
    session.execute(
        text(
            "INSERT INTO certificate_requests "
            "(request_id, organization_id, csr_der, csr_sha256, "
            " signature_algorithm, san_set_hash, status) "
            "VALUES (:rid, :oid, :csr, digest(:csr, 'sha256'), "
            "        'ML-DSA-65', digest('example.com', 'sha256'), 'validated')"
        ),
        {"rid": s.request_id, "oid": s.organization_id, "csr": b"fake-csr"},
    )
    session.execute(
        text(
            "INSERT INTO domain_challenges "
            "(challenge_id, organization_id, domain, method, status, token, "
            " key_auth_sha256, expires_at, validated_at, valid_until) "
            "VALUES (:cid, :oid, :domain, 'dns-01', 'valid', :token, "
            "        digest('key-auth', 'sha256'), :exp, :now, :until)"
        ),
        {
            "cid": challenge_id,
            "oid": s.organization_id,
            "domain": s.domain,
            "token": token,
            "exp": now + datetime.timedelta(days=7),
            "now": now,
            "until": now + datetime.timedelta(days=90),
        },
    )
    session.execute(
        text(
            "INSERT INTO request_domains (request_id, domain, is_wildcard, challenge_id) "
            "VALUES (:rid, :domain, false, :cid)"
        ),
        {"rid": s.request_id, "domain": s.domain, "cid": challenge_id},
    )
    # Root CA (offline: no key_label) and the active intermediate under it.
    for ca_id, name, ca_type, parent, label in (
        (s.root_ca_id, "Test Root", "root", None, None),
        (s.issuer_ca_id, "Test Intermediate", "intermediate", s.root_ca_id, "int-key"),
    ):
        session.execute(
            text(
                "INSERT INTO issuing_cas "
                "(ca_id, name, ca_type, parent_ca_id, subject_dn, "
                " signature_algorithm, cert_der, cert_sha256, "
                " not_before, not_after, key_label) "
                "VALUES (:id, :name, :type, :parent, :dn, 'ML-DSA-65', "
                "        :der, digest(:der, 'sha256'), :nb, :na, :label)"
            ),
            {
                "id": ca_id,
                "name": f"{name} {ca_id}",
                "type": ca_type,
                "parent": parent,
                "dn": f"CN={name}",
                "der": f"fake-ca-cert-{name}".encode(),
                "nb": now,
                "na": ten_years,
                "label": label,
            },
        )

    session.execute(text("SET LOCAL session_replication_role = origin"))
    session.flush()
    return s