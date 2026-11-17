"""Tests for the PKI models against the real schema (003_pki_core.sql)."""

from __future__ import annotations

import datetime
import os

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from pqca_models import (
    CRL,
    Certificate,
    CertificateStatus,
    IssuingCA,
    Revocation,
    RevocationReason,
    reserve_serial,
    sha256_of,
)


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _new_cert(seed, serial: bytes, **overrides) -> Certificate:
    now = _now()
    der = overrides.pop("cert_der", b"fake-cert-der")
    fields = dict(
        serial_number=serial,
        request_id=seed.request_id,
        issuer_ca_id=seed.issuer_ca_id,
        subject_dn="CN=example.com",
        san_list=[seed.domain],
        not_before=now,
        not_after=now + datetime.timedelta(days=90),
        cert_der=der,
        cert_sha256=sha256_of(der),
    )
    fields.update(overrides)
    return Certificate(**fields)


def _issue(session, seed) -> Certificate:
    """Reserve a serial and insert a valid certificate."""
    serial = reserve_serial(session, seed.request_id, seed.issuer_ca_id)
    cert = _new_cert(seed, serial)
    session.add(cert)
    session.flush()
    return cert


def _new_crl(seed, this_update: datetime.datetime) -> CRL:
    der = b"fake-crl-der"
    return CRL(
        issuer_ca_id=seed.issuer_ca_id,
        this_update=this_update,
        next_update=this_update + datetime.timedelta(days=1),
        crl_der=der,
        crl_sha256=sha256_of(der),
        revoked_count=0,
    )


def _expect_db_error(session, action) -> None:
    """The action must fail in the database; the session stays usable."""
    with pytest.raises(DBAPIError):
        with session.begin_nested():
            action()


# --- issuing CAs ------------------------------------------------------
def test_issuing_ca_maps_the_seeded_rows(session, seed):
    inter = session.get(IssuingCA, seed.issuer_ca_id)
    root = session.get(IssuingCA, seed.root_ca_id)

    assert inter.ca_type == "intermediate"
    assert inter.key_label == "int-key"
    assert inter.status == "active"
    assert inter.parent is root
    assert root.key_label is None  # the offline root has no HSM key
    assert root.parent is None


# --- serial reservation ----------------------------------------------
def test_reserve_serial_is_valid_and_idempotent(session, seed):
    s1 = reserve_serial(session, seed.request_id, seed.issuer_ca_id)
    s2 = reserve_serial(session, seed.request_id, seed.issuer_ca_id)
    assert s1 == s2
    assert len(s1) == 20
    assert 1 <= s1[0] <= 127  # DER-positive, RFC 5280


def test_reserve_serial_refuses_a_root_ca_as_issuer(session, seed):
    _expect_db_error(
        session,
        lambda: reserve_serial(session, seed.request_id, seed.root_ca_id),
    )


# --- certificate insert ----------------------------------------------
def test_certificate_insert_fills_trigger_columns(session, seed):
    cert = _issue(session, seed)

    assert cert.status == "active"
    assert cert.organization_id == seed.organization_id
    assert cert.issuer_dn == "CN=Test Intermediate"
    assert cert.signature_algorithm == "ML-DSA-65"  # the issuer's key
    assert cert.public_key_algorithm == "ML-DSA-65"  # from the request
    assert cert.issued_at is not None


def test_certificate_with_unreserved_serial_is_refused(session, seed):
    reserve_serial(session, seed.request_id, seed.issuer_ca_id)
    bogus = bytes([1]) + os.urandom(19)
    _expect_db_error(
        session, lambda: (session.add(_new_cert(seed, bogus)), session.flush())
    )


def test_san_list_must_equal_the_validated_sans(session, seed):
    serial = reserve_serial(session, seed.request_id, seed.issuer_ca_id)
    bad = _new_cert(seed, serial, san_list=[seed.domain, "evil.example.org"])
    _expect_db_error(session, lambda: (session.add(bad), session.flush()))


def test_large_der_round_trips_unchanged(session, seed):
    serial = reserve_serial(session, seed.request_id, seed.issuer_ca_id)
    der = os.urandom(3500)  # a multi-KB post-quantum sized blob
    cert = _new_cert(seed, serial, cert_der=der)
    session.add(cert)
    session.flush()
    session.expire(cert)
    assert bytes(cert.cert_der) == der


def test_certificate_rows_are_immutable(session, seed):
    cert = _issue(session, seed)
    _expect_db_error(
        session,
        lambda: session.execute(
            text(
                "UPDATE certificates SET subject_dn = 'CN=evil' "
                "WHERE serial_number = :s"
            ),
            {"s": cert.serial_number},
        ),
    )


# --- revocation and the status view ----------------------------------
def test_revocation_flips_certificate_and_view(session, seed):
    cert = _issue(session, seed)
    serial = cert.serial_number

    status = session.get(CertificateStatus, serial)
    assert status.cert_status == "good"

    session.add(
        Revocation(
            serial_number=serial,
            reason_code=int(RevocationReason.KEY_COMPROMISE),
            revoked_by=seed.user_id,
        )
    )
    session.flush()

    session.refresh(cert)  # the trigger changed status behind the ORM's back
    assert cert.status == "revoked"
    assert cert.revocation.reason_code == RevocationReason.KEY_COMPROMISE
    assert cert.revocation.published_at is None  # not in a CRL yet

    session.expire(status)
    assert session.get(CertificateStatus, serial).cert_status == "revoked"


def test_revocation_reason_6_is_refused(session, seed):
    cert = _issue(session, seed)
    bad = Revocation(
        serial_number=cert.serial_number,
        reason_code=6,  # certificateHold: not allowed, revocations are permanent
        revoked_by=seed.user_id,
    )
    _expect_db_error(session, lambda: (session.add(bad), session.flush()))


# --- CRLs -------------------------------------------------------------
def test_crl_numbers_go_up(session, seed):
    now = _now()
    first = _new_crl(seed, now)
    session.add(first)
    session.flush()
    assert first.crl_number == 1
    assert first.is_emergency is False

    second = _new_crl(seed, now + datetime.timedelta(hours=1))
    session.add(second)
    session.flush()
    assert second.crl_number == 2


def test_crl_this_update_must_increase(session, seed):
    now = _now()
    session.add(_new_crl(seed, now))
    session.flush()

    older = _new_crl(seed, now - datetime.timedelta(hours=1))
    _expect_db_error(session, lambda: (session.add(older), session.flush()))