from __future__ import annotations

import datetime
import enum
import hashlib
import uuid

from sqlalchemy import (
    ARRAY,
    BigInteger,
    FetchedValue,
    ForeignKey,
    Identity,
    SmallInteger,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base


def sha256_of(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


class CAType(str, enum.Enum):

    ROOT = "root"
    INTERMEDIATE = "intermediate"
    OCSP_SIGNER = "ocsp_signer"


class RevocationReason(enum.IntEnum):

    UNSPECIFIED = 0
    KEY_COMPROMISE = 1
    CA_COMPROMISE = 2
    AFFILIATION_CHANGED = 3
    SUPERSEDED = 4
    CESSATION_OF_OPERATION = 5
    PRIVILEGE_WITHDRAWN = 9
    AA_COMPROMISE = 10


# ISSUING CAs
class IssuingCA(Base):
    """Root, Intermediate or OCSP-signer CA. Only `status` can be updated."""

    __tablename__ = "issuing_cas"
    __mapper_args__ = {"eager_defaults": True}

    ca_id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True, server_default=FetchedValue()
    )
    name: Mapped[str]
    ca_type: Mapped[str]  
    parent_ca_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("issuing_cas.ca_id")
    )
    subject_dn: Mapped[str]
    signature_algorithm: Mapped[str]  
    cert_der: Mapped[bytes]
    cert_sha256: Mapped[bytes]
    not_before: Mapped[datetime.datetime]
    not_after: Mapped[datetime.datetime]
    key_label: Mapped[str | None]  
    status: Mapped[str] = mapped_column(server_default=FetchedValue())
    created_at: Mapped[datetime.datetime] = mapped_column(
        server_default=FetchedValue()
    )

    parent: Mapped[IssuingCA | None] = relationship(
        remote_side="IssuingCA.ca_id"
    )

    def __repr__(self) -> str:
        return f"<IssuingCA {self.name} ({self.ca_type}, {self.status})>"


# SERIAL RESERVATIONS
class SerialReservation(Base):

    __tablename__ = "serial_reservations"

    serial_number: Mapped[bytes] = mapped_column(primary_key=True)
    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("certificate_requests.request_id")
    )
    issuer_ca_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("issuing_cas.ca_id")
    )
    reserved_at: Mapped[datetime.datetime] = mapped_column(
        server_default=FetchedValue()
    )


# CERTIFICATES
class Certificate(Base):
    

    __tablename__ = "certificates"
    __mapper_args__ = {"eager_defaults": True}

    serial_number: Mapped[bytes] = mapped_column(
        ForeignKey("serial_reservations.serial_number"), primary_key=True
    )
    request_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("certificate_requests.request_id")
    )
    issuer_ca_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("issuing_cas.ca_id")
    )
    subject_dn: Mapped[str]
    san_list: Mapped[list[str]] = mapped_column(ARRAY(Text()))
    not_before: Mapped[datetime.datetime]
    not_after: Mapped[datetime.datetime]
    cert_der: Mapped[bytes]
    cert_sha256: Mapped[bytes]
    replaces_serial: Mapped[bytes | None] = mapped_column(
        ForeignKey("certificates.serial_number")
    )

    organization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("organizations.organization_id"),
        server_default=FetchedValue(),
    )
    issuer_dn: Mapped[str] = mapped_column(server_default=FetchedValue())
    public_key_algorithm: Mapped[str] = mapped_column(
        server_default=FetchedValue()
    )
    signature_algorithm: Mapped[str] = mapped_column(
        server_default=FetchedValue()
    )
    status: Mapped[str] = mapped_column(server_default=FetchedValue())
    issued_at: Mapped[datetime.datetime] = mapped_column(
        server_default=FetchedValue()
    )

    issuer: Mapped[IssuingCA] = relationship()
    revocation: Mapped[Revocation | None] = relationship(
        back_populates="certificate", uselist=False
    )

    @property
    def public_key_spki(self) -> bytes:
        
        from asn1crypto import x509

        cert = x509.Certificate.load(self.cert_der)
        return cert["tbs_certificate"]["subject_public_key_info"].dump()

    @property
    def public_key_sha256(self) -> bytes:
        return sha256_of(self.public_key_spki)

    def __repr__(self) -> str:
        return f"<Certificate {bytes(self.serial_number).hex()}>"



# REVOCATIONS
class Revocation(Base):
    

    __tablename__ = "revocations"
    __mapper_args__ = {"eager_defaults": True}

    serial_number: Mapped[bytes] = mapped_column(
        ForeignKey("certificates.serial_number"), primary_key=True
    )
    reason_code: Mapped[int] = mapped_column(SmallInteger())  # RevocationReason
    compromise_timestamp: Mapped[datetime.datetime | None]
    revoked_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.user_id"))
    note: Mapped[str | None]

    revocation_date: Mapped[datetime.datetime] = mapped_column(
        server_default=FetchedValue()
    )
    published_at: Mapped[datetime.datetime | None] = mapped_column(
        server_default=FetchedValue()
    )

    certificate: Mapped[Certificate] = relationship(
        back_populates="revocation"
    )


# CRLs
class CRL(Base):
    """One published CRL. crl_number is assigned by trigger and only goes up."""

    __tablename__ = "crls"
    __mapper_args__ = {"eager_defaults": True}

    crl_id: Mapped[int] = mapped_column(
        BigInteger(), Identity(always=True), primary_key=True
    )
    issuer_ca_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("issuing_cas.ca_id")
    )
    crl_number: Mapped[int] = mapped_column(
        BigInteger(), server_default=FetchedValue()
    )
    this_update: Mapped[datetime.datetime]
    next_update: Mapped[datetime.datetime]
    crl_der: Mapped[bytes]
    crl_sha256: Mapped[bytes]
    revoked_count: Mapped[int]
    is_emergency: Mapped[bool] = mapped_column(server_default=FetchedValue())
    file_path: Mapped[str | None]
    generated_at: Mapped[datetime.datetime] = mapped_column(
        server_default=FetchedValue()
    )

    issuer: Mapped[IssuingCA] = relationship()


# v_certificate_status (read-only view)
class CertificateStatus(Base):

    __tablename__ = "v_certificate_status"

    serial_number: Mapped[bytes] = mapped_column(primary_key=True)
    issuer_ca_id: Mapped[uuid.UUID]
    cert_status: Mapped[str]
    revocation_date: Mapped[datetime.datetime | None]
    reason_code: Mapped[int | None] = mapped_column(SmallInteger())
    compromise_timestamp: Mapped[datetime.datetime | None]
    not_before: Mapped[datetime.datetime]
    not_after: Mapped[datetime.datetime]