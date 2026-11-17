"""Tiny DER reader so tests can check key encodings without trusting the code under test.

Handles just what we need: SubjectPublicKeyInfo and PKCS#8 for ML-DSA (RFC 9881).
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass


def pem_to_der(pem: str) -> bytes:
    body = re.sub(r"-----(BEGIN|END)[^-]+-----|\s", "", pem)
    return base64.b64decode(body, validate=True)


def _tlv(buf: bytes, pos: int) -> tuple[int, int, int]:
    """Return (tag, content_start, content_end) of the element at pos."""
    tag = buf[pos]
    first = buf[pos + 1]
    if first < 0x80:
        length, start = first, pos + 2
    else:
        n = first & 0x7F
        length = int.from_bytes(buf[pos + 2 : pos + 2 + n], "big")
        start = pos + 2 + n
    end = start + length
    if end > len(buf):
        raise ValueError("truncated DER")
    return tag, start, end


def _children(content: bytes) -> list[tuple[int, bytes]]:
    out, pos = [], 0
    while pos < len(content):
        tag, start, end = _tlv(content, pos)
        out.append((tag, content[start:end]))
        pos = end
    return out


def _sequence(der: bytes) -> list[tuple[int, bytes]]:
    tag, start, end = _tlv(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("not a single DER SEQUENCE")
    return _children(der[start:end])


def decode_oid(raw: bytes) -> str:
    parts = [raw[0] // 40, raw[0] % 40]
    value = 0
    for byte in raw[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


@dataclass(frozen=True)
class PublicKeyInfo:
    oid: str
    parameter_count: int  # RFC 9881: must be 0 (parameters absent)
    key: bytes  # raw public key


@dataclass(frozen=True)
class PrivateKeyInfo:
    oid: str
    parameter_count: int
    fmt: str  # "seed" | "expanded" | "both" | "other"
    seed: bytes | None
    expanded: bytes | None


def parse_spki(der: bytes) -> PublicKeyInfo:
    algorithm, bitstring = _sequence(der)
    if algorithm[0] != 0x30 or bitstring[0] != 0x03:
        raise ValueError("not a SubjectPublicKeyInfo")
    alg_items = _children(algorithm[1])
    if bitstring[1][0] != 0:
        raise ValueError("unexpected unused bits in public key")
    return PublicKeyInfo(
        oid=decode_oid(alg_items[0][1]),
        parameter_count=len(alg_items) - 1,
        key=bitstring[1][1:],
    )


def parse_pkcs8(der: bytes) -> PrivateKeyInfo:
    items = _sequence(der)
    algorithm, wrapped = items[1], items[2]
    alg_items = _children(algorithm[1])
    inner = wrapped[1]
    tag, start, end = _tlv(inner, 0)
    seed = expanded = None
    if tag == 0x80:
        fmt, seed = "seed", inner[start:end]
    elif tag == 0x04:
        fmt, expanded = "expanded", inner[start:end]
    elif tag == 0x30:
        both = _children(inner[start:end])
        fmt, seed, expanded = "both", both[0][1], both[1][1]
    else:
        fmt = "other"
    return PrivateKeyInfo(
        oid=decode_oid(alg_items[0][1]),
        parameter_count=len(alg_items) - 1,
        fmt=fmt,
        seed=seed,
        expanded=expanded,
    )
