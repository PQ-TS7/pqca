"""Independent checks that call the openssl command directly (not the wrapper)."""

from __future__ import annotations

import subprocess
from pathlib import Path

from .config import OPENSSL_BIN, PROVIDER_ARGS


def _run(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [OPENSSL_BIN, *args], capture_output=True, timeout=60, shell=False, check=False
    )


def public_key_parses(public_pem: Path) -> bool:
    r = _run(["pkey", *PROVIDER_ARGS, "-pubin", "-in", str(public_pem), "-noout"])
    return r.returncode == 0


def public_der_from_private(private_pem: Path) -> bytes:
    """Ask OpenSSL to derive the public key (SPKI DER) from the private key file."""
    r = _run(
        ["pkey", *PROVIDER_ARGS, "-in", str(private_pem), "-pubout", "-outform", "DER"]
    )
    assert r.returncode == 0, "openssl could not reload the private key"
    return r.stdout


def sign(private_pem: Path, message: Path, signature: Path) -> None:
    r = _run(
        ["pkeyutl", "-sign", *PROVIDER_ARGS, "-inkey", str(private_pem),
         "-rawin", "-in", str(message), "-out", str(signature)]
    )
    assert r.returncode == 0, "openssl could not sign"


def verify(public_pem: Path, message: Path, signature: Path) -> bool:
    r = _run(
        ["pkeyutl", "-verify", *PROVIDER_ARGS, "-pubin", "-inkey", str(public_pem),
         "-rawin", "-in", str(message), "-sigfile", str(signature)]
    )
    return r.returncode == 0
