"""TEMPORARY stand-in for the real key-generation wrapper."""


from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .config import ALG_NAME, OPENSSL_BIN, PROVIDER_ARGS

TIMEOUT_SECONDS = 30
ALGORITHMS = {"ML-DSA-65": ALG_NAME}  # our name -> the name OpenSSL expects
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class KeyGenError(Exception):
    """Base class. Messages never contain key bytes, paths or raw OpenSSL output."""


class UnsupportedAlgorithmError(KeyGenError):
    pass


class InvalidNameError(KeyGenError):
    pass


class OutputPathError(KeyGenError):
    pass


class ProviderUnavailableError(KeyGenError):
    pass


class KeyGenTimeoutError(KeyGenError):
    pass


@dataclass(frozen=True)
class KeyPairFiles:
    algorithm: str
    private_key_path: Path
    public_key_path: Path


def _run(args: list[str]) -> subprocess.CompletedProcess:
    cmd = [OPENSSL_BIN, args[0], *PROVIDER_ARGS, *args[1:]]
    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=TIMEOUT_SECONDS, shell=False, check=False
        )
    except FileNotFoundError:
        raise ProviderUnavailableError("OpenSSL was not found on this system") from None
    except subprocess.TimeoutExpired:
        raise KeyGenTimeoutError("OpenSSL did not finish in time") from None
    if result.returncode != 0:
        # Heuristic: OpenSSL words "no such algorithm / provider" in several ways.
        hint = (result.stderr or b"").lower()
        if any(w in hint for w in (b"unsupported", b"unknown", b"not found", b"provider")):
            raise ProviderUnavailableError(
                "ML-DSA is not available in this OpenSSL build or provider"
            ) from None
        raise KeyGenError(f"OpenSSL {args[0]} failed (exit code {result.returncode})") from None
    return result


def generate_keypair(algorithm: str, out_dir, name: str) -> KeyPairFiles:
    if not isinstance(algorithm, str) or algorithm not in ALGORITHMS:
        raise UnsupportedAlgorithmError("algorithm is not on the allow-list")
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        raise InvalidNameError("key name may only use letters, digits, '_' and '-'")

    out_dir = Path(out_dir)
    if not out_dir.is_dir() or not os.access(out_dir, os.W_OK):
        raise OutputPathError("output directory does not exist or is not writable")
    private_path = out_dir / f"{name}.key.pem"
    public_path = out_dir / f"{name}.pub.pem"
    if private_path.exists() or public_path.exists():
        raise OutputPathError("key files already exist and will not be overwritten")

    # mkdtemp creates the directory with mode 0700, so the key is never exposed
    # while it is being written. It is removed on every path, success or not.
    work = Path(tempfile.mkdtemp(prefix=".keygen-", dir=out_dir))
    linked: list[Path] = []
    try:
        tmp_private, tmp_public = work / "private.pem", work / "public.pem"
        _run(["genpkey", "-algorithm", ALGORITHMS[algorithm], "-out", str(tmp_private)])
        os.chmod(tmp_private, 0o600)
        _run(["pkey", "-in", str(tmp_private), "-pubout", "-out", str(tmp_public)])
        try:
            for src, dst in ((tmp_private, private_path), (tmp_public, public_path)):
                os.link(src, dst)  # fails if dst exists: never overwrites
                linked.append(dst)
        except FileExistsError:
            raise OutputPathError("key files already exist and will not be overwritten") from None
        return KeyPairFiles(algorithm, private_path, public_path)
    except BaseException:
        for path in linked:
            path.unlink(missing_ok=True)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
