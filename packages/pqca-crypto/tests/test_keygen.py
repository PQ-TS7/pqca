"""TC-KEY-01 .. TC-KEY-18: ML-DSA-65 root key pair generation (SCRUM-215)."""

from __future__ import annotations

import json
import logging
import os
import random
import stat
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from support import der, openssl_cli as cli
from support.config import (
    EXPECTED_PRIVATE_FORMAT,
    ML_DSA_65_OID,
    PRIVATE_KEY_BYTES,
    PUBLIC_KEY_BYTES,
    SEED_BYTES,
    SIGNATURE_BYTES,
)

ALG = "ML-DSA-65"
DATA_DIR = Path(__file__).parent / "data"


# ---------------------------------------------------------------- helpers
def public_info(pair) -> der.PublicKeyInfo:
    return der.parse_spki(der.pem_to_der(Path(pair.public_key_path).read_text()))


def private_info(pair) -> der.PrivateKeyInfo:
    return der.parse_pkcs8(der.pem_to_der(Path(pair.private_key_path).read_text()))


def sign_with_openssl(pair, message: bytes, tmp: Path) -> bytes:
    msg, sig = tmp / "msg.bin", tmp / "sig.bin"
    msg.write_bytes(message)
    cli.sign(Path(pair.private_key_path), msg, sig)
    return sig.read_bytes()


def pyca_public_key(pair):
    mldsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.mldsa")
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(Path(pair.public_key_path).read_bytes())
    assert isinstance(key, mldsa.MLDSA65PublicKey)
    return key


class FakeRun:
    """Stands in for subprocess.run. Each step is a function(args) -> result or raises."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.calls: list[tuple[list, dict]] = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        return self.steps.pop(0)(args)


def _write_out(args, data: bytes = b"partial-key-bytes") -> None:
    if "-out" in args:
        Path(args[args.index("-out") + 1]).write_bytes(data)


def step_ok(args):
    _write_out(args)
    return subprocess.CompletedProcess(args, 0, b"", b"")


def step_fail(stderr: bytes = b"", code: int = 1):
    def step(args):
        return subprocess.CompletedProcess(args, code, b"", stderr)

    return step


def step_raise(exc: Exception):
    def step(args):
        _write_out(args)  # a half-written file is on disk when the failure hits
        raise exc

    return step


def install(monkeypatch, kg, *steps) -> FakeRun:
    fake = FakeRun(*steps)
    monkeypatch.setattr(kg.subprocess, "run", fake)
    return fake


# ------------------------------------------------------ TC-KEY-01 .. 08 [real]
def test_key_01_generated_sizes(kg, keydir):
    pair = kg.generate_keypair(ALG, keydir, "root")
    assert len(public_info(pair).key) == PUBLIC_KEY_BYTES
    priv = private_info(pair)
    if priv.fmt in ("expanded", "both"):
        assert len(priv.expanded) == PRIVATE_KEY_BYTES
    if priv.fmt in ("seed", "both"):
        assert len(priv.seed) == SEED_BYTES
    assert priv.fmt != "other", "unrecognised private-key encoding"


def test_key_02_public_key_encoding(kg, keydir):
    pair = kg.generate_keypair(ALG, keydir, "root")
    info = public_info(pair)
    assert info.oid == ML_DSA_65_OID
    assert info.parameter_count == 0  # RFC 9881: no parameters
    assert cli.public_key_parses(Path(pair.public_key_path))
    pyca_public_key(pair)  # an independent library accepts it as ML-DSA-65


def test_key_03_private_key_encoding_and_reload(kg, keydir):
    pair = kg.generate_keypair(ALG, keydir, "root")
    priv = private_info(pair)
    assert priv.oid == ML_DSA_65_OID
    assert priv.parameter_count == 0
    assert priv.fmt == EXPECTED_PRIVATE_FORMAT
    # OpenSSL can reload the stored private key and derives the same public key
    derived = cli.public_der_from_private(Path(pair.private_key_path))
    stored = der.pem_to_der(Path(pair.public_key_path).read_text())
    assert derived == stored


def test_key_04_sign_and_verify_with_independent_libraries(kg, keydir, tmp_path):
    pair = kg.generate_keypair(ALG, keydir, "root")
    message = b"PQ-CA root key test message"
    signature = sign_with_openssl(pair, message, tmp_path)
    assert len(signature) == SIGNATURE_BYTES
    pyca_public_key(pair).verify(signature, message)  # raises if invalid
    assert cli.verify(
        Path(pair.public_key_path), tmp_path / "msg.bin", tmp_path / "sig.bin"
    )


def test_key_05_tamper_detection(kg, keydir, tmp_path):
    from cryptography.exceptions import InvalidSignature

    rng = random.Random(2026)  # fixed seed: reproducible, not flaky
    pair = kg.generate_keypair(ALG, keydir, "root")
    other = kg.generate_keypair(ALG, keydir, "other")
    public, other_public = pyca_public_key(pair), pyca_public_key(other)

    for _ in range(10):
        message = rng.randbytes(rng.randint(1, 512))
        signature = sign_with_openssl(pair, message, tmp_path)
        public.verify(signature, message)

        flipped_message = bytes([message[0] ^ 1]) + message[1:]
        flipped_sig = signature[:100] + bytes([signature[100] ^ 1]) + signature[101:]
        for bad_message, bad_sig, key in (
            (flipped_message, signature, public),
            (message, flipped_sig, public),
            (message, signature, other_public),
        ):
            with pytest.raises(InvalidSignature):
                key.verify(bad_sig, bad_message)

    # one negative check through the openssl command as well
    (tmp_path / "bad.bin").write_bytes(flipped_sig)
    assert not cli.verify(
        Path(pair.public_key_path), tmp_path / "msg.bin", tmp_path / "bad.bin"
    )


def test_key_06_uniqueness(kg, keydir):
    seen = set()
    for i in range(100):
        pair = kg.generate_keypair(ALG, keydir, f"key{i}")
        seen.add(Path(pair.public_key_path).read_text())
    assert len(seen) == 100


def test_key_07_known_answer_from_nist_acvp(kg, keydir):
    # Needs a wrapper that accepts a seed, plus an ACVP vector saved as
    # tests/data/acvp_ml_dsa_65_keygen.json: {"seed": "<hex>", "pk": "<hex>"}
    import inspect

    if "seed" not in inspect.signature(kg.generate_keypair).parameters:
        pytest.xfail("wrapper has no seed input yet (TC-KEY-07); add the ticket number here")
    vector_file = DATA_DIR / "acvp_ml_dsa_65_keygen.json"
    if not vector_file.exists():
        pytest.skip("ACVP vector file not committed yet")
    vector = json.loads(vector_file.read_text())
    pair = kg.generate_keypair(ALG, keydir, "kat", seed=bytes.fromhex(vector["seed"]))
    assert public_info(pair).key == bytes.fromhex(vector["pk"])


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes only")
def test_key_08_private_key_file_is_not_group_or_world_accessible(kg, keydir):
    pair = kg.generate_keypair(ALG, keydir, "root")
    mode = stat.S_IMODE(Path(pair.private_key_path).stat().st_mode)
    assert mode & 0o077 == 0, f"private key mode is {oct(mode)}"
    assert mode in (0o400, 0o600)


# ----------------------------------------------------- TC-KEY-09 .. 14 [mocked]
@pytest.mark.parametrize(
    "bad", ["", None, "ML-DSA-66", "RSA-2048", "ML-DSA-65; rm -rf /", 65, b"ML-DSA-65"]
)
def test_key_09_algorithm_allow_list(kg, keydir, monkeypatch, bad):
    fake = install(monkeypatch, kg)
    with pytest.raises(kg.UnsupportedAlgorithmError):
        kg.generate_keypair(bad, keydir, "root")
    assert fake.calls == [], "a command ran before the algorithm was checked"


def test_key_10_openssl_missing(kg, keydir, monkeypatch):
    install(monkeypatch, kg, step_raise(FileNotFoundError("/usr/local/bin/openssl")))
    with pytest.raises(kg.ProviderUnavailableError) as err:
        kg.generate_keypair(ALG, keydir, "root")
    assert "/usr" not in str(err.value)


def test_key_10_provider_not_loaded(kg, keydir, monkeypatch):
    stderr = b"Error: unsupported algorithm (module /opt/oqs/lib/ossl-modules/x.so)"
    install(monkeypatch, kg, step_fail(stderr))
    with pytest.raises(kg.ProviderUnavailableError) as err:
        kg.generate_keypair(ALG, keydir, "root")
    assert "/opt" not in str(err.value) and "Traceback" not in str(err.value)


def test_key_11_openssl_error_is_sanitised(kg, keydir, monkeypatch):
    stderr = b"boom SECRET-SEED-0123456789abcdef at /home/svc/.keys/root.pem"
    install(monkeypatch, kg, step_fail(stderr, code=3))
    with pytest.raises(kg.KeyGenError) as err:
        kg.generate_keypair(ALG, keydir, "root")
    text = str(err.value)
    assert "SECRET-SEED" not in text and "/home/svc" not in text
    assert "Traceback" not in text


def test_key_12_timeout_cleans_up(kg, keydir, monkeypatch):
    fake = install(
        monkeypatch, kg, step_raise(subprocess.TimeoutExpired(["openssl"], 30))
    )
    with pytest.raises(kg.KeyGenTimeoutError):
        kg.generate_keypair(ALG, keydir, "root")
    assert list(keydir.iterdir()) == [], "partial files were left behind"
    # subprocess.run kills the child itself when a timeout is set
    assert fake.calls[0][1].get("timeout")


def test_key_13_existing_file_is_not_overwritten(kg, keydir):
    existing = keydir / "root.key.pem"
    existing.write_text("DO NOT TOUCH")
    with pytest.raises(kg.OutputPathError):
        kg.generate_keypair(ALG, keydir, "root")
    assert existing.read_text() == "DO NOT TOUCH"


def test_key_13_missing_directory(kg, keydir):
    with pytest.raises(kg.OutputPathError):
        kg.generate_keypair(ALG, keydir / "does-not-exist", "root")


@pytest.mark.skipif(
    os.name == "nt" or os.geteuid() == 0,
    reason="root ignores directory permissions (containers run as root)",
)
def test_key_13_unwritable_directory(kg, keydir):
    keydir.chmod(0o500)
    try:
        with pytest.raises(kg.OutputPathError):
            kg.generate_keypair(ALG, keydir, "root")
    finally:
        keydir.chmod(0o700)


def test_key_13_failure_after_private_key_leaves_nothing(kg, keydir, monkeypatch):
    install(monkeypatch, kg, step_ok, step_fail(b"derive failed"))
    with pytest.raises(kg.KeyGenError):
        kg.generate_keypair(ALG, keydir, "root")
    assert list(keydir.iterdir()) == []


@pytest.mark.parametrize(
    "name",
    ["a;b", "$(id)", "`id`", "a\nb", "../evil", "a/b", "a b", "x|y", "a&b", "..\\x", "", None],
)
def test_key_14_injection_in_name(kg, keydir, monkeypatch, name):
    fake = install(monkeypatch, kg)
    with pytest.raises(kg.InvalidNameError):
        kg.generate_keypair(ALG, keydir, name)
    assert fake.calls == []
    assert list(keydir.iterdir()) == []


def test_key_14_commands_use_argument_lists_without_a_shell(kg, keydir, monkeypatch):
    fake = install(monkeypatch, kg, step_ok, step_ok)
    kg.generate_keypair(ALG, keydir, "root")
    assert len(fake.calls) == 2
    for args, kwargs in fake.calls:
        assert isinstance(args, list) and all(isinstance(a, str) for a in args)
        assert not kwargs.get("shell", False)


# ----------------------------------------------------------- TC-KEY-15 .. 18
def test_key_15_no_key_material_in_logs_errors_or_repr(kg, keydir, caplog):
    import base64

    caplog.set_level(logging.DEBUG)
    pair = kg.generate_keypair(ALG, keydir, "root")
    priv = private_info(pair)
    secrets = [
        (priv.seed or priv.expanded).hex(),
        base64.b64encode(priv.seed or priv.expanded).decode(),
    ]
    with pytest.raises(kg.OutputPathError) as err:  # second call: file exists
        kg.generate_keypair(ALG, keydir, "root")
    haystack = f"{caplog.text}\n{pair!r}\n{pair}\n{err.value!r}"
    for secret in secrets:
        assert secret not in haystack


def test_key_16_liboqs_offers_ml_dsa_65():
    # Acceptance check on the third-party library (needs liboqs-python in the image).
    oqs = pytest.importorskip("oqs")
    assert ALG in oqs.get_enabled_sig_mechanisms()


@pytest.mark.skip(reason="TC-KEY-16 wrapper behaviour: liboqs backend is not in the wrapper yet")
def test_key_16_wrapper_reports_missing_liboqs_mechanism():
    ...


@pytest.mark.skip(reason="TC-KEY-17: needs both the OpenSSL and the liboqs backend in the wrapper")
def test_key_17_backend_parity():
    ...


def test_key_18_parallel_generations_are_distinct(kg, keydir):
    def make(i):
        return Path(kg.generate_keypair(ALG, keydir, f"par{i}").public_key_path).read_text()

    with ThreadPoolExecutor(max_workers=10) as pool:
        keys = list(pool.map(make, range(10)))
    assert len(set(keys)) == 10
    assert sorted(p.name for p in keydir.iterdir()) == sorted(
        [f"par{i}.key.pem" for i in range(10)] + [f"par{i}.pub.pem" for i in range(10)]
    )


def test_key_18_same_name_race_has_exactly_one_winner(kg, keydir):
    def attempt(_):
        try:
            kg.generate_keypair(ALG, keydir, "contested")
            return "ok"
        except kg.OutputPathError:
            return "refused"

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(attempt, range(10)))
    assert results.count("ok") == 1 and results.count("refused") == 9
