#pytest setup shared by all tests
#It defines the kg fixture (the module being tested: the real wrapper if it exists, otherwise the shim), 
# the keydir fixture (a fresh empty folder per test), and a header line saying which backend is in use.

from __future__ import annotations

import importlib
import importlib.util
import os

import pytest


def _real_wrapper_exists() -> bool:
    try:
        return importlib.util.find_spec("pqca_crypto.keys") is not None
    except ModuleNotFoundError:
        return False


def pytest_report_header(config):
    choice = os.environ.get("PQCA_KEYGEN_BACKEND", "auto")
    using_real = choice == "real" or (choice == "auto" and _real_wrapper_exists())
    return f"keygen backend: {'REAL wrapper' if using_real else 'TEMPORARY SHIM'}"


@pytest.fixture(scope="session")
def kg():
    choice = os.environ.get("PQCA_KEYGEN_BACKEND", "auto")
    if choice == "real" or (choice == "auto" and _real_wrapper_exists()):
        return importlib.import_module("pqca_crypto.keys")
    from support import keygen_shim

    return keygen_shim


@pytest.fixture()
def keydir(tmp_path):
    d = tmp_path / "keys"
    d.mkdir()
    return d