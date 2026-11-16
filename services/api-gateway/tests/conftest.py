import os

import pytest


@pytest.fixture(autouse=True)
def clean_gateway_env(monkeypatch):
    """Keep a developer's own PQCA_GATEWAY_* variables out of the tests."""
    for name in list(os.environ):
        if name.startswith("PQCA_GATEWAY_"):
            monkeypatch.delenv(name)
