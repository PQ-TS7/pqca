import pytest
from pydantic import ValidationError

from api_gateway.config import DEV_CORS_ORIGINS, Settings


def test_defaults_are_dev_friendly():
    s = Settings()
    assert s.environment == "dev"
    assert s.docs_enabled is True
    assert s.cors_origins == list(DEV_CORS_ORIGINS)
    assert s.cors_allow_credentials is False
    assert s.api_prefix == "/api/v1"


def test_prod_defaults_are_closed(monkeypatch):
    monkeypatch.setenv("PQCA_GATEWAY_ENVIRONMENT", "prod")
    s = Settings()
    assert s.docs_enabled is False
    assert s.cors_origins == []


def test_docs_can_be_forced(monkeypatch):
    monkeypatch.setenv("PQCA_GATEWAY_ENVIRONMENT", "prod")
    monkeypatch.setenv("PQCA_GATEWAY_ENABLE_DOCS", "true")
    assert Settings().docs_enabled is True


def test_origins_from_comma_list(monkeypatch):
    monkeypatch.setenv("PQCA_GATEWAY_CORS_ALLOW_ORIGINS", "https://a.example, https://b.example:8443")
    assert Settings().cors_origins == ["https://a.example", "https://b.example:8443"]


def test_origins_from_json_list(monkeypatch):
    monkeypatch.setenv("PQCA_GATEWAY_CORS_ALLOW_ORIGINS", '["https://a.example"]')
    assert Settings().cors_origins == ["https://a.example"]


def test_explicit_empty_origins_disable_the_dev_default(monkeypatch):
    monkeypatch.setenv("PQCA_GATEWAY_CORS_ALLOW_ORIGINS", "")
    assert Settings().cors_origins == []


def test_trailing_slash_origin_is_rejected(monkeypatch):
    monkeypatch.setenv("PQCA_GATEWAY_CORS_ALLOW_ORIGINS", "https://a.example/")
    with pytest.raises(ValidationError, match="not a valid origin"):
        Settings()


def test_wildcard_with_credentials_is_rejected(monkeypatch):
    monkeypatch.setenv("PQCA_GATEWAY_CORS_ALLOW_ORIGINS", "*")
    monkeypatch.setenv("PQCA_GATEWAY_CORS_ALLOW_CREDENTIALS", "true")
    with pytest.raises(ValidationError, match="allow_credentials"):
        Settings()


def test_wildcard_in_prod_is_rejected(monkeypatch):
    monkeypatch.setenv("PQCA_GATEWAY_ENVIRONMENT", "prod")
    monkeypatch.setenv("PQCA_GATEWAY_CORS_ALLOW_ORIGINS", "*")
    with pytest.raises(ValidationError, match="prod"):
        Settings()


def test_unknown_environment_is_rejected(monkeypatch):
    monkeypatch.setenv("PQCA_GATEWAY_ENVIRONMENT", "staging")
    with pytest.raises(ValidationError):
        Settings()


@pytest.mark.parametrize("prefix", ["api", "/api/"])
def test_bad_api_prefix_is_rejected(monkeypatch, prefix):
    monkeypatch.setenv("PQCA_GATEWAY_API_PREFIX", prefix)
    with pytest.raises(ValidationError, match="api_prefix"):
        Settings()
