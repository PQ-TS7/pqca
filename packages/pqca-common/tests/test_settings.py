import pytest

from pqca_common.db import DatabaseConfigError, DatabaseSettings, build_url

BASE_ENV = {
    "PQCA_DB_HOST": "postgres",
    "PQCA_DB_NAME": "pqca",
    "PQCA_DB_USER": "gateway_svc",
    "PQCA_DB_PASSWORD": "p@ss:/word",
}


def test_reads_required_values_and_defaults():
    settings = DatabaseSettings.from_env(BASE_ENV)

    assert (settings.host, settings.name, settings.user) == ("postgres", "pqca", "gateway_svc")
    assert settings.port == 5432
    assert settings.sslmode == "prefer"


def test_password_file_wins_over_env(tmp_path):
    secret = tmp_path / "password"
    secret.write_text("from-file\n", encoding="utf-8")

    settings = DatabaseSettings.from_env({**BASE_ENV, "PQCA_DB_PASSWORD_FILE": str(secret)})

    assert settings.password == "from-file"


def test_unreadable_password_file_is_a_config_error(tmp_path):
    with pytest.raises(DatabaseConfigError, match="PASSWORD_FILE"):
        DatabaseSettings.from_env({**BASE_ENV, "PQCA_DB_PASSWORD_FILE": str(tmp_path / "missing")})


@pytest.mark.parametrize("key", ["PQCA_DB_HOST", "PQCA_DB_NAME", "PQCA_DB_USER", "PQCA_DB_PASSWORD"])
def test_missing_required_value_is_a_config_error(key):
    env = {k: v for k, v in BASE_ENV.items() if k != key}

    with pytest.raises(DatabaseConfigError):
        DatabaseSettings.from_env(env)


def test_rejects_unknown_sslmode():
    with pytest.raises(DatabaseConfigError, match="SSLMODE"):
        DatabaseSettings.from_env({**BASE_ENV, "PQCA_DB_SSLMODE": "on"})


def test_rejects_non_numeric_port():
    with pytest.raises(DatabaseConfigError, match="PORT"):
        DatabaseSettings.from_env({**BASE_ENV, "PQCA_DB_PORT": "five"})


def test_password_never_appears_in_repr_or_url_string():
    settings = DatabaseSettings.from_env(BASE_ENV)

    assert "p@ss" not in repr(settings)
    assert "p@ss" not in str(build_url(settings))


def test_url_escapes_password():
    url = build_url(DatabaseSettings.from_env(BASE_ENV))

    assert url.password == "p@ss:/word"
    assert url.render_as_string(hide_password=False).startswith("postgresql+asyncpg://gateway_svc:p%40ss%3A%2Fword@")
