import pytest
from fastapi.testclient import TestClient

from api_gateway.config import Settings
from api_gateway.main import create_app


class FakeDatabase:
    """Stands in for pqca_common.db.Database; no PostgreSQL needed."""

    def __init__(self, ping_error: Exception | None = None) -> None:
        self.ping_error = ping_error

    async def ping(self) -> None:
        if self.ping_error:
            raise self.ping_error

    async def dispose(self) -> None:
        pass


def make_client(db=None, **settings) -> TestClient:
    app = create_app(Settings(**settings), db=db or FakeDatabase())
    return TestClient(app)


def test_liveness():
    with make_client() as client:
        response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_readiness_ok():
    with make_client() as client:
        response = client.get("/readyz")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_readiness_503_when_database_is_down():
    with make_client(db=FakeDatabase(ConnectionRefusedError("boom"))) as client:
        response = client.get("/readyz")
    assert response.status_code == 503
    assert response.json() == {"detail": "database unavailable"}  # no internals leaked


def test_cors_allows_a_listed_origin():
    with make_client(cors_allow_origins=["https://portal.example"]) as client:
        response = client.options(
            "/healthz",
            headers={
                "Origin": "https://portal.example",
                "Access-Control-Request-Method": "GET",
            },
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "https://portal.example"


def test_cors_rejects_an_unlisted_origin():
    with make_client(cors_allow_origins=["https://portal.example"]) as client:
        response = client.options(
            "/healthz",
            headers={
                "Origin": "https://evil.example",
                "Access-Control-Request-Method": "GET",
            },
        )
    assert "access-control-allow-origin" not in response.headers


def test_prod_has_no_cors_by_default():
    with make_client(environment="prod") as client:
        response = client.get("/healthz", headers={"Origin": "http://localhost:5173"})
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize(("environment", "status"), [("dev", 200), ("prod", 404)])
def test_docs_follow_the_environment(environment, status):
    with make_client(environment=environment) as client:
        assert client.get("/docs").status_code == status
