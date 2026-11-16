# pqca-common

Shared plumbing for PQ-CA services. So far: `pqca_common.db`, the PostgreSQL connection and session setup (SQLAlchemy 2.0 async + asyncpg). The ORM base class is in `pqca-models`.

## Configuration

Each service reads the same variables. Its Kubernetes manifest sets them to that service's own login (`gateway_svc`, `ra_svc`, ...; see `database/init/007_logins.sh`).

| Variable | Default | Notes |
|---|---|---|
| `PQCA_DB_HOST` | required | |
| `PQCA_DB_PORT` | `5432` | |
| `PQCA_DB_NAME` | required | |
| `PQCA_DB_USER` | required | the service's login, e.g. `gateway_svc` |
| `PQCA_DB_PASSWORD_FILE` | | path to a mounted Secret; wins over `PQCA_DB_PASSWORD` |
| `PQCA_DB_PASSWORD` | | from a `secretKeyRef`, if you don't mount a file |
| `PQCA_DB_SSLMODE` | `prefer` | `disable` / `prefer` / `require` / `verify-ca` / `verify-full` |
| `PQCA_DB_APP_NAME` | `pqca` | shows in `pg_stat_activity` |
| `PQCA_DB_POOL_SIZE`, `PQCA_DB_MAX_OVERFLOW` | `5`, `5` | per process |
| `PQCA_DB_POOL_TIMEOUT_S`, `PQCA_DB_POOL_RECYCLE_S` | `10`, `1800` | |
| `PQCA_DB_CONNECT_TIMEOUT_S` | `5` | |
| `PQCA_DB_STATEMENT_TIMEOUT_MS` | `30000` | server-side `statement_timeout` |
| `PQCA_DB_IDLE_IN_TX_TIMEOUT_MS` | `60000` | server-side `idle_in_transaction_session_timeout` |

## Usage

```python
from pqca_common.db import Database

db = Database.from_env()

async with db.transaction(actor_id=user.id, client_ip=request.client.host) as session:
    session.add(...)
    await session.execute(text("SELECT audit_log('certificate.revoke', 'certificate', :id)"), {"id": serial})
# committed here; any exception rolls back
```

- One `transaction()` = one database transaction. Don't call `session.commit()` inside it.
- `actor_id` / `client_ip` become `pqca.actor_id` / `pqca.client_ip` for that transaction only. `audit_log()` and the audit triggers read them. `actor_id` must be an existing `users.user_id` (foreign key).
- `await db.ping()` is for readiness probes. Call `await db.dispose()` on shutdown.

FastAPI example:

```python
@asynccontextmanager
async def lifespan(app):
    app.state.db = Database.from_env()
    yield
    await app.state.db.dispose()

async def db_session(request: Request, user: User = Depends(current_user)):
    async with request.app.state.db.transaction(actor_id=user.id, client_ip=request.client.host) as session:
        yield session
```

## Tests

```bash
pip install -e "packages/pqca-common[test]" -e "packages/pqca-models[test]"
pytest packages/pqca-common packages/pqca-models          # unit tests; DB tests skip
```

The DB tests run against the real schema image. The passwords are throwaway values, generated in the shell and never written to a file:

```bash
docker build -f database/Dockerfile -t pqca/database:dev .
PW=$(python -c "import secrets; print(secrets.token_urlsafe(18))")
docker run -d --name pqca-db-test -p 55432:5432 -e POSTGRES_DB=pqca -e POSTGRES_PASSWORD="$PW" \
  $(for v in GATEWAY RA OV_AGENT CA_ENGINE OCSP CRL COPILOT SUPPORT_BOT JOBS AUDITOR; do echo -n "-e ${v}_DB_PASSWORD=$PW "; done) \
  pqca/database:dev
# wait until `docker logs pqca-db-test` shows "init process complete" and pg_isready passes, then:
PQCA_TEST_DB_HOST=127.0.0.1 PQCA_TEST_DB_PORT=55432 \
PQCA_TEST_GATEWAY_PASSWORD="$PW" PQCA_TEST_SUPPORT_BOT_PASSWORD="$PW" \
  pytest -v packages/pqca-common packages/pqca-models
docker rm -f pqca-db-test
```
