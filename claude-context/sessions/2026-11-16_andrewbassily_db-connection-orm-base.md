# 2026-11-16 — PostgreSQL connections, sessions, ORM base

**Author:** andrewbassily  
**Area:** packages/pqca-common, packages/pqca-models

## Goal
Set up the PostgreSQL connection config, session management and the SQLAlchemy declarative base on top of the existing `database/` schema.

## Done
- `packages/pqca-common` (`pqca_common.db`):
  - `settings.py`: `DatabaseSettings.from_env()` reads `PQCA_DB_*`. The password comes from `PQCA_DB_PASSWORD_FILE` (mounted Secret, preferred) or `PQCA_DB_PASSWORD`, is kept out of `repr`, and the sslmode is validated.
  - `engine.py`: asyncpg `AsyncEngine` (URL built with `URL.create`, `pool_pre_ping`, server-side `application_name` / `statement_timeout` / `idle_in_transaction_session_timeout`).
  - `session.py`: `Database.transaction(actor_id=, client_ip=)` gives one transaction per block (commit on exit, rollback on exception). It sets `pqca.actor_id` / `pqca.client_ip` via `set_config(..., true)`, which `audit_log()` and the audit triggers read. Also `ping()` (readiness) and `dispose()`.
  - README with env vars, FastAPI usage and how to run the DB tests.
- `packages/pqca-models`: `pqca_models.Base` (`DeclarativeBase`) with a type map that matches the SQL (TEXT, BYTEA, UUID, TIMESTAMPTZ, NUMERIC, JSONB). Its docstring says: the schema is SQL-owned, no `create_all`, DB-generated columns use server defaults.
- No table models yet; only the base.

## Verified
- `pytest packages/pqca-common packages/pqca-models` (Python 3.12, SQLAlchemy 2.0.57, asyncpg 0.32.0): 13 passed, 9 skipped without a DB.
- Against `pqca/database:dev` (built from `database/Dockerfile`, all logins created by 007): 22 passed. That covers connecting as `gateway_svc`; actor and IP reaching `audit_logs` via `audit_log()`; the context not leaking to the next transaction on the same backend PID; rollback on exception; the support bot INSERT-only cases. `audit_verify_chain()` returned NULL (chain intact) afterwards.

## Decisions
- None by the user. Placement (connection/session in `pqca-common`, `Base` in `pqca-models`) follows the README descriptions of those packages.

## Left open / next
- ORM models for the 25 tables (pqca-models).
- `PQCA_DB_SSLMODE` defaults to `prefer`; the postgres image has no TLS yet. Prod overlay should use `verify-full` once TLS exists.
- Kustomize base for postgres (would set the `*_DB_PASSWORD` Secret and the `PQCA_DB_*` env for services).
- CI job to run these tests (needs the DB image as a service container).
- OCSP's `LISTEN cert_revoked` needs a raw asyncpg connection; not covered here.

## Follow-up: secret storage options
- Wrote `docs/adr/0001-secret-storage.md` (status **Proposed**): options A plain K8s Secrets / secretGenerator, B Sealed Secrets, C SOPS+age, D OpenBao/Vault + External Secrets, E Vault dynamic DB credentials, F cloud secret manager. Suggested: A for dev, B for prod, E later. Not decided; nothing added to DECISIONS.md.
- Not verified (documentation only).
