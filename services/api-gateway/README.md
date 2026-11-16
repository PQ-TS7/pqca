# api-gateway

FastAPI entry point for the portals and the REST API. Right now it has the app skeleton only: configuration, CORS, health probes and the database lifecycle. Auth, RBAC and the real endpoints come next.

```
src/api_gateway/
├── main.py            create_app(): builds the app (CORS, routers, DB lifecycle)
├── config.py          Settings: PQCA_GATEWAY_* env vars (Pydantic Settings)
├── dependencies.py    get_settings(), get_db()
└── api/
    ├── router.py      /api/v1 router; feature routers get included here
    └── routes/
        └── health.py  /healthz (liveness), /readyz (readiness, pings the DB)
```

## Run it locally

From the repo root:

```bash
pip install -e packages/pqca-common -e "services/api-gateway[test]"
cp services/api-gateway/.env.example services/api-gateway/.env   # then fill in PQCA_DB_PASSWORD
cd services/api-gateway
uvicorn api_gateway.main:create_app --factory --reload --env-file .env
```

Then open http://localhost:8000/docs (docs are on in dev, off in prod) and http://localhost:8000/healthz. `/readyz` returns 503 until the database is reachable.

## Configuration

Gateway settings use the `PQCA_GATEWAY_` prefix; database settings use `PQCA_DB_*` and are documented in `packages/pqca-common/README.md`.

| Variable | Default | Notes |
|---|---|---|
| `PQCA_GATEWAY_ENVIRONMENT` | `dev` | `dev` / `test` / `prod` |
| `PQCA_GATEWAY_ENABLE_DOCS` | on unless `prod` | Swagger UI + `openapi.json` |
| `PQCA_GATEWAY_API_PREFIX` | `/api/v1` | |
| `PQCA_GATEWAY_CORS_ALLOW_ORIGINS` | none (dev: `localhost:3000`, `localhost:5173`) | comma-separated or JSON list |
| `PQCA_GATEWAY_CORS_ALLOW_METHODS` | `GET,POST,PUT,PATCH,DELETE` | |
| `PQCA_GATEWAY_CORS_ALLOW_HEADERS` | `Authorization,Content-Type` | |
| `PQCA_GATEWAY_CORS_ALLOW_CREDENTIALS` | `false` | can't be combined with `*` |
| `PQCA_GATEWAY_CORS_MAX_AGE_S` | `600` | |

CORS is closed by default: in production the SPA is served by Nginx on the same origin, so no cross-origin access is needed. `*` is rejected in `prod` and whenever credentials are on. Origins must look like `https://host[:port]`, with no trailing slash.

## Tests

```bash
pytest services/api-gateway
```

These need no database; they use a fake.
