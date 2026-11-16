# PQ-CA

A post-quantum certificate authority. This repo holds every service, the database schema, the deployment manifests and the tests, all in one place.

Right now most folders are empty placeholders (they only contain a `.gitkeep`). The database schema is the only part with real code. This README explains what each folder is for, so new code lands in the right place.

## Layout

```
pqca/
├── services/          One folder per deployable service
├── packages/          Shared Python code used by several services
├── database/          PostgreSQL image, schema and migrations
├── deploy/k8s/        Kubernetes manifests (Kustomize base + overlays)
├── images/            Base container images
├── infra/             Infrastructure outside the cluster
├── offline-root/      Offline root CA material and procedures
├── tests/             Cross-service test suites
├── docs/              Design docs and decisions
├── claude-context/    Shared Claude Code memory (state, decisions, session logs)
├── .claude/           Claude Code hooks and shared settings
└── .github/workflows/ CI pipelines
```

## services/

Each subfolder is one container. A service owns its own code, Dockerfile and dependencies.

| Service | What it does |
|---|---|
| `api-gateway` | FastAPI entry point for the customer portal and the REST API |
| `admin-portal` | Web UI for CA operators, RA officers and auditors |
| `ra-service` | Registration authority: domain challenges and the RA officer review queue |
| `ov-agent` | AI organization-validation agent. It checks documents and recommends; a human always makes the final call |
| `ca-engine` | Signs certificates. Reserves a serial before signing |
| `crl-generator` | Builds and publishes certificate revocation lists |
| `ocsp-responder` | Answers OCSP status queries (read-only) |
| `ai-copilot` | Internal assistant for staff |
| `ai-support-bot` | Public customer chatbot |
| `jobs` | Scheduled sweepers (expiring challenges, cleanup, etc.) |

Each service connects to Postgres with its own login and gets only the grants it needs. See `database/init/006_roles_grants.sql`.

## packages/

Code that more than one service needs. Services import from here; packages never import from services.

- `pqca-common`: logging, config, errors and other plumbing
- `pqca-crypto`: post-quantum and classical crypto helpers (keys, signing, certificate building)
- `pqca-models`: shared data models and schemas

If something is only used by one service, keep it inside that service. Move it here once a second service needs it.

## database/

PostgreSQL 16 with the full PQ-CA schema.

- `Dockerfile` copies `init/` into the Postgres entrypoint. Build it from the repo root:
  ```
  docker build -f database/Dockerfile -t pqca/database:dev .
  ```
- `init/` runs once, in filename order, on an empty data volume:

  | File | Contents |
  |---|---|
  | `001_domain_validation.sql` | RA policy, organizations, certificate requests, SANs, domain challenges and attempts |
  | `002_organization_validation.sql` | Users, OV applications, uploaded documents, AI assessments, human reviews |
  | `003_pki_core.sql` | Issuing CAs, serial reservations, certificates, revocations, CRLs |
  | `004_audit.sql` | Append-only, hash-chained audit log |
  | `005_ai_assistants.sql` | Assistant feedback and the reviewed "lessons learned" pipeline |
  | `006_roles_grants.sql` | One group role per service with least-privilege grants |
  | `007_logins.sh` | Creates one login per service; passwords come from environment variables |

- `migrations/` is for schema changes after the initial setup. Don't edit the `init/` files once a database is running somewhere; add a migration instead.

Many rules are enforced in the database itself through triggers and constraints (immutable certificates, no self-approval, audit entries can't be edited). Read the header comment of each file before changing it.

## deploy/k8s/

Kustomize layout.

- `base/` has one folder per component: every service above, plus `postgres`, `chromadb` (vector store for the AI assistants), `ollama` (local LLM runtime) and `network-policies`.
- `overlays/dev` and `overlays/prod` patch the base for each environment (replicas, resources, secrets, image tags).

When you add a service, add a matching folder under `base/`.

## Other folders

- `images/oqs-base/`: base image with Open Quantum Safe (liboqs / oqs-provider) built in. Services that do post-quantum crypto build on top of it.
- `infra/`: anything provisioned outside Kubernetes (cluster setup, networking, cloud resources).
- `offline-root/`: offline root CA scripts and key ceremony procedures. This never runs in the cluster.
- `tests/`
  - `integration/`: tests that run several services together
  - `load/`: load and performance tests
  - `ai-eval/`: evaluation sets for the AI agent and assistants
- `docs/`: architecture notes, decision records, requirements.
- `.github/workflows/`: CI.
- `CLAUDE.md`, `claude-context/`, `.claude/`: instructions and shared memory for Claude Code. See `claude-context/README.md`.

Unit tests live inside each service or package, next to the code they test. `tests/` is only for suites that span services.

## Ground rules

- No secrets in the repo. Passwords and keys come from environment variables or Kubernetes Secrets.
- Services talk to each other over APIs, not by importing each other's code.
- The database is the source of truth. Redis is only for rate-limit counters.
