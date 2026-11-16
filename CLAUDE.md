# CLAUDE.md — PQ-CA (Post-Quantum TLS Certificate Authority)

Graduation project (Gigabyte Bridge program). A post-quantum TLS CA built as microservices: ML-DSA signing via OpenSSL 3.x + oqs-provider, a separate RA, an AI-assisted Organization Validation (OV) agent, and two local-LLM assistants.

Source of truth for scope and ownership: the proposal (V0.4), *Optional Roles Assign V1.4*, the *Comparative Study on PQC Algorithms* and the team's task breakdown (kept outside this repo), plus `claude-context/DECISIONS.md`. If they disagree, the newest entry in DECISIONS.md wins; otherwise ask before acting.

---

## Context system (read first, update last)

`claude-context/` is Claude Code's shared, committed memory for this repo. Everyone on the team uses it, so keep it factual and short.

These load automatically every session:

@claude-context/STATE.md
@claude-context/DECISIONS.md
@claude-context/GOTCHAS.md

**At session start:** the SessionStart hook prints the latest session logs. Read the most recent one(s) that touch the area you're working on.

**Before you finish any session that changed files**, update the context (the Stop hook blocks until you do):
1. Create `claude-context/sessions/YYYY-MM-DD_<author>_<topic>.md` from `claude-context/sessions/_TEMPLATE.md` (author = `git config user.name`, lowercase, no spaces). One file per session — never edit another person's session file.
2. Update `STATE.md` if status, in-progress work or next steps changed.
3. Append to `DECISIONS.md` for any decision the user made (date, decision, why, who). Never rewrite past entries — supersede them with a new one.
4. Add to `GOTCHAS.md` anything that cost time and will bite again (a failing command and its fix, an env quirk).

Rules: only record what actually happened or what the user decided — no guesses, no plans you invented. No secrets, passwords, keys or personal data. If the user says "skip context", skip it.

---

## Hard rules (do not break these)

1. **Issuance order is enforced:** OV `accepted` → domain validation passed → signing. Never add a path that signs a cert without both gates.
2. **The AI never decides OV.** Only an `ov_reviews` row (human RA officer) can set an organization to `accepted` / `rejected`. The OV agent writes `ov_assessments` only (advisory: `clear` / `needs_attention` / `reject_recommended` / `abstain`). The DB refuses `clear` unless every deterministic check passed.
3. **No AI in the RA.** The AI CSR validation engine (J09 / FR19) was removed. RA = deterministic HTTP-01 / DNS-01 only.
4. **Data boundaries for AI:**
   - All LLM inference is local (Ollama + ChromaDB). `ollama` and `chromadb` have **no internet egress**.
   - `ov-agent` is the only service allowed outbound HTTPS, and only to the DUNS provider, sending minimal identifiers (name, registration no., DUNS). Never send documents, PKI config or key material.
   - Internal copilot: recommendations only, no HSM / CA-key permissions, no autonomous actions, no fine-tuning (corrections live in the Lessons knowledge base).
   - External support bot: public docs / FAQs only — no telemetry, admin logs, CA config or other customers' data. DB grant is `INSERT` on `assistant_feedback` and nothing else.
5. **Secrets never in files.** DB passwords and keys come from Kubernetes Secrets / env vars. No passwords in SQL, manifests or code.
6. **Keys:** Root CA is offline / air-gapped (manual one-way USB). Intermediate CA key sits behind PKCS#11 (SoftHSM2). Never write private keys to the repo, logs or the DB.
7. **Audit log is append-only and hash-chained.** Nobody gets `INSERT` on `audit_logs`; write through `audit_log(...)` and triggers.
8. **Our own implementation only — no EJBCA.** Don't add, deploy, depend on or benchmark against EJBCA (or any other off-the-shelf CA platform). Every CA/RA/OCSP/CRL component is built in this repo.

---

## Tech stack

| Layer | Choice |
|---|---|
| Crypto | OpenSSL 3.x + liboqs + oqs-provider; ML-DSA-44/65/87 (FIPS 204), RFC 9881 certs |
| Key storage | SoftHSM2 via PKCS#11 (python-pkcs11 / PyKCS11) |
| Services | Python 3.11+, FastAPI, SQLAlchemy 2.0 / asyncpg |
| Database | PostgreSQL 16 (Redis only for rate-limit counters) |
| CRL | Background worker (Celery / cron), RFC 5280 v2 CRLs signed ML-DSA-65, served by Nginx |
| OCSP | FastAPI responder, in-memory cache synced via `LISTEN cert_revoked`, target ≤ 50 ms local |
| Frontend | React 18 SPA (admin + customer portal) behind Nginx, JWT + MFA |
| AI | Ollama (open-weights), ChromaDB (separate collections per assistant) |
| Deploy | **Kubernetes** (Kustomize) for the whole system. One Dockerfile per component. **No Docker Compose.** |
| CI/CD | GitHub Actions — lint, build images, unit tests, deploy |

OIDs: ML-DSA-44 `2.16.840.1.101.3.4.3.17`, ML-DSA-65 `…3.18`, ML-DSA-87 `…3.19`.

---

## Repository layout (monorepo)

```
pqca/
├── services/            # one folder per container (own code, Dockerfile, deps)
│   ├── api-gateway/     # AuthN/Z, RBAC, rate limiting, OV + domain gates
│   ├── admin-portal/    # React admin + customer portal
│   ├── ra-service/      # HTTP-01 / DNS-01 challenges, RA officer review queue
│   ├── ov-agent/        # extraction → comparison → DUNS → assessment
│   ├── ca-engine/       # signing; reserves a serial before signing
│   ├── crl-generator/
│   ├── ocsp-responder/  # read-only
│   ├── ai-copilot/      # internal admin copilot (RAG + Lessons Learned)
│   ├── ai-support-bot/  # external customer chatbot (RAG, public docs)
│   └── jobs/            # scheduled sweepers
├── packages/            # shared Python: pqca-common, pqca-crypto, pqca-models
├── database/            # Dockerfile, init/ (001–007), migrations/
├── deploy/k8s/          # Kustomize: base/<component>/, overlays/dev, overlays/prod
├── images/oqs-base/     # OpenSSL 3 + liboqs + oqs-provider base image
├── infra/               # anything provisioned outside Kubernetes
├── offline-root/        # offline root CA scripts + key ceremony (never in-cluster)
├── tests/               # cross-service only: integration/, load/, ai-eval/
├── docs/                # architecture notes, decision records, requirements
├── claude-context/      # Claude Code's shared memory — see "Context system" below
└── .github/workflows/   # CI
```

- Services talk over APIs, never by importing each other's code.
- `packages/` never imports from `services/`. Keep code inside a service until a second service needs it.
- Unit tests live next to the code; `tests/` is only for suites spanning services.
- New service → also add `deploy/k8s/base/<service>/`.
- Most folders are still `.gitkeep` placeholders; the database schema is the only real code so far.

---

## Database

PostgreSQL 16. Image: `docker build -f database/Dockerfile -t pqca/database:dev .` (from repo root).
Scripts in `database/init/`, applied once in filename order on an empty volume. **Never edit `init/` once a database runs somewhere — add a file under `database/migrations/`.**

| File | Contents |
|---|---|
| `001_domain_validation.sql` | organizations, RA policy, certificate requests, domain challenges, `forbid_modify()` |
| `002_organization_validation.sql` | users, OV applications / documents / contents / assessments / extracted fields / comparisons / DUNS lookups / follow-ups / reviews, review-queue view |
| `003_pki_core.sql` | issuing CAs, serial reservations, certificates, revocations, CRLs |
| `004_audit.sql` | hash-chained `audit_logs`, `audit_log()`, `audit_verify_chain()` |
| `005_ai_assistants.sql` | `assistant_feedback`, `lessons`, `lesson_versions`, retrievable-lessons view |
| `006_roles_grants.sql` | one NOLOGIN group role per service, least-privilege grants |
| `007_logins.sh` | one LOGIN per service from env vars (Kubernetes Secret) |

Conventions:
- **Rules live in the database.** Triggers and `SECURITY DEFINER` functions (fixed `search_path`) enforce state transitions; services hold only the grants they need. When adding a table, add its grants in `006` for the services that need it — nothing is granted by default.
- Evidence and decision rows are **frozen** after insert (`forbid_modify()`); don't add UPDATE/DELETE paths for them.
- OV extracted fields are **rows, not JSON**. AI assessment and human review are **separate tables**.
- Uploaded OV documents are stored **in the DB** (`ov_document_contents`, BYTEA, 25 MB cap), separate from metadata, purged by `purge_expired_ov_documents()`.
- Organizations **without a DUNS** are allowed; they can never be `clear` and always need reviewer attention.
- Multi-KB PQC certs and CRLs → `BYTEA`. Serials from `reserve_serial()`, never generated in app code.
- PostgreSQL 15+/16 features are fine (`UNIQUE NULLS NOT DISTINCT`, `gen_random_uuid()`, pgcrypto `digest`).

Service ↔ DB role map: gateway `pqca_gateway`, RA `pqca_ra`, OV agent `pqca_ov_agent`, CA engine `pqca_ca_engine`, CRL `pqca_crl`, OCSP `pqca_ocsp` (read-only), copilot `pqca_copilot`, support bot `pqca_support_bot`, cron jobs `pqca_jobs`, auditor `pqca_auditor`.

---

## Roles (RBAC)

`super_admin`, `ca_operator`, `auditor`, `ra_officer` (OV review), `applicant`, plus a **Lesson Reviewer** permission. No self-approval: a reviewer can't review an OV application they submitted, and nobody approves their own lesson.

---

## Ownership

| Area | Owner |
|---|---|
| API gateway, crypto provider / OQS image, internal copilot | Mohamed Mohsen |
| Cert profiles, PQC specs, Root CA runbook, OV agent | Marawan Ahmed |
| CA issuing engine, CRL daemon, tests / QA | Mariam Hazem Gamgoum |
| RA & domain validation, OCSP, external support bot | Mariam Ramy |
| Database, containers / Kubernetes, CI/CD | Andrew Rami |
| Admin & customer portal, IAM / RBAC, audit explorer, browser trust stores | Seif Aly |
| PM, network & TLS tuning, Linux hardening, DMZ / ZeroTier | Saif Wael |

---

## Working in this repo

- Work strictly from real output (logs, `openssl` / `kubectl` / `psql` results). Don't assume a command worked — show how to verify it.
- Prefer exact commands over long explanations.
- Before changing a DB script, check what later scripts (`003`–`007`) depend on it.
- Verify PQ support with `openssl list -signature-algorithms -provider oqsprovider` (expect `mldsa44`, `mldsa65`, `mldsa87`).
- Tests: Pytest for services; OV labeled set target ≥ 90% correct assessments; copilot Q&A set > 90% accuracy, < 3 s latency.

## Open questions (don't silently pick an answer)

- SoftHSM2 ML-DSA support over PKCS#11 (3.2) — confirm, else decide a fallback before M2.
- D&B / DUNS API access — use a mock provider (`provider = 'mock'`) until resolved.
- OCSP: planned as its own microservice (`services/ocsp-responder`); earlier diagrams showed it as external. Confirm with the team.
- ACME is out of scope but referenced in proposal §10.5 — reconcile.
- External chatbot needs its own FR in the proposal.
