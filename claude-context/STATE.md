# Project state

_Last updated: 2026-11-16 — andrewbassily_

## Done
- Repo skeleton: services/, packages/, database/, deploy/k8s/ (Kustomize), images/oqs-base/, offline-root/, tests/, docs/.
- Database schema `database/init/001`–`007` (domain validation, OV, PKI core, audit, AI assistants, roles/grants, per-service logins).
- `CLAUDE.md` + `claude-context/` system.
- OQS base image `images/oqs-base/` (OpenSSL 3.5.9 + liboqs 0.16.0 + oqs-provider 0.12.0); build-time `oqs-selftest` passes for ML-DSA-44/65/87 and hybrid `p384_mldsa65`.
- DB access layer: `packages/pqca-common` (`pqca_common.db`: env settings, asyncpg engine, `Database.transaction()` with audit actor/IP context) and `packages/pqca-models` (`Base`). Tested against the real schema image.

## In progress
- (nothing recorded yet)

## Next
- CI job: build `pqca/oqs-base` and run `oqs-selftest`.
- SoftHSM2 slot setup + confirm ML-DSA keygen/sign over PKCS#11.
- PoC CLI issuance: ML-DSA CSR → RFC 9881 cert, verified with `openssl verify`.
- Kustomize base for postgres.
- ORM models for the schema tables in `pqca-models`.
- CI job running `pqca-common` DB tests against the `pqca/database` image.

## Open questions
- Pure ML-DSA provider: on OpenSSL 3.5 it's native (`@ default`), oqsprovider only adds hybrids. Keep that, or pin older OpenSSL so oqsprovider serves ML-DSA?
- SoftHSM2 ML-DSA support (PKCS#11 3.2) — fallback if missing?
- DUNS / D&B API access — mock provider until resolved.
- OCSP: own microservice (current plan) vs. external component (earlier diagrams).
- ACME out of scope but referenced in proposal §10.5.
- External chatbot needs its own FR in the proposal.
- Secret storage for prod: see `docs/adr/0001-secret-storage.md` (Proposed: Sealed Secrets for prod, secretGenerator for dev).
