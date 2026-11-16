# Project state

_Last updated: 2026-11-16 — andrew_

## Done
- Repo skeleton: services/, packages/, database/, deploy/k8s/ (Kustomize), images/oqs-base/, offline-root/, tests/, docs/.
- Database schema `database/init/001`–`007` (domain validation, OV, PKI core, audit, AI assistants, roles/grants, per-service logins).
- `CLAUDE.md` + `claude-context/` system.

## In progress
- (nothing recorded yet)

## Next
- OQS base image (`images/oqs-base/`) with ML-DSA-44/65/87 verified.
- SoftHSM2 slot setup + confirm ML-DSA keygen/sign over PKCS#11.
- PoC CLI issuance: ML-DSA CSR → RFC 9881 cert, verified with `openssl verify`.
- Kustomize base for postgres.

## Open questions
- SoftHSM2 ML-DSA support (PKCS#11 3.2) — fallback if missing?
- DUNS / D&B API access — mock provider until resolved.
- OCSP: own microservice (current plan) vs. external component (earlier diagrams).
- ACME out of scope but referenced in proposal §10.5.
- External chatbot needs its own FR in the proposal.
