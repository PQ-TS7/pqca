# Decisions (append-only)

Format: `- YYYY-MM-DD — decision. Why (if given). — who`
To change one, add a new line that says what it supersedes.

- 2026-10-12 — RA is its own service, separate from the CA. — team
- 2026-10-20 — AI CSR validation engine (RA AI, J09/FR19) removed; RA does deterministic HTTP-01/DNS-01 only. — team
- 2026-10-20 — AI chatbot split into internal admin copilot + external customer support bot. — team
- 2026-10-20 — Add AI Organization Validation agent with DUNS lookup. — team
- 2026-11-15 — OV requires mandatory human review; the agent only recommends (`clear` / `needs_attention` / `reject_recommended` / `abstain`). — team
- 2026-11-15 — Organizations without a DUNS number are allowed (never `clear`, always reviewed). — team
- 2026-11-15 — OV extracted fields stored as rows, not JSON; AI assessment and human review in separate tables. — team
- 2026-11-15 — Uploaded OV documents stored inside the database (`ov_document_contents`). — team
- 2026-11-15 — Monorepo, one Dockerfile per component, Kubernetes for the whole system; no Docker Compose. — team
- 2026-11-16 — No EJBCA. Every CA/RA/OCSP/CRL component is our own implementation; no EJBCA lab or benchmarks. Supersedes the earlier plan to deploy EJBCA CE first. — team
- 2026-11-16 — Claude Code context lives in `claude-context/`, enforced by hooks in `.claude/`. — andrew
