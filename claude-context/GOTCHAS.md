# Gotchas

Things that cost time and will bite again. Format: `- **Symptom** — cause — fix.`

- **Editing `database/init/*.sql` has no effect on an existing DB** — init scripts only run on an empty data volume — add a migration under `database/migrations/`, or wipe the volume in dev.
- **Permission denied on a table from a service** — nothing is granted by default — add the grant in `006_roles_grants.sql` (or a migration) for that service's group role.
- **`openssl genpkey -algorithm mldsa65 -propquery provider=oqsprovider` → unsupported** — on OpenSSL ≥ 3.5 pure ML-DSA is built into the default provider and oqsprovider 0.12 doesn't register it (only hybrids like `p384_mldsa65`) — drop the propquery; `openssl list -signature-algorithms` shows `ML-DSA-65 @ default`.
- **`docker` in Git Bash: "cannot find dockerDesktopLinuxEngine"** — Docker Desktop not running (installed at `G:\Docker` on andrew's machine) — start Docker Desktop, wait for `docker info`.
- **`permission denied for table assistant_feedback` (or `for sequence ..._seq`) from the support bot, though it has INSERT** — SQLAlchemy fetches the new PK via `RETURNING` (needs SELECT), or via `nextval()` when `implicit_returning=False` — use `insert(Model.__table__).inline().values(...)`. `session.add()` and plain `insert()` can't work under an INSERT-only grant.
- **`audit_logs_actor_id_fkey` violation from `audit_log()`** — `pqca.actor_id` / `actor_id=` must be an existing `users.user_id` — pass a real user, or no actor for system actions.
