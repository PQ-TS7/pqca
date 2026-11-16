# Gotchas

Things that cost time and will bite again. Format: `- **Symptom** — cause — fix.`

- **Editing `database/init/*.sql` has no effect on an existing DB** — init scripts only run on an empty data volume — add a migration under `database/migrations/`, or wipe the volume in dev.
- **Permission denied on a table from a service** — nothing is granted by default — add the grant in `006_roles_grants.sql` (or a migration) for that service's group role.
