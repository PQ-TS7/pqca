# Database migrations (Alembic)

**What this is.** `database/init/` builds the schema once, when the database starts empty. After that, every schema change is a *migration*: a small numbered Python file in `versions/` that changes the database from one version to the next. Alembic runs them in order and remembers the current version in a table called `alembic_version`. Everyone (laptops, dev, prod) ends up on the same schema by running the same files.

Layout:

```
database/
├── alembic.ini            config (no URL, no password)
└── migrations/
    ├── env.py             how Alembic connects (reads PQCA_DB_*)
    ├── script.py.mako     template for new migration files
    └── versions/
        └── 0001_baseline.py
```

`0001_baseline` creates nothing. It stands for "the database as built by `init/001`–`007`" and checks that this really is the case.

## Setup

From the repo root:

```bash
pip install -e packages/pqca-common "alembic>=1.13,<2"
```

Migrations must run as the schema owner (`postgres` in dev), **not** as a service login: those have no CREATE/ALTER rights. Use the same variables the services use:

```bash
export PQCA_DB_HOST=localhost PQCA_DB_PORT=55432 PQCA_DB_NAME=pqca PQCA_DB_USER=postgres
export PQCA_DB_PASSWORD=...        # the POSTGRES_PASSWORD you started the container with
```

## Everyday commands

```bash
alembic -c database/alembic.ini current                 # which version is this database on?
alembic -c database/alembic.ini upgrade head            # apply everything new
alembic -c database/alembic.ini history                 # list all migrations
alembic -c database/alembic.ini upgrade head --sql      # print the SQL, touch nothing (no DB needed)
alembic -c database/alembic.ini revision -m "add foo table" --rev-id 0002   # new empty migration
```

## Writing a migration

`--autogenerate` does not work here (there are no table models, by design), so write the SQL yourself in `upgrade()` with `op.execute("""...""")`. Follow the rules in `CLAUDE.md`:

- **Never edit `init/`.** Add a migration instead.
- **Grant explicitly.** Nothing is granted by default. If you add a table, add the `GRANT`s for the services that need it in the same migration (the way `006_roles_grants.sql` does).
- Triggers and helper functions that enforce rules: `SECURITY DEFINER` with a fixed `search_path = public, pg_temp`, like the existing ones.
- Evidence and decision rows stay frozen (`forbid_modify()`); don't add UPDATE/DELETE paths for them.
- Serials come from `reserve_serial()`, never from app code.
- No secrets, passwords or keys in a migration.
- Write a real `downgrade()` when it is safe; otherwise raise `NotImplementedError` with a reason.

Each migration runs in one transaction, so a failure leaves the database untouched. Revision ids are sequential (`0002`, `0003`, ...); if two people create the same number on different branches, renumber one before merging.

## Fresh database vs. existing database

- Fresh one built from `pqca/database`: `upgrade head` records `0001` and applies anything newer.
- A database that is already running and was never touched by Alembic: the same command works (the baseline is a no-op), no manual `stamp` needed.
- An empty database with no `init/` applied: `upgrade head` stops with an error naming what's missing.
