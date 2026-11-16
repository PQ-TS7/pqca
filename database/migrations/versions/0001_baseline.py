"""baseline: the schema created by database/init/001-007

Revision ID: 0001
Revises:
Create Date: 2026-11-16

This revision creates nothing. The initial schema is built by the SQL in
database/init/ when the database image starts on an empty volume; Alembic
takes over from here. Running `alembic upgrade head` on such a database just
records 0001 in the alembic_version table.

It does check that init/001-007 really ran, so a bare or half-built database
fails loudly instead of being marked as up to date.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# One or more objects from each init script is enough to tell it ran.
_REQUIRED_TABLES = {"organizations", "users", "certificates", "audit_logs", "lessons"}
_REQUIRED_FUNCTIONS = {"forbid_modify", "reserve_serial", "audit_log"}
_REQUIRED_ROLES = {"pqca_gateway", "pqca_ca_engine", "pqca_auditor"}


def upgrade() -> None:
    if context.is_offline_mode():
        return  # `--sql` has no database to inspect

    bind = op.get_bind()
    tables = set(
        bind.execute(sa.text("SELECT tablename::text FROM pg_tables WHERE schemaname = 'public'")).scalars()
    )
    functions = set(
        bind.execute(
            sa.text(
                "SELECT p.proname::text FROM pg_proc p "
                "JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'public'"
            )
        ).scalars()
    )
    roles = set(bind.execute(sa.text("SELECT rolname::text FROM pg_roles")).scalars())

    missing = sorted(
        [f"table {name}" for name in _REQUIRED_TABLES - tables]
        + [f"function {name}()" for name in _REQUIRED_FUNCTIONS - functions]
        + [f"role {name}" for name in _REQUIRED_ROLES - roles]
    )
    if missing:
        raise RuntimeError(
            "Baseline 0001 expects database/init/001-007 to have run, but this database "
            f"is missing: {', '.join(missing)}. Start it from the pqca/database image "
            "(see README.md, 'database/') on an empty volume, then run the migration again."
        )


def downgrade() -> None:
    raise NotImplementedError(
        "0001 is the baseline; downgrading it would mean dropping the whole schema. "
        "To start over, recreate the database from database/init/."
    )
