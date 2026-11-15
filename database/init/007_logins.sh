#!/bin/bash
# Creates one login per service. Passwords come from the environment (Kubernetes Secret),
# never from this file. Runs once, after 001-006, on an empty data volume.
set -euo pipefail

create_login() {   # $1 = login, $2 = group role, $3 = password
  psql -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
       -v login="$1" -v grp="$2" -v pw="$3" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L IN ROLE %I', :'login', :'pw', :'grp') \gexec
SQL
}

create_login gateway_svc      pqca_gateway      "$GATEWAY_DB_PASSWORD"
create_login ra_svc           pqca_ra           "$RA_DB_PASSWORD"
create_login ov_agent_svc     pqca_ov_agent     "$OV_AGENT_DB_PASSWORD"
create_login ca_engine_svc    pqca_ca_engine    "$CA_ENGINE_DB_PASSWORD"
create_login ocsp_svc         pqca_ocsp         "$OCSP_DB_PASSWORD"
create_login crl_svc          pqca_crl          "$CRL_DB_PASSWORD"
create_login copilot_svc      pqca_copilot      "$COPILOT_DB_PASSWORD"
create_login support_bot_svc  pqca_support_bot  "$SUPPORT_BOT_DB_PASSWORD"
create_login jobs_svc         pqca_jobs         "$JOBS_DB_PASSWORD"
create_login auditor_svc      pqca_auditor      "$AUDITOR_DB_PASSWORD"
