#!/bin/sh
# Runs once on first database init. Grafana gets a read-only role that can
# see every table and view the scanner creates later.
set -eu
psql -v ON_ERROR_STOP=1 -v pw="$GRAFANA_DB_PASSWORD" -U "$POSTGRES_USER" -d "$POSTGRES_DB" <<'SQL'
CREATE ROLE grafana LOGIN PASSWORD :'pw';
GRANT USAGE ON SCHEMA public TO grafana;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO grafana;
SQL
