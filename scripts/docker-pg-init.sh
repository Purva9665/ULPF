#!/bin/bash
# docker-pg-init.sh
# Creates multiple PostgreSQL databases on first container start.
# Called automatically by the postgres Docker entrypoint.
set -e

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" <<-EOSQL
    CREATE DATABASE ulpf_raw;
    CREATE DATABASE ulpf_siem;
    CREATE DATABASE ulpf_datalake;
EOSQL

echo "Created databases: ulpf_raw, ulpf_siem, ulpf_datalake"