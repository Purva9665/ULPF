-- -------------------------------------------------------------------
-- ULPF PostgreSQL Role Initialisation
-- Run this as the postgres superuser ONCE per installation.
-- Creates: databases + roles + service accounts
-- -------------------------------------------------------------------

-- -- Databases -------------------------------------------------------
CREATE DATABASE ulpf_raw;
CREATE DATABASE ulpf_siem;
CREATE DATABASE ulpf_datalake;

-- -- Group roles (no login) ------------------------------------------

-- svc_collector: write raw events only (log agents / REST API)
CREATE ROLE ulpf_collector NOLOGIN;
-- svc_processor: read raw, write processed (ULPF engine)
CREATE ROLE ulpf_processor NOLOGIN;
-- svc_analyst: read processed data only (dashboards, SOC analysts)
CREATE ROLE ulpf_analyst NOLOGIN;

-- -- Permissions on ulpf_raw -----------------------------------------
GRANT CONNECT ON DATABASE ulpf_raw TO ulpf_collector, ulpf_processor;

\connect ulpf_raw;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ulpf_collector, ulpf_processor;
-- Collector: INSERT only on raw_events
GRANT INSERT ON ALL TABLES IN SCHEMA public TO ulpf_collector;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ulpf_collector;
-- Processor: SELECT + limited UPDATE (mark processed)
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ulpf_processor;
GRANT UPDATE (processed, processed_at) ON raw_events TO ulpf_processor;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT INSERT ON TABLES TO ulpf_collector;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO ulpf_processor;

-- -- Permissions on ulpf_siem ----------------------------------------
GRANT CONNECT ON DATABASE ulpf_siem TO ulpf_processor, ulpf_analyst;

\connect ulpf_siem;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ulpf_processor, ulpf_analyst;
-- Processor: INSERT/UPDATE siem_events
GRANT INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO ulpf_processor;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ulpf_processor;
-- Analyst: SELECT only
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ulpf_analyst;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT INSERT, UPDATE ON TABLES TO ulpf_processor;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO ulpf_analyst;

-- -- Permissions on ulpf_datalake ------------------------------------
GRANT CONNECT ON DATABASE ulpf_datalake TO ulpf_processor, ulpf_analyst;

\connect ulpf_datalake;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ulpf_processor, ulpf_analyst;
GRANT INSERT ON ALL TABLES IN SCHEMA public TO ulpf_processor;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO ulpf_processor;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO ulpf_analyst;

ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT INSERT ON TABLES TO ulpf_processor;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO ulpf_analyst;

-- -- Service account login users -------------------------------------
-- CHANGE PASSWORDS before production deployment!
CREATE USER svc_collector WITH PASSWORD 'ulpf_coll_changeme' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE USER svc_ulpf      WITH PASSWORD 'ulpf_proc_changeme' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE USER svc_analyst   WITH PASSWORD 'ulpf_anly_changeme' NOSUPERUSER NOCREATEDB NOCREATEROLE;

GRANT ulpf_collector TO svc_collector;
GRANT ulpf_processor TO svc_ulpf;
GRANT ulpf_analyst   TO svc_analyst;

-- -- Done -------------------------------------------------------------
-- Next step: run backend/storage/schema.sql against each database.