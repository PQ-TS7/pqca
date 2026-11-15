-- =====================================================================
-- PQ-CA — Database roles and least-privilege grants
-- PostgreSQL 15+   |   database/init/006_roles_grants.sql
-- Requires: 001 … 005. Run as the schema owner.
--
-- One group role per service (NOLOGIN). Create one login per container
-- and add it to its group, for example:
--     CREATE ROLE ca_engine_login LOGIN PASSWORD '...' IN ROLE pqca_ca_engine;
-- Passwords come from the deployment (.env / Docker secrets), never from
-- this file.
--
-- How the rules stay enforced with limited grants:
--   * Trigger and helper functions run as the schema owner
--     (SECURITY DEFINER, fixed search_path), so a service can cause a
--     side effect (e.g. "request becomes issued") without holding the
--     privilege to do it directly.
--   * Nobody gets INSERT on audit_logs; entries are written through
--     audit_log() and the triggers.
-- =====================================================================

DO $$
DECLARE r TEXT;
BEGIN
    FOREACH r IN ARRAY ARRAY[
        'pqca_gateway',      -- FastAPI API gateway (portal + REST API)
        'pqca_ra',           -- RA service: domain challenges + RA officer queue
        'pqca_ov_agent',     -- AI organization-validation agent
        'pqca_ca_engine',    -- CA core issuing engine
        'pqca_crl',          -- CRL generator
        'pqca_ocsp',         -- OCSP responder (read-only)
        'pqca_copilot',      -- internal admin copilot
        'pqca_support_bot',  -- external customer chatbot
        'pqca_jobs',         -- scheduled sweepers (cron / Celery)
        'pqca_auditor'       -- read-only audit access
    ] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', r);
        END IF;
    END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- 1. Lock everything down, then open only what each service needs
-- ---------------------------------------------------------------------
REVOKE ALL ON ALL TABLES    IN SCHEMA public FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Our own functions (not pgcrypto's): run as owner, not callable by default
DO $$
DECLARE f RECORD;
BEGIN
    FOR f IN
        SELECT p.oid::regprocedure AS sig
          FROM pg_proc p
          JOIN pg_namespace n ON n.oid = p.pronamespace
         WHERE n.nspname = 'public'
           AND NOT EXISTS (SELECT 1 FROM pg_depend d
                            WHERE d.objid = p.oid AND d.deptype = 'e')   -- skip extension functions
    LOOP
        EXECUTE format('ALTER FUNCTION %s SECURITY DEFINER SET search_path = public, pg_temp', f.sig);
        EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f.sig);
    END LOOP;
END $$;

GRANT USAGE ON SCHEMA public TO
    pqca_gateway, pqca_ra, pqca_ov_agent, pqca_ca_engine, pqca_crl,
    pqca_ocsp, pqca_copilot, pqca_support_bot, pqca_jobs, pqca_auditor;

-- Everyone who acts may write audit entries through the function
GRANT EXECUTE ON FUNCTION audit_log(TEXT, TEXT, TEXT, TEXT, JSONB, UUID, UUID) TO
    pqca_gateway, pqca_ra, pqca_ov_agent, pqca_ca_engine, pqca_crl, pqca_copilot, pqca_jobs;

-- ---------------------------------------------------------------------
-- 2. API gateway — portal and REST API
-- ---------------------------------------------------------------------
GRANT SELECT ON
    users, organizations, ra_policy,
    certificate_requests, request_domains, domain_challenges,
    certificates, revocations, issuing_cas, crls,
    ov_applications, ov_documents, ov_assessments, ov_extracted_fields,
    ov_field_comparisons, ov_duns_lookups, ov_followup_requests, ov_reviews,
    audit_logs, assistant_feedback, lessons,
    v_request_validation, v_certificate_status, v_certs_last_week,
    v_domain_failures_last_hour, v_ov_review_queue, v_telemetry_summary, v_lesson_metrics
    TO pqca_gateway;
GRANT INSERT, UPDATE ON users TO pqca_gateway;
GRANT INSERT ON organizations TO pqca_gateway;
GRANT UPDATE (legal_name, address, duns, account_key_thumbprint) ON organizations TO pqca_gateway;
GRANT UPDATE ON ra_policy TO pqca_gateway;
GRANT INSERT ON certificate_requests, request_domains TO pqca_gateway;
GRANT UPDATE (status, rejection_reason) ON certificate_requests TO pqca_gateway;
GRANT INSERT ON ov_applications, ov_documents, ov_document_contents TO pqca_gateway;
GRANT UPDATE (status) ON ov_applications TO pqca_gateway;                 -- withdraw
GRANT UPDATE (status, response_text, response_document_id, answered_at)
    ON ov_followup_requests TO pqca_gateway;                              -- applicant answers
GRANT INSERT ON revocations TO pqca_gateway;                              -- /revoke
GRANT INSERT ON assistant_feedback TO pqca_gateway;
GRANT EXECUTE ON FUNCTION request_is_validated(UUID) TO pqca_gateway;
GRANT EXECUTE ON FUNCTION audit_verify_chain() TO pqca_gateway;           -- audit explorer

-- ---------------------------------------------------------------------
-- 3. RA service — domain validation and the RA officer queue
-- ---------------------------------------------------------------------
GRANT SELECT ON
    users, organizations, ra_policy, certificate_requests, request_domains,
    domain_challenges, challenge_attempts,
    ov_applications, ov_documents, ov_document_contents, ov_assessments,
    ov_extracted_fields, ov_field_comparisons, ov_duns_lookups,
    ov_followup_requests, ov_reviews,
    v_request_validation, v_domain_failures_last_hour, v_certs_last_week, v_ov_review_queue
    TO pqca_ra;
GRANT INSERT, UPDATE ON domain_challenges TO pqca_ra;
GRANT INSERT ON challenge_attempts TO pqca_ra;
GRANT UPDATE (challenge_id) ON request_domains TO pqca_ra;
GRANT UPDATE (status, rejection_reason) ON certificate_requests TO pqca_ra;
GRANT INSERT ON ov_reviews, ov_followup_requests TO pqca_ra;              -- officer decisions (FR26)
GRANT EXECUTE ON FUNCTION request_is_validated(UUID) TO pqca_ra;

-- ---------------------------------------------------------------------
-- 4. OV agent — reads the case, writes its assessment. Cannot decide.
-- ---------------------------------------------------------------------
GRANT SELECT ON
    organizations, ov_applications, ov_documents, ov_document_contents,
    ov_assessments, ov_extracted_fields, ov_field_comparisons,
    ov_duns_lookups, ov_followup_requests
    TO pqca_ov_agent;
GRANT INSERT ON
    ov_assessments, ov_extracted_fields, ov_field_comparisons,
    ov_duns_lookups, ov_followup_requests
    TO pqca_ov_agent;
GRANT UPDATE (status, recommendation, confidence, justification, signals)
    ON ov_assessments TO pqca_ov_agent;

-- ---------------------------------------------------------------------
-- 5. CA engine — reserve a serial, record the signed certificate
-- ---------------------------------------------------------------------
GRANT SELECT ON
    organizations, certificate_requests, request_domains, issuing_cas,
    serial_reservations, certificates, v_request_validation
    TO pqca_ca_engine;
GRANT INSERT ON certificates TO pqca_ca_engine;
GRANT EXECUTE ON FUNCTION reserve_serial(UUID, UUID)    TO pqca_ca_engine;
GRANT EXECUTE ON FUNCTION request_is_validated(UUID)    TO pqca_ca_engine;

-- ---------------------------------------------------------------------
-- 6. CRL generator
-- ---------------------------------------------------------------------
GRANT SELECT ON issuing_cas, crls, v_crl_entries TO pqca_crl;
GRANT INSERT ON crls TO pqca_crl;

-- ---------------------------------------------------------------------
-- 7. OCSP responder — read-only.  LISTEN cert_revoked needs no grant.
-- ---------------------------------------------------------------------
GRANT SELECT ON issuing_cas, v_certificate_status TO pqca_ocsp;

-- ---------------------------------------------------------------------
-- 8. Internal copilot — telemetry, feedback, lessons, action log
-- ---------------------------------------------------------------------
GRANT SELECT ON
    users, assistant_feedback, lessons, lesson_versions, audit_logs,
    v_telemetry_summary, v_retrievable_lessons, v_lesson_metrics
    TO pqca_copilot;
GRANT INSERT ON assistant_feedback, lessons TO pqca_copilot;
GRANT UPDATE (question, incorrect_answer, lesson_text, category, last_edited_by, status,
              approver_id, decision_reason, review_date, injection_scan_status, vector_ref)
    ON lessons TO pqca_copilot;

-- ---------------------------------------------------------------------
-- 9. External support chatbot — strict data boundary: feedback only
-- ---------------------------------------------------------------------
GRANT INSERT ON assistant_feedback TO pqca_support_bot;

-- ---------------------------------------------------------------------
-- 10. Scheduled jobs
-- ---------------------------------------------------------------------
GRANT EXECUTE ON FUNCTION expire_stale_challenges()     TO pqca_jobs;
GRANT EXECUTE ON FUNCTION purge_expired_ov_documents()  TO pqca_jobs;

-- ---------------------------------------------------------------------
-- 11. Auditor — reads everything except the uploaded files themselves
-- ---------------------------------------------------------------------
GRANT SELECT ON ALL TABLES IN SCHEMA public TO pqca_auditor;      -- includes views
REVOKE SELECT ON ov_document_contents FROM pqca_auditor;
GRANT EXECUTE ON FUNCTION audit_verify_chain() TO pqca_auditor;
