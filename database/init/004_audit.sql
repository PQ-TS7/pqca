-- =====================================================================
-- PQ-CA — Audit Log: append-only, hash-chained, tamper-evident
-- PostgreSQL 15+   |   database/init/004_audit.sql
-- Requires: 001, 002, 003
--
--   * Every entry stores the hash of the previous entry and its own hash.
--     Editing or removing an entry breaks the chain; audit_verify_chain()
--     reports the first broken entry.
--   * UPDATE, DELETE and TRUNCATE are refused.
--   * Key events are logged automatically by triggers. Services add their
--     own events with audit_log(...).
--   * Who did it: the row's own user column when there is one, otherwise
--     the session settings the application sets per request:
--         SET LOCAL pqca.actor_id  = '<user uuid>';
--         SET LOCAL pqca.client_ip = '<ip>';
-- =====================================================================

CREATE TABLE audit_logs (
    log_id           BIGINT PRIMARY KEY,                 -- gapless, set by trigger
    logged_at        TIMESTAMPTZ NOT NULL,               -- set by trigger
    actor_id         UUID REFERENCES users(user_id),     -- NULL = a service, not a person
    actor_label      TEXT NOT NULL,                      -- database login of the service
    action           TEXT NOT NULL,                      -- e.g. 'certificate.issued'
    resource_type    TEXT,
    resource_id      TEXT,
    ip_address       INET,
    status           TEXT NOT NULL DEFAULT 'success' CHECK (status IN ('success','failure','denied')),
    details          JSONB NOT NULL DEFAULT '{}',
    correlation_id   UUID,
    hash_prev_entry  BYTEA NOT NULL CHECK (octet_length(hash_prev_entry) = 32),
    entry_hash       BYTEA NOT NULL CHECK (octet_length(entry_hash) = 32)
);
CREATE INDEX ix_audit_time     ON audit_logs (logged_at);
CREATE INDEX ix_audit_actor    ON audit_logs (actor_id, logged_at);
CREATE INDEX ix_audit_resource ON audit_logs (resource_type, resource_id);
CREATE INDEX ix_audit_action   ON audit_logs (action, logged_at);

-- Hash of one entry = SHA-256( previous hash || canonical text of the entry )
CREATE OR REPLACE FUNCTION audit_entry_hash(r audit_logs) RETURNS BYTEA
LANGUAGE sql STABLE AS $$
    SELECT digest(
        r.hash_prev_entry ||
        convert_to(concat_ws('|',
            r.log_id::text,
            to_char(r.logged_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US'),
            coalesce(r.actor_id::text, ''),
            r.actor_label,
            r.action,
            coalesce(r.resource_type, ''),
            coalesce(r.resource_id, ''),
            coalesce(host(r.ip_address), ''),
            r.status,
            r.details::text,
            coalesce(r.correlation_id::text, '')), 'UTF8'),
        'sha256');
$$;

CREATE OR REPLACE FUNCTION audit_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE prev RECORD;
BEGIN
    -- One writer at a time, so the chain has a single order
    PERFORM pg_advisory_xact_lock(hashtext('pqca.audit_logs'));

    SELECT log_id, entry_hash INTO prev FROM audit_logs ORDER BY log_id DESC LIMIT 1;

    NEW.log_id          := coalesce(prev.log_id, 0) + 1;
    NEW.logged_at       := clock_timestamp();
    NEW.hash_prev_entry := coalesce(prev.entry_hash, decode(repeat('00', 32), 'hex'));
    NEW.entry_hash      := audit_entry_hash(NEW);
    RETURN NEW;
END $$;

CREATE TRIGGER trg_audit_before_insert BEFORE INSERT ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION audit_before_insert();
CREATE TRIGGER trg_audit_frozen BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();
CREATE TRIGGER trg_audit_no_truncate BEFORE TRUNCATE ON audit_logs
    FOR EACH STATEMENT EXECUTE FUNCTION forbid_modify();

-- ---------------------------------------------------------------------
-- Write an entry (services call this; they get no INSERT on the table)
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_log(
    p_action         TEXT,
    p_resource_type  TEXT  DEFAULT NULL,
    p_resource_id    TEXT  DEFAULT NULL,
    p_status         TEXT  DEFAULT 'success',
    p_details        JSONB DEFAULT '{}',
    p_actor_id       UUID  DEFAULT NULL,
    p_correlation_id UUID  DEFAULT NULL
) RETURNS BIGINT LANGUAGE plpgsql AS $$
DECLARE new_id BIGINT;
BEGIN
    INSERT INTO audit_logs (log_id, logged_at, actor_id, actor_label, action, resource_type,
                            resource_id, ip_address, status, details, correlation_id,
                            hash_prev_entry, entry_hash)
    VALUES (0, now(),
            coalesce(p_actor_id, nullif(current_setting('pqca.actor_id', true), '')::uuid),
            session_user,
            p_action, p_resource_type, p_resource_id,
            nullif(current_setting('pqca.client_ip', true), '')::inet,
            p_status, coalesce(p_details, '{}'), p_correlation_id,
            decode(repeat('00', 32), 'hex'), decode(repeat('00', 32), 'hex'))   -- overwritten by trigger
    RETURNING log_id INTO new_id;
    RETURN new_id;
END $$;

-- ---------------------------------------------------------------------
-- Verify the chain. Returns NULL when intact, otherwise the log_id of
-- the first entry that is missing, altered or out of order.
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_verify_chain() RETURNS BIGINT LANGUAGE plpgsql STABLE AS $$
DECLARE
    r         audit_logs;
    expected  BIGINT := 1;
    prev_hash BYTEA  := decode(repeat('00', 32), 'hex');
BEGIN
    FOR r IN SELECT * FROM audit_logs ORDER BY log_id LOOP
        IF r.log_id <> expected THEN
            RETURN expected;                              -- an entry was removed
        END IF;
        IF r.hash_prev_entry <> prev_hash OR r.entry_hash <> audit_entry_hash(r) THEN
            RETURN r.log_id;                              -- an entry was altered
        END IF;
        prev_hash := r.entry_hash;
        expected  := expected + 1;
    END LOOP;
    RETURN NULL;
END $$;

-- ---------------------------------------------------------------------
-- Automatic logging of key events
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION audit_trigger() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_TABLE_NAME = 'certificates' THEN
        PERFORM audit_log('certificate.issued', 'certificate', encode(NEW.serial_number, 'hex'), 'success',
            jsonb_build_object('request_id', NEW.request_id, 'organization_id', NEW.organization_id,
                               'issuer_ca_id', NEW.issuer_ca_id, 'san_list', NEW.san_list,
                               'not_after', NEW.not_after));

    ELSIF TG_TABLE_NAME = 'revocations' THEN
        PERFORM audit_log('certificate.revoked', 'certificate', encode(NEW.serial_number, 'hex'), 'success',
            jsonb_build_object('reason_code', NEW.reason_code,
                               'compromise_timestamp', NEW.compromise_timestamp, 'note', NEW.note),
            NEW.revoked_by);

    ELSIF TG_TABLE_NAME = 'crls' THEN
        PERFORM audit_log('crl.published', 'crl', NEW.crl_number::text, 'success',
            jsonb_build_object('issuer_ca_id', NEW.issuer_ca_id, 'revoked_count', NEW.revoked_count,
                               'is_emergency', NEW.is_emergency, 'next_update', NEW.next_update));

    ELSIF TG_TABLE_NAME = 'issuing_cas' THEN
        IF TG_OP = 'INSERT' THEN
            PERFORM audit_log('ca.registered', 'issuing_ca', NEW.ca_id::text, 'success',
                jsonb_build_object('name', NEW.name, 'ca_type', NEW.ca_type));
        ELSE
            PERFORM audit_log('ca.status_changed', 'issuing_ca', NEW.ca_id::text, 'success',
                jsonb_build_object('from', OLD.status, 'to', NEW.status));
        END IF;

    ELSIF TG_TABLE_NAME = 'ov_assessments' THEN
        IF NEW.status = 'completed' AND OLD.status = 'running' THEN
            PERFORM audit_log('ov.assessment.completed', 'ov_application', NEW.application_id::text, 'success',
                jsonb_build_object('assessment_id', NEW.assessment_id, 'run_no', NEW.run_no,
                                   'recommendation', NEW.recommendation,
                                   'all_checks_passed', NEW.all_checks_passed,
                                   'confidence', NEW.confidence,
                                   'model', NEW.model_name || ' ' || NEW.model_version,
                                   'prompt_version', NEW.prompt_version));
        END IF;

    ELSIF TG_TABLE_NAME = 'ov_reviews' THEN
        PERFORM audit_log('ov.review.' || NEW.decision, 'ov_application', NEW.application_id::text, 'success',
            jsonb_build_object('review_id', NEW.review_id, 'assessment_id', NEW.assessment_id,
                               'is_override', NEW.is_override, 'reason', NEW.reason),
            NEW.reviewer_id);

    ELSIF TG_TABLE_NAME = 'ov_document_contents' THEN
        PERFORM audit_log('ov.document.purged', 'ov_document', OLD.document_id::text);

    ELSIF TG_TABLE_NAME = 'domain_challenges' THEN
        IF NEW.status IS DISTINCT FROM OLD.status THEN
            PERFORM audit_log('domain.challenge.' || NEW.status, 'domain_challenge', NEW.challenge_id::text, 'success',
                jsonb_build_object('organization_id', NEW.organization_id, 'domain', NEW.domain,
                                   'is_wildcard', NEW.is_wildcard, 'method', NEW.method));
        END IF;
        IF NEW.ra_decision IS DISTINCT FROM OLD.ra_decision THEN
            PERFORM audit_log('domain.challenge.ra_' || NEW.ra_decision, 'domain_challenge', NEW.challenge_id::text,
                'success', jsonb_build_object('domain', NEW.domain, 'reason', NEW.ra_review_reason),
                NEW.reviewed_by);
        END IF;

    ELSIF TG_TABLE_NAME = 'ra_policy' THEN
        PERFORM audit_log('ra_policy.updated', 'ra_policy', '1', 'success',
            jsonb_build_object('old', to_jsonb(OLD), 'new', to_jsonb(NEW)), NEW.updated_by);

    ELSIF TG_TABLE_NAME = 'users' THEN
        IF TG_OP = 'INSERT' THEN
            PERFORM audit_log('user.created', 'user', NEW.user_id::text, 'success',
                jsonb_build_object('role', NEW.role));
        ELSIF (NEW.role, NEW.is_active) IS DISTINCT FROM (OLD.role, OLD.is_active) THEN
            PERFORM audit_log('user.access_changed', 'user', NEW.user_id::text, 'success',
                jsonb_build_object('role_from', OLD.role, 'role_to', NEW.role,
                                   'active_from', OLD.is_active, 'active_to', NEW.is_active));
        END IF;

    ELSIF TG_TABLE_NAME = 'lessons' THEN                  -- table created in 005
        IF NEW.status IS DISTINCT FROM OLD.status THEN
            PERFORM audit_log('lesson.' || NEW.status, 'lesson', NEW.lesson_id::text, 'success',
                jsonb_build_object('version', NEW.version, 'reason', NEW.decision_reason),
                coalesce(NEW.approver_id, NEW.last_edited_by));
        END IF;
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER trg_audit_cert      AFTER INSERT           ON certificates         FOR EACH ROW EXECUTE FUNCTION audit_trigger();
CREATE TRIGGER trg_audit_rev       AFTER INSERT           ON revocations          FOR EACH ROW EXECUTE FUNCTION audit_trigger();
CREATE TRIGGER trg_audit_crl       AFTER INSERT           ON crls                 FOR EACH ROW EXECUTE FUNCTION audit_trigger();
CREATE TRIGGER trg_audit_ca        AFTER INSERT OR UPDATE ON issuing_cas          FOR EACH ROW EXECUTE FUNCTION audit_trigger();
CREATE TRIGGER trg_audit_ovassess  AFTER UPDATE           ON ov_assessments       FOR EACH ROW EXECUTE FUNCTION audit_trigger();
CREATE TRIGGER trg_audit_ovreview  AFTER INSERT           ON ov_reviews           FOR EACH ROW EXECUTE FUNCTION audit_trigger();
CREATE TRIGGER trg_audit_ovpurge   AFTER DELETE           ON ov_document_contents FOR EACH ROW EXECUTE FUNCTION audit_trigger();
CREATE TRIGGER trg_audit_challenge AFTER UPDATE           ON domain_challenges    FOR EACH ROW EXECUTE FUNCTION audit_trigger();
CREATE TRIGGER trg_audit_policy    AFTER UPDATE           ON ra_policy            FOR EACH ROW EXECUTE FUNCTION audit_trigger();
CREATE TRIGGER trg_audit_users     AFTER INSERT OR UPDATE ON users                FOR EACH ROW EXECUTE FUNCTION audit_trigger();
