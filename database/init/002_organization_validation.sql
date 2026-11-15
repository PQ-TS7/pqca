-- =====================================================================
-- PQ-CA — Organization Validation (OV) Schema
-- PostgreSQL 15+   |   database/init/002_organization_validation.sql
-- Requires: 001_domain_validation.sql (organizations, forbid_modify()).
--
-- Team decisions (2026-11-15):
--   * Mandatory human review: only an ov_reviews row can make an
--     organization 'accepted' or 'rejected'. The AI never decides.
--   * The agent tells the reviewer when a case is 'clear'. The database
--     only accepts 'clear' when every deterministic check passed.
--   * Extracted fields are rows, not JSON.
--   * AI output (ov_assessments) and human decision (ov_reviews) are
--     two separate tables.
--   * Organizations without a DUNS number are allowed; they can never
--     be 'clear' and always need the reviewer's attention.
--   * Uploaded files are stored inside the database
--     (ov_document_contents), separate from their metadata.
-- =====================================================================

-- ---------------------------------------------------------------------
-- 1. Users (minimal — RBAC owner may extend: MFA, sessions, permissions)
-- ---------------------------------------------------------------------
CREATE TABLE users (
    user_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email            TEXT NOT NULL UNIQUE CHECK (email = lower(email)),
    full_name        TEXT NOT NULL,
    role             TEXT NOT NULL
                     CHECK (role IN ('super_admin','ca_operator','auditor','ra_officer','applicant')),
    organization_id  UUID REFERENCES organizations(organization_id),   -- applicants only
    is_active        BOOLEAN NOT NULL DEFAULT true,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (role = 'applicant' OR organization_id IS NULL)
);

-- Wire up the user columns left open in 001
ALTER TABLE domain_challenges
    ADD CONSTRAINT fk_chal_reviewed_by FOREIGN KEY (reviewed_by) REFERENCES users(user_id);
ALTER TABLE ra_policy
    ADD CONSTRAINT fk_policy_updated_by FOREIGN KEY (updated_by) REFERENCES users(user_id);

-- ---------------------------------------------------------------------
-- 2. Field names shared by extraction and comparison
-- ---------------------------------------------------------------------
CREATE DOMAIN ov_field_name AS TEXT CHECK (VALUE IN (
    'legal_name','registration_no','address','country',
    'issue_date','expiry_date','applicant_role','authorization_evidence'));

-- ---------------------------------------------------------------------
-- 3. OV applications — one case per submission (FR20)
-- ---------------------------------------------------------------------
CREATE TABLE ov_applications (
    application_id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id         UUID NOT NULL REFERENCES organizations(organization_id),
    submitted_by            UUID NOT NULL REFERENCES users(user_id),

    -- Snapshot of what the applicant typed (compared against documents)
    entered_legal_name      TEXT    NOT NULL,
    entered_registration_no TEXT    NOT NULL,
    entered_address         TEXT    NOT NULL,
    entered_country         CHAR(2) NOT NULL,
    entered_duns            CHAR(9) CHECK (entered_duns ~ '^[0-9]{9}$'),
    has_no_duns             BOOLEAN NOT NULL DEFAULT false,

    status                  TEXT NOT NULL DEFAULT 'submitted'
                            CHECK (status IN ('submitted','processing','awaiting_applicant',
                                              'awaiting_review','accepted','rejected','withdrawn')),
    consent_given_at        TIMESTAMPTZ NOT NULL,          -- consent to process documents
    submitted_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    decided_at              TIMESTAMPTZ,

    CHECK (has_no_duns = (entered_duns IS NULL)),
    CHECK ((status IN ('accepted','rejected')) = (decided_at IS NOT NULL))
);

-- One open case per organization
CREATE UNIQUE INDEX ux_ovapp_open
    ON ov_applications (organization_id)
    WHERE status IN ('submitted','processing','awaiting_applicant','awaiting_review');
CREATE INDEX ix_ovapp_org ON ov_applications (organization_id, submitted_at);

-- ---------------------------------------------------------------------
-- 4. Uploaded documents (FR20, AI-OV-01)
-- ---------------------------------------------------------------------
CREATE TABLE ov_documents (
    document_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id     UUID NOT NULL REFERENCES ov_applications(application_id),
    category           TEXT NOT NULL
                       CHECK (category IN ('commercial_registration','tax_card',
                                           'authorization_letter','other')),
    original_filename  TEXT   NOT NULL,
    mime_type          TEXT   NOT NULL,
    size_bytes         BIGINT NOT NULL CHECK (size_bytes > 0),
    sha256             BYTEA  NOT NULL CHECK (octet_length(sha256) = 32),   -- of the original file
    language           TEXT CHECK (language IN ('en','ar','mixed','other')),
    intake_status      TEXT NOT NULL
                       CHECK (intake_status IN ('accepted','rejected_unsupported',
                                                'rejected_encrypted','rejected_unsafe')),
    intake_reason      TEXT,
    uploaded_by        UUID NOT NULL REFERENCES users(user_id),
    uploaded_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    retention_until    TIMESTAMPTZ,
    deleted_at         TIMESTAMPTZ,               -- set by trigger when the content is deleted
    UNIQUE (application_id, sha256),
    CHECK (intake_status = 'accepted' OR intake_reason IS NOT NULL)
);
CREATE INDEX ix_ovdoc_retention ON ov_documents (retention_until) WHERE deleted_at IS NULL;

CREATE TRIGGER trg_ovdoc_no_delete
    BEFORE DELETE ON ov_documents
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- ---------------------------------------------------------------------
-- 4b. File contents — kept apart from the metadata so that listing
--     documents never loads the files, and so the file can be deleted
--     at the end of retention while the metadata row stays for audit.
-- ---------------------------------------------------------------------
CREATE TABLE ov_document_contents (
    document_id        UUID PRIMARY KEY REFERENCES ov_documents(document_id),
    content            BYTEA NOT NULL
                       CHECK (octet_length(content) BETWEEN 1 AND 26214400),   -- 25 MB cap
    encryption_key_id  TEXT,          -- NULL = stored as uploaded (hash checked by trigger);
                                      -- set = encrypted by the application with that key
    stored_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- PDFs and scans are already compressed: skip TOAST compression
ALTER TABLE ov_document_contents ALTER COLUMN content SET STORAGE EXTERNAL;

CREATE OR REPLACE FUNCTION ov_content_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE d ov_documents;
BEGIN
    SELECT * INTO d FROM ov_documents WHERE document_id = NEW.document_id;
    IF d.intake_status <> 'accepted' THEN
        RAISE EXCEPTION 'only accepted documents are stored (intake: %)', d.intake_status;
    END IF;
    IF d.deleted_at IS NOT NULL THEN
        RAISE EXCEPTION 'document % was deleted and cannot be re-stored', d.document_id;
    END IF;
    IF NEW.encryption_key_id IS NULL
       AND (digest(NEW.content, 'sha256') <> d.sha256 OR octet_length(NEW.content) <> d.size_bytes) THEN
        RAISE EXCEPTION 'file content does not match the recorded hash/size';
    END IF;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION ov_content_after_delete() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE ov_documents SET deleted_at = now() WHERE document_id = OLD.document_id;
    RETURN NULL;
END $$;

CREATE TRIGGER trg_ovcontent_ins BEFORE INSERT ON ov_document_contents
    FOR EACH ROW EXECUTE FUNCTION ov_content_before_insert();
CREATE TRIGGER trg_ovcontent_no_update BEFORE UPDATE ON ov_document_contents
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();
CREATE TRIGGER trg_ovcontent_del AFTER DELETE ON ov_document_contents
    FOR EACH ROW EXECUTE FUNCTION ov_content_after_delete();

-- Retention sweeper (run from cron / Celery)
CREATE OR REPLACE FUNCTION purge_expired_ov_documents() RETURNS INT LANGUAGE plpgsql AS $$
DECLARE n INT;
BEGIN
    DELETE FROM ov_document_contents c
     USING ov_documents d
     WHERE d.document_id = c.document_id AND d.retention_until <= now();
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END $$;

-- ---------------------------------------------------------------------
-- 5. AI assessment — what the agent produced (FR23, SRS "AI OV assessment")
--    Advisory only. Never changes ov_status to accepted/rejected.
-- ---------------------------------------------------------------------
CREATE TABLE ov_assessments (
    assessment_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    application_id     UUID NOT NULL REFERENCES ov_applications(application_id),
    run_no             INT  NOT NULL,                       -- set by trigger
    status             TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','completed','failed')),
    model_name         TEXT NOT NULL,
    model_version      TEXT NOT NULL,
    prompt_version     TEXT NOT NULL,

    -- Message to the human reviewer:
    --   clear              every deterministic check passed (see trigger)
    --   needs_attention    something is missing, partial or unverified
    --   reject_recommended a hard mismatch or an invalid DUNS
    --   abstain            the agent could not assess
    recommendation     TEXT CHECK (recommendation IN ('clear','needs_attention','reject_recommended','abstain')),
    all_checks_passed  BOOLEAN,                             -- computed by trigger, not by the model
    confidence         NUMERIC(4,3) CHECK (confidence BETWEEN 0 AND 1),   -- model's own score
    justification      TEXT,
    signals            JSONB NOT NULL DEFAULT '[]',
    started_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    completed_at       TIMESTAMPTZ,

    UNIQUE (application_id, run_no),
    CHECK (status <> 'completed'
           OR (recommendation IS NOT NULL AND justification IS NOT NULL
               AND all_checks_passed IS NOT NULL AND completed_at IS NOT NULL))
);

-- ---------------------------------------------------------------------
-- 6. Extracted fields — one row per field per document (FR21, AI-OV-02)
-- ---------------------------------------------------------------------
CREATE TABLE ov_extracted_fields (
    field_id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    assessment_id     UUID NOT NULL REFERENCES ov_assessments(assessment_id),
    document_id       UUID NOT NULL REFERENCES ov_documents(document_id),
    field_name        ov_field_name NOT NULL,
    presence          TEXT NOT NULL CHECK (presence IN ('found','unknown','absent')),
                      -- unknown = could not read it;  absent = document does not contain it
    value_text        TEXT,                    -- as written in the document
    normalized_value  TEXT,                    -- after deterministic normalization
    page_no           INT CHECK (page_no >= 1),
    region            JSONB,                   -- {"x":..,"y":..,"w":..,"h":..} on that page
    confidence        NUMERIC(4,3) CHECK (confidence BETWEEN 0 AND 1),
    UNIQUE (assessment_id, document_id, field_name),
    UNIQUE (field_id, assessment_id),
    CHECK ((presence = 'found') = (value_text IS NOT NULL)),
    CHECK (presence <> 'found' OR page_no IS NOT NULL)      -- provenance is mandatory
);

-- ---------------------------------------------------------------------
-- 7. Field comparisons — entered value vs document value (FR21, AI-OV-03)
--    Results come from deterministic rules, not from the model.
-- ---------------------------------------------------------------------
CREATE TABLE ov_field_comparisons (
    comparison_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    assessment_id       UUID NOT NULL REFERENCES ov_assessments(assessment_id),
    field_name          ov_field_name NOT NULL,
    extracted_field_id  BIGINT,                -- NULL when no document supplied the field
    entered_value       TEXT,
    document_value      TEXT,
    result              TEXT NOT NULL CHECK (result IN ('match','partial_match','mismatch','missing')),
    rule_id             TEXT NOT NULL,         -- e.g. 'name.casefold_exact', 'expiry.not_expired'
    note                TEXT,
    FOREIGN KEY (extracted_field_id, assessment_id)
        REFERENCES ov_extracted_fields (field_id, assessment_id),
    UNIQUE NULLS NOT DISTINCT (assessment_id, field_name, extracted_field_id)
);
CREATE INDEX ix_ovcmp_assessment ON ov_field_comparisons (assessment_id, result);

-- ---------------------------------------------------------------------
-- 8. DUNS lookup — one per assessment run (FR22, AI-OV-05)
--    Only minimal identifiers leave the boundary; they are recorded here.
-- ---------------------------------------------------------------------
CREATE TABLE ov_duns_lookups (
    lookup_id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    assessment_id         UUID NOT NULL UNIQUE REFERENCES ov_assessments(assessment_id),
    provider              TEXT NOT NULL,       -- 'dnb', 'mock', 'none'
    duns_sent             CHAR(9),
    name_sent             TEXT,
    registration_no_sent  TEXT,
    result                TEXT NOT NULL
                          CHECK (result IN ('valid','invalid','different_company',
                                            'not_verified','not_applicable')),
                          -- not_verified   = provider unreachable / no approved connector → escalate
                          -- not_applicable = organization declared it has no DUNS
    record_name           TEXT,
    record_address        TEXT,
    record_status         TEXT,
    raw_response          JSONB,
    error_message         TEXT,
    looked_up_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK ((result = 'not_applicable') = (duns_sent IS NULL))
);

-- ---------------------------------------------------------------------
-- 9. Follow-up requests to the applicant (FR24)
-- ---------------------------------------------------------------------
CREATE TABLE ov_followup_requests (
    followup_id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_id        UUID NOT NULL REFERENCES ov_applications(application_id),
    assessment_id         UUID REFERENCES ov_assessments(assessment_id),   -- NULL = asked by a reviewer
    requested_by          UUID REFERENCES users(user_id),                  -- NULL = asked by the agent
    kind                  TEXT NOT NULL CHECK (kind IN ('document','field','clarification')),
    field_name            ov_field_name,
    document_category     TEXT,
    question              TEXT NOT NULL,
    status                TEXT NOT NULL DEFAULT 'open'
                          CHECK (status IN ('open','answered','cancelled','expired')),
    response_text         TEXT,
    response_document_id  UUID REFERENCES ov_documents(document_id),
    requested_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    due_at                TIMESTAMPTZ,
    answered_at           TIMESTAMPTZ,
    CHECK ((status = 'answered') = (answered_at IS NOT NULL))
);
CREATE INDEX ix_ovfollow_open ON ov_followup_requests (application_id) WHERE status = 'open';

-- ---------------------------------------------------------------------
-- 10. Human review — the ONLY source of accepted / rejected (FR26, AI-OV-04)
-- ---------------------------------------------------------------------
CREATE TABLE ov_reviews (
    review_id       BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    application_id  UUID NOT NULL REFERENCES ov_applications(application_id),
    assessment_id   UUID NOT NULL REFERENCES ov_assessments(assessment_id),  -- what the reviewer saw
    reviewer_id     UUID NOT NULL REFERENCES users(user_id),
    decision        TEXT NOT NULL CHECK (decision IN ('accepted','rejected','more_info_requested')),
    reason          TEXT NOT NULL CHECK (length(btrim(reason)) >= 10),
    is_override     BOOLEAN NOT NULL DEFAULT false,   -- set by trigger: decision went against the agent
    reviewed_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_ovrev_app ON ov_reviews (application_id, review_id);

-- =====================================================================
-- Triggers
-- =====================================================================

-- A. New assessment run: number it, move the case to 'processing'
CREATE OR REPLACE FUNCTION ov_assessment_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE app_status TEXT;
BEGIN
    SELECT status INTO app_status FROM ov_applications
     WHERE application_id = NEW.application_id FOR UPDATE;
    IF app_status IN ('accepted','rejected','withdrawn') THEN
        RAISE EXCEPTION 'application % is closed (%)', NEW.application_id, app_status;
    END IF;

    NEW.status := 'running';
    NEW.run_no := coalesce((SELECT max(run_no) FROM ov_assessments
                             WHERE application_id = NEW.application_id), 0) + 1;
    UPDATE ov_applications SET status = 'processing' WHERE application_id = NEW.application_id;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_ov_assessment_before_insert
    BEFORE INSERT ON ov_assessments
    FOR EACH ROW EXECUTE FUNCTION ov_assessment_before_insert();

-- B. Deterministic "all checks passed" — the basis for 'clear'
CREATE OR REPLACE FUNCTION ov_checks_passed(p_assessment UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE AS $$
    SELECT
        -- at least one accepted document, and none rejected as unsafe
        EXISTS (SELECT 1 FROM ov_documents d JOIN ov_assessments a USING (application_id)
                 WHERE a.assessment_id = p_assessment AND d.intake_status = 'accepted')
    AND NOT EXISTS (SELECT 1 FROM ov_documents d JOIN ov_assessments a USING (application_id)
                     WHERE a.assessment_id = p_assessment AND d.intake_status = 'rejected_unsafe')
        -- the four identity fields were all compared ...
    AND (SELECT count(DISTINCT field_name) FROM ov_field_comparisons
          WHERE assessment_id = p_assessment
            AND field_name IN ('legal_name','registration_no','address','country')) = 4
        -- ... and every comparison is an exact match
    AND NOT EXISTS (SELECT 1 FROM ov_field_comparisons
                     WHERE assessment_id = p_assessment AND result <> 'match')
        -- nothing the agent failed to read
    AND NOT EXISTS (SELECT 1 FROM ov_extracted_fields
                     WHERE assessment_id = p_assessment AND presence = 'unknown')
        -- DUNS verified (so no-DUNS organizations can never be 'clear')
    AND EXISTS (SELECT 1 FROM ov_duns_lookups
                 WHERE assessment_id = p_assessment AND result = 'valid')
        -- no unanswered question to the applicant
    AND NOT EXISTS (SELECT 1 FROM ov_followup_requests f JOIN ov_assessments a USING (application_id)
                     WHERE a.assessment_id = p_assessment AND f.status = 'open');
$$;

-- C. Finishing an assessment: freeze it, compute checks, queue for a human
CREATE OR REPLACE FUNCTION ov_assessment_before_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status <> 'running' THEN
        RAISE EXCEPTION 'assessment % is % and cannot be changed', OLD.assessment_id, OLD.status;
    END IF;
    IF (NEW.application_id, NEW.run_no) IS DISTINCT FROM (OLD.application_id, OLD.run_no) THEN
        RAISE EXCEPTION 'assessment identity is immutable';
    END IF;

    IF NEW.status = 'completed' THEN
        NEW.all_checks_passed := ov_checks_passed(NEW.assessment_id);
        NEW.completed_at      := coalesce(NEW.completed_at, now());

        IF NEW.recommendation = 'clear' AND NOT NEW.all_checks_passed THEN
            RAISE EXCEPTION 'recommendation ''clear'' refused: not every deterministic check passed';
        END IF;

        UPDATE ov_applications SET status = 'awaiting_review'
         WHERE application_id = NEW.application_id;
        UPDATE organizations o SET ov_status = 'manual_review'
          FROM ov_applications a
         WHERE a.application_id = NEW.application_id
           AND o.organization_id = a.organization_id
           AND o.ov_status <> 'accepted';      -- re-validation does not suspend a valid org
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_ov_assessment_before_update
    BEFORE UPDATE ON ov_assessments
    FOR EACH ROW EXECUTE FUNCTION ov_assessment_before_update();

CREATE TRIGGER trg_ov_assessment_no_delete
    BEFORE DELETE ON ov_assessments
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- D. Evidence rows: only while the run is open, same application, then frozen
CREATE OR REPLACE FUNCTION ov_evidence_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE a ov_assessments;
BEGIN
    SELECT * INTO a FROM ov_assessments WHERE assessment_id = NEW.assessment_id;
    IF a.status <> 'running' THEN
        RAISE EXCEPTION 'assessment % is %; evidence can no longer be added', a.assessment_id, a.status;
    END IF;
    IF TG_TABLE_NAME = 'ov_extracted_fields' THEN
        IF NOT EXISTS (SELECT 1 FROM ov_documents d
                        WHERE d.document_id = NEW.document_id
                          AND d.application_id = a.application_id
                          AND d.intake_status = 'accepted') THEN
            RAISE EXCEPTION 'document is not an accepted document of this application';
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_ovfield_ins BEFORE INSERT ON ov_extracted_fields
    FOR EACH ROW EXECUTE FUNCTION ov_evidence_before_insert();
CREATE TRIGGER trg_ovcmp_ins   BEFORE INSERT ON ov_field_comparisons
    FOR EACH ROW EXECUTE FUNCTION ov_evidence_before_insert();
CREATE TRIGGER trg_ovduns_ins  BEFORE INSERT ON ov_duns_lookups
    FOR EACH ROW EXECUTE FUNCTION ov_evidence_before_insert();

CREATE TRIGGER trg_ovfield_frozen BEFORE UPDATE OR DELETE ON ov_extracted_fields
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();
CREATE TRIGGER trg_ovcmp_frozen   BEFORE UPDATE OR DELETE ON ov_field_comparisons
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();
CREATE TRIGGER trg_ovduns_frozen  BEFORE UPDATE OR DELETE ON ov_duns_lookups
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- E. Human review: who may review, on what, and what it changes
CREATE OR REPLACE FUNCTION ov_review_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    app  ov_applications;
    ass  ov_assessments;
    usr  users;
BEGIN
    SELECT * INTO app FROM ov_applications WHERE application_id = NEW.application_id FOR UPDATE;
    SELECT * INTO ass FROM ov_assessments  WHERE assessment_id  = NEW.assessment_id;
    SELECT * INTO usr FROM users           WHERE user_id        = NEW.reviewer_id;

    IF NOT usr.is_active OR usr.role NOT IN ('ra_officer','super_admin') THEN
        RAISE EXCEPTION 'reviewer must be an active RA officer';
    END IF;
    IF NEW.reviewer_id = app.submitted_by THEN
        RAISE EXCEPTION 'a reviewer cannot review an application they submitted';
    END IF;
    IF app.status <> 'awaiting_review' THEN
        RAISE EXCEPTION 'application % is not awaiting review (%)', app.application_id, app.status;
    END IF;
    IF ass.application_id <> NEW.application_id OR ass.status <> 'completed'
       OR ass.run_no <> (SELECT max(run_no) FROM ov_assessments
                          WHERE application_id = NEW.application_id) THEN
        RAISE EXCEPTION 'review must reference the latest completed assessment of this application';
    END IF;

    NEW.reviewed_at := now();
    NEW.is_override := (NEW.decision = 'accepted' AND ass.recommendation <> 'clear')
                    OR (NEW.decision = 'rejected' AND ass.recommendation =  'clear');
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION ov_review_after_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.decision = 'more_info_requested' THEN
        UPDATE ov_applications SET status = 'awaiting_applicant'
         WHERE application_id = NEW.application_id;
    ELSE
        UPDATE ov_applications SET status = NEW.decision, decided_at = NEW.reviewed_at
         WHERE application_id = NEW.application_id;
        UPDATE organizations o SET ov_status = NEW.decision
          FROM ov_applications a
         WHERE a.application_id = NEW.application_id
           AND o.organization_id = a.organization_id;
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER trg_ov_review_before_insert BEFORE INSERT ON ov_reviews
    FOR EACH ROW EXECUTE FUNCTION ov_review_before_insert();
CREATE TRIGGER trg_ov_review_after_insert  AFTER  INSERT ON ov_reviews
    FOR EACH ROW EXECUTE FUNCTION ov_review_after_insert();
CREATE TRIGGER trg_ov_review_frozen BEFORE UPDATE OR DELETE ON ov_reviews
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- F. Guard on organizations.ov_status: accepted / rejected must match the
--    organization's latest human decision. Nothing else can set them.
CREATE OR REPLACE FUNCTION org_ov_status_guard() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE last_decision TEXT;
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.ov_status = OLD.ov_status THEN
            RETURN NEW;
        END IF;
    END IF;

    IF NEW.ov_status IN ('accepted','rejected') THEN
        SELECT r.decision INTO last_decision
          FROM ov_reviews r JOIN ov_applications a USING (application_id)
         WHERE a.organization_id = NEW.organization_id
           AND r.decision IN ('accepted','rejected')
         ORDER BY r.review_id DESC LIMIT 1;

        IF last_decision IS DISTINCT FROM NEW.ov_status THEN
            RAISE EXCEPTION 'ov_status ''%'' requires a matching human review (ov_reviews)', NEW.ov_status;
        END IF;
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_org_ov_status_guard
    BEFORE INSERT OR UPDATE OF ov_status ON organizations
    FOR EACH ROW EXECUTE FUNCTION org_ov_status_guard();

-- =====================================================================
-- RA officer queue — everything the reviewer needs in one row
-- =====================================================================
CREATE OR REPLACE VIEW v_ov_review_queue AS
SELECT app.application_id,
       app.organization_id,
       app.entered_legal_name,
       app.has_no_duns,
       app.submitted_at,
       a.assessment_id,
       a.run_no,
       a.recommendation,
       a.all_checks_passed,
       a.confidence,
       a.justification,
       dl.result AS duns_result,
       (SELECT count(*) FROM ov_field_comparisons c
         WHERE c.assessment_id = a.assessment_id AND c.result = 'mismatch')      AS mismatches,
       (SELECT count(*) FROM ov_field_comparisons c
         WHERE c.assessment_id = a.assessment_id AND c.result = 'partial_match') AS partial_matches,
       (SELECT count(*) FROM ov_field_comparisons c
         WHERE c.assessment_id = a.assessment_id AND c.result = 'missing')       AS missing_fields,
       (SELECT count(*) FROM ov_extracted_fields f
         WHERE f.assessment_id = a.assessment_id AND f.presence = 'unknown')     AS unreadable_fields
FROM ov_applications app
JOIN ov_assessments a
  ON a.application_id = app.application_id
 AND a.run_no = (SELECT max(run_no) FROM ov_assessments x
                  WHERE x.application_id = app.application_id)
LEFT JOIN ov_duns_lookups dl ON dl.assessment_id = a.assessment_id
WHERE app.status = 'awaiting_review'
ORDER BY (a.recommendation = 'clear'), app.submitted_at;   -- cases needing attention first
