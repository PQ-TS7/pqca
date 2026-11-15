-- =====================================================================
-- PQ-CA — AI Assistants: feedback and the Lessons Learned pipeline
-- PostgreSQL 15+   |   database/init/005_ai_assistants.sql
-- Requires: 001, 002, 003, 004
--
-- Rules (Comparative Study §2, Tasks.MD §3.1):
--   * Every lesson starts as 'pending'. Nothing is retrievable until a
--     reviewer approves it.
--   * No self-approval: the approver cannot be the author or the last editor.
--   * Approval requires a passed prompt-injection scan.
--   * Rejected lessons are kept but never retrieved.
--   * Editing an approved lesson creates a new version that must be
--     approved again; the old version is kept in lesson_versions.
--   * The vectors themselves live in ChromaDB; this is the system of record.
-- =====================================================================

-- "Lesson Reviewer" permission (Tasks.MD §3.6)
ALTER TABLE users ADD COLUMN is_lesson_reviewer BOOLEAN NOT NULL DEFAULT false;

-- ---------------------------------------------------------------------
-- 1. Feedback on assistant answers (thumbs up / down)
-- ---------------------------------------------------------------------
CREATE TABLE assistant_feedback (
    feedback_id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    assistant             TEXT NOT NULL CHECK (assistant IN ('internal_copilot','external_support')),
    submitted_by          UUID REFERENCES users(user_id),        -- may be NULL for the public chatbot
    question              TEXT NOT NULL,
    answer                TEXT NOT NULL,
    sources               JSONB NOT NULL DEFAULT '[]',           -- documents / lessons the answer cited
    rating                TEXT NOT NULL CHECK (rating IN ('up','down')),
    category              TEXT CHECK (category IN ('incorrect','outdated','unsafe','incomplete')),
    correct_answer        TEXT,
    linked_resource_type  TEXT CHECK (linked_resource_type IN ('certificate','certificate_request','audit_log')),
    linked_resource_id    TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (assistant = 'external_support' OR submitted_by IS NOT NULL),
    CHECK ((rating = 'down') = (category IS NOT NULL)),
    CHECK ((linked_resource_type IS NULL) = (linked_resource_id IS NULL))
);
CREATE INDEX ix_feedback_time ON assistant_feedback (assistant, created_at);

CREATE TRIGGER trg_feedback_frozen BEFORE UPDATE OR DELETE ON assistant_feedback
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- ---------------------------------------------------------------------
-- 2. Lessons
-- ---------------------------------------------------------------------
CREATE TABLE lessons (
    lesson_id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    origin                 TEXT NOT NULL CHECK (origin IN ('feedback','reversed_action','manual')),
    feedback_id            BIGINT REFERENCES assistant_feedback(feedback_id),
    reversed_audit_log_id  BIGINT REFERENCES audit_logs(log_id),   -- the action that was reversed
    question               TEXT NOT NULL,
    incorrect_answer       TEXT,
    lesson_text            TEXT NOT NULL,                          -- the correct answer
    category               TEXT CHECK (category IN ('incorrect','outdated','unsafe','incomplete')),
    author_id              UUID NOT NULL REFERENCES users(user_id),
    last_edited_by         UUID REFERENCES users(user_id),
    status                 TEXT NOT NULL DEFAULT 'pending'
                           CHECK (status IN ('pending','approved','rejected','retired')),
    approver_id            UUID REFERENCES users(user_id),
    decided_at             TIMESTAMPTZ,
    decision_reason        TEXT,
    version                INT  NOT NULL DEFAULT 1,
    review_date            DATE,                                   -- when to look at it again
    injection_scan_status  TEXT NOT NULL DEFAULT 'not_scanned'
                           CHECK (injection_scan_status IN ('not_scanned','passed','failed')),
    injection_scanned_at   TIMESTAMPTZ,
    vector_ref             TEXT,                                   -- id in the ChromaDB lessons_learned collection
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (origin <> 'feedback'        OR feedback_id IS NOT NULL),
    CHECK (origin <> 'reversed_action' OR reversed_audit_log_id IS NOT NULL),
    CHECK ((status IN ('approved','rejected')) = (decided_at IS NOT NULL) OR status = 'retired'),
    CHECK (status <> 'rejected' OR decision_reason IS NOT NULL)
);
CREATE INDEX ix_lessons_status ON lessons (status, created_at);
CREATE INDEX ix_lessons_review ON lessons (review_date) WHERE status = 'approved';

-- History of earlier versions
CREATE TABLE lesson_versions (
    lesson_id         UUID NOT NULL REFERENCES lessons(lesson_id),
    version           INT  NOT NULL,
    question          TEXT NOT NULL,
    incorrect_answer  TEXT,
    lesson_text       TEXT NOT NULL,
    category          TEXT,
    status            TEXT NOT NULL,
    edited_by         UUID REFERENCES users(user_id),
    approver_id       UUID REFERENCES users(user_id),
    decided_at        TIMESTAMPTZ,
    archived_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (lesson_id, version)
);
CREATE TRIGGER trg_lessonver_frozen BEFORE UPDATE OR DELETE ON lesson_versions
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

CREATE OR REPLACE FUNCTION lesson_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    NEW.status                := 'pending';
    NEW.version               := 1;
    NEW.approver_id           := NULL;
    NEW.decided_at            := NULL;
    NEW.decision_reason       := NULL;
    NEW.injection_scan_status := 'not_scanned';
    NEW.injection_scanned_at  := NULL;
    NEW.vector_ref            := NULL;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION lesson_before_update() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE usr users;
BEGIN
    IF NEW.author_id <> OLD.author_id OR NEW.lesson_id <> OLD.lesson_id THEN
        RAISE EXCEPTION 'lesson author is immutable';
    END IF;
    IF OLD.status IN ('rejected','retired') THEN
        RAISE EXCEPTION 'lesson % is % and cannot be changed', OLD.lesson_id, OLD.status;
    END IF;
    NEW.updated_at := now();
    NEW.version    := OLD.version;

    -- 1. Content edit → new version, back to pending
    IF (NEW.question, NEW.incorrect_answer, NEW.lesson_text, NEW.category)
       IS DISTINCT FROM (OLD.question, OLD.incorrect_answer, OLD.lesson_text, OLD.category) THEN
        IF NEW.last_edited_by IS NULL THEN
            RAISE EXCEPTION 'set last_edited_by when editing a lesson';
        END IF;
        INSERT INTO lesson_versions (lesson_id, version, question, incorrect_answer, lesson_text,
                                     category, status, edited_by, approver_id, decided_at)
        VALUES (OLD.lesson_id, OLD.version, OLD.question, OLD.incorrect_answer, OLD.lesson_text,
                OLD.category, OLD.status, OLD.last_edited_by, OLD.approver_id, OLD.decided_at);

        NEW.version               := OLD.version + 1;
        NEW.status                := 'pending';
        NEW.approver_id           := NULL;
        NEW.decided_at            := NULL;
        NEW.decision_reason       := NULL;
        NEW.injection_scan_status := 'not_scanned';
        NEW.injection_scanned_at  := NULL;
        NEW.vector_ref            := NULL;        -- the application removes the old vector
        RETURN NEW;
    END IF;

    -- 2. Scan result
    IF NEW.injection_scan_status <> OLD.injection_scan_status THEN
        NEW.injection_scanned_at := now();
    END IF;

    -- 3. Status change
    IF NEW.status <> OLD.status THEN
        IF OLD.status = 'pending' AND NEW.status IN ('approved','rejected') THEN
            SELECT * INTO usr FROM users WHERE user_id = NEW.approver_id;
            IF NOT FOUND OR NOT usr.is_active
               OR NOT (usr.is_lesson_reviewer OR usr.role = 'super_admin') THEN
                RAISE EXCEPTION 'approver must be an active lesson reviewer';
            END IF;
            IF NEW.approver_id = OLD.author_id OR NEW.approver_id IS NOT DISTINCT FROM OLD.last_edited_by THEN
                RAISE EXCEPTION 'no self-approval: the approver wrote or edited this lesson';
            END IF;
            IF NEW.status = 'approved' AND NEW.injection_scan_status <> 'passed' THEN
                RAISE EXCEPTION 'a lesson needs a passed prompt-injection scan before approval';
            END IF;
            NEW.decided_at := now();
        ELSIF OLD.status = 'approved' AND NEW.status = 'retired' THEN
            NULL;                                 -- "delete": kept, never retrieved again
        ELSE
            RAISE EXCEPTION 'lesson status cannot go from % to %', OLD.status, NEW.status;
        END IF;
    ELSIF (NEW.approver_id, NEW.decided_at) IS DISTINCT FROM (OLD.approver_id, OLD.decided_at) THEN
        RAISE EXCEPTION 'approver and decision time change only with the status';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_lesson_before_insert BEFORE INSERT ON lessons
    FOR EACH ROW EXECUTE FUNCTION lesson_before_insert();
CREATE TRIGGER trg_lesson_before_update BEFORE UPDATE ON lessons
    FOR EACH ROW EXECUTE FUNCTION lesson_before_update();
CREATE TRIGGER trg_lesson_no_delete BEFORE DELETE ON lessons
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();
CREATE TRIGGER trg_audit_lessons AFTER UPDATE ON lessons
    FOR EACH ROW EXECUTE FUNCTION audit_trigger();

-- ---------------------------------------------------------------------
-- Views
-- ---------------------------------------------------------------------

-- The only lessons the copilot may retrieve
CREATE OR REPLACE VIEW v_retrievable_lessons AS
SELECT lesson_id, version, question, lesson_text, category,
       author_id, approver_id, decided_at AS approved_at, review_date, vector_ref
FROM lessons
WHERE status = 'approved' AND injection_scan_status = 'passed';

-- Copilot UI metrics: pending lessons, approval rate, thumbs ratio
CREATE OR REPLACE VIEW v_lesson_metrics AS
SELECT
    (SELECT count(*) FROM lessons WHERE status = 'pending')                                  AS lessons_pending,
    (SELECT count(*) FROM lessons WHERE status = 'approved')                                 AS lessons_approved,
    (SELECT count(*) FROM lessons WHERE status = 'rejected')                                 AS lessons_rejected,
    (SELECT round(count(*) FILTER (WHERE status = 'approved')::numeric
                  / nullif(count(*) FILTER (WHERE status IN ('approved','rejected')), 0), 3)
       FROM lessons)                                                                         AS approval_rate,
    (SELECT count(*) FROM lessons WHERE status = 'approved' AND review_date <= current_date) AS lessons_due_for_review,
    (SELECT count(*) FROM assistant_feedback WHERE rating = 'up')                            AS thumbs_up,
    (SELECT count(*) FROM assistant_feedback WHERE rating = 'down')                          AS thumbs_down,
    (SELECT round(count(*) FILTER (WHERE rating = 'up')::numeric / nullif(count(*), 0), 3)
       FROM assistant_feedback)                                                              AS thumbs_up_ratio;
