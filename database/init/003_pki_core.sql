-- =====================================================================
-- PQ-CA — PKI Core Schema: CAs, serials, certificates, revocations, CRLs, CRL run log, OCSP responses
-- PostgreSQL 15+   |   database/init/003_pki_core.sql
-- Requires: 001_domain_validation.sql, 002_organization_validation.sql
--
-- Rules enforced here:
--   * A serial is reserved (and proven unique) BEFORE the CA signs.
--   * A certificate row is accepted only if its request passed both
--     gates: OV accepted + every SAN validated (FR25), and its SAN list
--     is exactly the validated SAN list.
--   * Certificates are immutable; the only change is active → revoked,
--     and only through a row in revocations.
--   * Revocations are permanent. CRL numbers only go up.
-- =====================================================================

-- Who created the request (portal user)
ALTER TABLE certificate_requests
    ADD COLUMN requested_by UUID REFERENCES users(user_id);

-- ---------------------------------------------------------------------
-- 0. Generic helper: allow UPDATE on the listed columns only
--    usage: ... EXECUTE FUNCTION allow_update_only('status', 'other_col')
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION allow_update_only() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    n JSONB := to_jsonb(NEW);
    o JSONB := to_jsonb(OLD);
    c TEXT;
BEGIN
    FOREACH c IN ARRAY TG_ARGV LOOP
        n := n - c;
        o := o - c;
    END LOOP;
    IF n <> o THEN
        RAISE EXCEPTION 'only (%) may be updated on %', array_to_string(TG_ARGV, ', '), TG_TABLE_NAME;
    END IF;
    RETURN NEW;
END $$;

-- RFC 5280: positive, at most 20 octets. First byte 1..127 keeps the
-- DER encoding positive and minimal.
CREATE DOMAIN cert_serial AS BYTEA
    CHECK (octet_length(VALUE) BETWEEN 8 AND 20 AND get_byte(VALUE, 0) BETWEEN 1 AND 127);

-- ---------------------------------------------------------------------
-- 1. Issuing CAs (Root, Intermediate, OCSP signer). No key material:
--    key_label is only the PKCS#11 label inside the HSM.
-- ---------------------------------------------------------------------
CREATE TABLE issuing_cas (
    ca_id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                 TEXT NOT NULL UNIQUE,
    ca_type              TEXT NOT NULL CHECK (ca_type IN ('root','intermediate','ocsp_signer')),
    parent_ca_id         UUID REFERENCES issuing_cas(ca_id),
    subject_dn           TEXT NOT NULL,
    signature_algorithm  TEXT NOT NULL                    -- algorithm of this CA's own key
                         CHECK (signature_algorithm IN ('ML-DSA-44','ML-DSA-65','ML-DSA-87')),
    cert_der             BYTEA NOT NULL,
    cert_sha256          BYTEA NOT NULL UNIQUE CHECK (octet_length(cert_sha256) = 32),
    not_before           TIMESTAMPTZ NOT NULL,
    not_after            TIMESTAMPTZ NOT NULL,
    key_label            TEXT,                            -- NULL for the offline root
    status               TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','retired','revoked')),
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (not_after > not_before),
    CHECK ((ca_type = 'root') = (parent_ca_id IS NULL)),
    CHECK (cert_sha256 = digest(cert_der, 'sha256'))
);

CREATE TRIGGER trg_ca_update BEFORE UPDATE ON issuing_cas
    FOR EACH ROW EXECUTE FUNCTION allow_update_only('status');
CREATE TRIGGER trg_ca_no_delete BEFORE DELETE ON issuing_cas
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- ---------------------------------------------------------------------
-- 2. Serial reservations — collision prevention.
--    The CA engine calls reserve_serial() first, signs with that serial,
--    then inserts the certificate. A reservation with no certificate is
--    a signing that failed (or a certificate that was never recorded).
-- ---------------------------------------------------------------------
CREATE TABLE serial_reservations (
    serial_number  cert_serial PRIMARY KEY,
    request_id     UUID NOT NULL UNIQUE REFERENCES certificate_requests(request_id),
    issuer_ca_id   UUID NOT NULL REFERENCES issuing_cas(ca_id),
    reserved_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TRIGGER trg_serial_frozen BEFORE UPDATE OR DELETE ON serial_reservations
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- 20 random bytes from the CSPRNG (159 bits of entropy). Idempotent per request.
CREATE OR REPLACE FUNCTION reserve_serial(p_request UUID, p_issuer UUID) RETURNS BYTEA
LANGUAGE plpgsql AS $$
DECLARE
    s  BYTEA;
    ca issuing_cas;
BEGIN
    SELECT serial_number INTO s FROM serial_reservations WHERE request_id = p_request;
    IF FOUND THEN
        RETURN s;
    END IF;

    SELECT * INTO ca FROM issuing_cas WHERE ca_id = p_issuer;
    IF NOT FOUND OR ca.ca_type <> 'intermediate' OR ca.status <> 'active' THEN
        RAISE EXCEPTION 'issuer must be an active intermediate CA';
    END IF;
    IF NOT request_is_validated(p_request) THEN
        RAISE EXCEPTION 'request % has not passed OV and domain validation', p_request;
    END IF;

    LOOP
        s := gen_random_bytes(20);
        s := set_byte(s, 0, greatest(get_byte(s, 0) & 127, 1));
        INSERT INTO serial_reservations (serial_number, request_id, issuer_ca_id)
        VALUES (s, p_request, p_issuer)
        ON CONFLICT (serial_number) DO NOTHING;
        IF FOUND THEN
            RETURN s;
        END IF;                       -- collision: draw again
    END LOOP;
END $$;

-- ---------------------------------------------------------------------
-- 3. Certificates (end-entity)
-- ---------------------------------------------------------------------
CREATE TABLE certificates (
    serial_number         cert_serial PRIMARY KEY REFERENCES serial_reservations(serial_number),
    request_id            UUID NOT NULL UNIQUE REFERENCES certificate_requests(request_id),
    organization_id       UUID NOT NULL REFERENCES organizations(organization_id),   -- set by trigger
    issuer_ca_id          UUID NOT NULL REFERENCES issuing_cas(ca_id),
    subject_dn            TEXT NOT NULL,
    issuer_dn             TEXT NOT NULL,                                             -- set by trigger
    san_list              TEXT[] NOT NULL CHECK (cardinality(san_list) >= 1),
    public_key_algorithm  TEXT NOT NULL,                                             -- set by trigger (from the request)
    signature_algorithm   TEXT NOT NULL,                                             -- set by trigger (issuer's key)
    not_before            TIMESTAMPTZ NOT NULL,
    not_after             TIMESTAMPTZ NOT NULL,
    cert_der              BYTEA NOT NULL,
    cert_sha256           BYTEA NOT NULL UNIQUE CHECK (octet_length(cert_sha256) = 32),
    status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
                          -- "expired" is not stored: see v_certificate_status
    replaces_serial       cert_serial REFERENCES certificates(serial_number),        -- renewal
    issued_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (not_after > not_before),
    CHECK (cert_sha256 = digest(cert_der, 'sha256'))
);
CREATE INDEX ix_cert_status   ON certificates (status);
CREATE INDEX ix_cert_expiry   ON certificates (not_after) WHERE status = 'active';
CREATE INDEX ix_cert_org      ON certificates (organization_id, issued_at);
CREATE INDEX ix_cert_issuer   ON certificates (issuer_ca_id);
CREATE INDEX ix_cert_san      ON certificates USING GIN (san_list);

CREATE OR REPLACE FUNCTION certificate_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    res       serial_reservations;
    req       certificate_requests;
    ca        issuing_cas;
    expected  TEXT[];
    provided  TEXT[];
BEGIN
    SELECT * INTO res FROM serial_reservations WHERE serial_number = NEW.serial_number;
    IF NOT FOUND OR res.request_id <> NEW.request_id OR res.issuer_ca_id <> NEW.issuer_ca_id THEN
        RAISE EXCEPTION 'serial was not reserved for this request and issuer';
    END IF;

    SELECT * INTO req FROM certificate_requests WHERE request_id = NEW.request_id FOR UPDATE;
    IF req.status NOT IN ('pending_validation','validated') THEN
        RAISE EXCEPTION 'request % is % and cannot be issued', req.request_id, req.status;
    END IF;

    SELECT * INTO ca FROM issuing_cas WHERE ca_id = NEW.issuer_ca_id;
    IF ca.ca_type <> 'intermediate' OR ca.status <> 'active' THEN
        RAISE EXCEPTION 'issuer must be an active intermediate CA';
    END IF;
    IF NEW.not_after > ca.not_after THEN
        RAISE EXCEPTION 'certificate would outlive its issuer';
    END IF;

    -- Issuance gate (FR25): OV accepted + every SAN validated
    IF NOT request_is_validated(NEW.request_id) THEN
        RAISE EXCEPTION 'issuance gate: request % has not passed OV and domain validation', NEW.request_id;
    END IF;

    -- The certificate may contain exactly the validated SANs, nothing else
    SELECT array_agg(s ORDER BY s) INTO expected
      FROM (SELECT CASE WHEN is_wildcard THEN '*.' || domain ELSE domain END AS s
              FROM request_domains WHERE request_id = NEW.request_id) x;
    SELECT array_agg(DISTINCT lower(s) ORDER BY lower(s)) INTO provided
      FROM unnest(NEW.san_list) AS s;
    IF expected IS NULL OR provided IS DISTINCT FROM expected THEN
        RAISE EXCEPTION 'SAN list % does not match the validated SANs %', provided, expected;
    END IF;

    NEW.san_list             := provided;
    NEW.organization_id      := req.organization_id;
    NEW.issuer_dn            := ca.subject_dn;
    NEW.signature_algorithm  := ca.signature_algorithm;
    NEW.public_key_algorithm := req.signature_algorithm;
    NEW.status               := 'active';
    NEW.issued_at            := now();
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION certificate_after_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE certificate_requests
       SET status = 'issued', issued_at = NEW.issued_at
     WHERE request_id = NEW.request_id;
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION certificate_before_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT (OLD.status = 'active' AND NEW.status = 'revoked') THEN
        RAISE EXCEPTION 'the only allowed change is active -> revoked';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM revocations WHERE serial_number = NEW.serial_number) THEN
        RAISE EXCEPTION 'revoke by inserting into revocations, not by updating certificates';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_cert_before_insert BEFORE INSERT ON certificates
    FOR EACH ROW EXECUTE FUNCTION certificate_before_insert();
CREATE TRIGGER trg_cert_after_insert AFTER INSERT ON certificates
    FOR EACH ROW EXECUTE FUNCTION certificate_after_insert();
CREATE TRIGGER trg_cert_update_cols BEFORE UPDATE ON certificates
    FOR EACH ROW EXECUTE FUNCTION allow_update_only('status');
-- (the revocations table must exist before this trigger can fire; created below)
CREATE TRIGGER trg_cert_update_rule BEFORE UPDATE ON certificates
    FOR EACH ROW EXECUTE FUNCTION certificate_before_update();
CREATE TRIGGER trg_cert_no_delete BEFORE DELETE ON certificates
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- ---------------------------------------------------------------------
-- 4. Revocations — permanent
-- ---------------------------------------------------------------------
CREATE TABLE revocations (
    serial_number         cert_serial PRIMARY KEY REFERENCES certificates(serial_number),
    revocation_date       TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason_code           SMALLINT NOT NULL CHECK (reason_code IN (0,1,2,3,4,5,9,10)),
                          -- RFC 5280 CRLReason: 0 unspecified, 1 keyCompromise, 2 cACompromise,
                          -- 3 affiliationChanged, 4 superseded, 5 cessationOfOperation,
                          -- 9 privilegeWithdrawn, 10 aACompromise.
                          -- 6 certificateHold and 8 removeFromCRL are excluded: no un-revoking.
    compromise_timestamp  TIMESTAMPTZ,                   -- RFC 5280 invalidityDate
    revoked_by            UUID NOT NULL REFERENCES users(user_id),
    note                  TEXT,
    published_at          TIMESTAMPTZ,                   -- thisUpdate of the first CRL listing it
    CHECK (compromise_timestamp IS NULL OR compromise_timestamp <= revocation_date)
);
CREATE INDEX ix_rev_unpublished ON revocations (revocation_date) WHERE published_at IS NULL;

CREATE OR REPLACE FUNCTION revocation_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM certificates
                    WHERE serial_number = NEW.serial_number AND status = 'active') THEN
        RAISE EXCEPTION 'certificate does not exist or is already revoked';
    END IF;
    NEW.revocation_date := now();
    NEW.published_at    := NULL;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION revocation_after_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE certificates SET status = 'revoked' WHERE serial_number = NEW.serial_number;
    -- OCSP responder: LISTEN cert_revoked;  payload = hex serial
    PERFORM pg_notify('cert_revoked', encode(NEW.serial_number, 'hex'));
    RETURN NULL;
END $$;

CREATE OR REPLACE FUNCTION revocation_before_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.published_at IS NOT NULL OR NEW.published_at IS NULL THEN
        RAISE EXCEPTION 'revocations are permanent; published_at is set once';
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_rev_before_insert BEFORE INSERT ON revocations
    FOR EACH ROW EXECUTE FUNCTION revocation_before_insert();
CREATE TRIGGER trg_rev_after_insert AFTER INSERT ON revocations
    FOR EACH ROW EXECUTE FUNCTION revocation_after_insert();
CREATE TRIGGER trg_rev_update_cols BEFORE UPDATE ON revocations
    FOR EACH ROW EXECUTE FUNCTION allow_update_only('published_at');
CREATE TRIGGER trg_rev_update_rule BEFORE UPDATE ON revocations
    FOR EACH ROW EXECUTE FUNCTION revocation_before_update();
CREATE TRIGGER trg_rev_no_delete BEFORE DELETE ON revocations
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- NFR-SEC-019: drop the cached OCSP response; reason 1 (keyCompromise)
-- signals the CRL daemon to rebuild now.  LISTEN emergency_crl; payload =
-- issuer ca_id.  Delivered at commit, so it follows the revocation itself.
CREATE OR REPLACE FUNCTION revocation_flush_and_escalate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM ocsp_responses WHERE serial_number = NEW.serial_number;
    IF NEW.reason_code = 1 THEN
        PERFORM pg_notify('emergency_crl',
            (SELECT issuer_ca_id::text FROM certificates WHERE serial_number = NEW.serial_number));
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER trg_rev_flush_ocsp AFTER INSERT ON revocations
    FOR EACH ROW EXECUTE FUNCTION revocation_flush_and_escalate();

-- ---------------------------------------------------------------------
-- 5. CRLs — one row per published CRL, numbered per issuer
-- ---------------------------------------------------------------------
CREATE TABLE crls (
    crl_id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issuer_ca_id   UUID   NOT NULL REFERENCES issuing_cas(ca_id),
    crl_number     BIGINT NOT NULL,                      -- set by trigger; only goes up
    this_update    TIMESTAMPTZ NOT NULL,
    next_update    TIMESTAMPTZ NOT NULL,
    crl_der        BYTEA NOT NULL,
    crl_sha256     BYTEA NOT NULL CHECK (octet_length(crl_sha256) = 32),
    revoked_count  INT   NOT NULL CHECK (revoked_count >= 0),
    is_emergency   BOOLEAN NOT NULL DEFAULT false,       -- rebuilt after a key compromise
    file_path      TEXT,                                 -- where Nginx serves it from
    generated_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (issuer_ca_id, crl_number),
    CHECK (next_update > this_update),
    CHECK (crl_sha256 = digest(crl_der, 'sha256'))
);

CREATE OR REPLACE FUNCTION crl_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    ca    issuing_cas;
    prev  crls;
BEGIN
    SELECT * INTO ca FROM issuing_cas WHERE ca_id = NEW.issuer_ca_id FOR UPDATE;   -- one CRL at a time per CA
    IF ca.ca_type = 'ocsp_signer' OR ca.status = 'retired' THEN
        RAISE EXCEPTION 'this CA cannot publish CRLs';
    END IF;

    SELECT * INTO prev FROM crls
     WHERE issuer_ca_id = NEW.issuer_ca_id ORDER BY crl_number DESC LIMIT 1;
    IF FOUND AND NEW.this_update <= prev.this_update THEN
        RAISE EXCEPTION 'thisUpdate must be later than the previous CRL (%)', prev.this_update;
    END IF;
    NEW.crl_number := coalesce(prev.crl_number, 0) + 1;
    RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION crl_after_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    UPDATE revocations r
       SET published_at = NEW.this_update
      FROM certificates c
     WHERE c.serial_number = r.serial_number
       AND c.issuer_ca_id  = NEW.issuer_ca_id
       AND r.published_at IS NULL
       AND r.revocation_date <= NEW.this_update;
    RETURN NULL;
END $$;

CREATE TRIGGER trg_crl_before_insert BEFORE INSERT ON crls
    FOR EACH ROW EXECUTE FUNCTION crl_before_insert();
CREATE TRIGGER trg_crl_after_insert AFTER INSERT ON crls
    FOR EACH ROW EXECUTE FUNCTION crl_after_insert();
CREATE TRIGGER trg_crl_frozen BEFORE UPDATE OR DELETE ON crls
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- ---------------------------------------------------------------------
-- 5b. CRL generation log — crls holds only successful CRLs; this table
--     records every attempt, so a failed or stuck build is visible.
-- ---------------------------------------------------------------------
CREATE TABLE crl_generation_runs (
    run_id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    issuer_ca_id   UUID NOT NULL REFERENCES issuing_cas(ca_id),
    trigger        TEXT NOT NULL CHECK (trigger IN ('scheduled','revocation','emergency','manual')),
    status         TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','succeeded','failed')),
    started_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at    TIMESTAMPTZ,
    entries_count  INT CHECK (entries_count >= 0),
    crl_id         BIGINT REFERENCES crls(crl_id),
    error_message  TEXT,
    CHECK ((status = 'running') = (finished_at IS NULL)),
    CHECK (status <> 'succeeded' OR crl_id IS NOT NULL),
    CHECK (status <> 'failed'    OR error_message IS NOT NULL)
);
CREATE INDEX ix_crlrun_issuer ON crl_generation_runs (issuer_ca_id, started_at DESC);
CREATE INDEX ix_crlrun_failed ON crl_generation_runs (started_at) WHERE status = 'failed';

CREATE OR REPLACE FUNCTION crl_run_before_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.status <> 'running' THEN
        RAISE EXCEPTION 'crl run % is finished and cannot change', OLD.run_id;
    END IF;
    IF NEW.status <> 'running' THEN
        NEW.finished_at := coalesce(NEW.finished_at, now());
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_crlrun_cols BEFORE UPDATE ON crl_generation_runs
    FOR EACH ROW EXECUTE FUNCTION allow_update_only('status','finished_at','entries_count','crl_id','error_message');
CREATE TRIGGER trg_crlrun_rule BEFORE UPDATE ON crl_generation_runs
    FOR EACH ROW EXECUTE FUNCTION crl_run_before_update();
CREATE TRIGGER trg_crlrun_no_delete BEFORE DELETE ON crl_generation_runs
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- ---------------------------------------------------------------------
-- 5c. OCSP response store — one latest signed response per certificate.
--     Needed only for pre-signed responses (OD-21). With engine-brokered
--     signing and an in-memory cache this table can stay empty.
--     'unknown' is never stored: an unknown serial has no row here.
-- ---------------------------------------------------------------------
CREATE TABLE ocsp_responses (
    serial_number    cert_serial PRIMARY KEY REFERENCES certificates(serial_number),
    signer_ca_id     UUID NOT NULL REFERENCES issuing_cas(ca_id),
    cert_status      TEXT NOT NULL CHECK (cert_status IN ('good','revoked')),
    revocation_date  TIMESTAMPTZ,
    reason_code      SMALLINT,
    this_update      TIMESTAMPTZ NOT NULL,
    next_update      TIMESTAMPTZ NOT NULL,
    produced_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    response_der     BYTEA NOT NULL,
    response_sha256  BYTEA NOT NULL CHECK (octet_length(response_sha256) = 32),
    CHECK (next_update > this_update),
    CHECK ((cert_status = 'revoked') = (revocation_date IS NOT NULL)),
    CHECK (response_sha256 = digest(response_der, 'sha256'))
);
CREATE INDEX ix_ocsp_expiry ON ocsp_responses (next_update);

CREATE OR REPLACE FUNCTION ocsp_response_before_write() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE s issuing_cas;
BEGIN
    SELECT * INTO s FROM issuing_cas WHERE ca_id = NEW.signer_ca_id;
    IF NOT FOUND OR s.ca_type <> 'ocsp_signer' OR s.status <> 'active' THEN
        RAISE EXCEPTION 'signer must be an active OCSP signer';
    END IF;
    IF NEW.cert_status = 'good'
       AND EXISTS (SELECT 1 FROM revocations WHERE serial_number = NEW.serial_number) THEN
        RAISE EXCEPTION 'certificate % is revoked; cannot store a good response', encode(NEW.serial_number, 'hex');
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_ocsp_before_write BEFORE INSERT OR UPDATE ON ocsp_responses
    FOR EACH ROW EXECUTE FUNCTION ocsp_response_before_write();

-- =====================================================================
-- Views for the other services
-- =====================================================================

-- OCSP responder / status API: one row per certificate
CREATE OR REPLACE VIEW v_certificate_status AS
SELECT c.serial_number,
       c.issuer_ca_id,
       CASE WHEN r.serial_number IS NOT NULL THEN 'revoked'
            WHEN c.not_after <= now()        THEN 'expired'
            ELSE 'good' END                  AS cert_status,
       r.revocation_date,
       r.reason_code,
       r.compromise_timestamp,
       c.not_before,
       c.not_after
FROM certificates c
LEFT JOIN revocations r USING (serial_number);

-- CRL generator: what goes into the next CRL of each issuer
-- (revoked certificates that have not expired yet)
CREATE OR REPLACE VIEW v_crl_entries AS
SELECT c.issuer_ca_id,
       r.serial_number,
       r.revocation_date,
       r.reason_code,
       r.compromise_timestamp
FROM revocations r
JOIN certificates c USING (serial_number)
WHERE c.not_after > now();


-- CRL health for the dashboard (FR14)
CREATE OR REPLACE VIEW v_crl_health AS
SELECT ca.ca_id AS issuer_ca_id,
       ca.name,
       l.crl_number,
       l.this_update,
       l.next_update,
       coalesce(l.next_update < now(), true) AS is_overdue,
       (SELECT count(*) FROM revocations r
          JOIN certificates c USING (serial_number)
         WHERE c.issuer_ca_id = ca.ca_id AND r.published_at IS NULL) AS unpublished_revocations,
       (SELECT count(*) FROM crl_generation_runs g
         WHERE g.issuer_ca_id = ca.ca_id AND g.status = 'failed'
           AND g.started_at > now() - interval '24 hours')           AS failed_runs_24h
FROM issuing_cas ca
LEFT JOIN LATERAL (SELECT * FROM crls WHERE issuer_ca_id = ca.ca_id
                    ORDER BY crl_number DESC LIMIT 1) l ON true
WHERE ca.ca_type <> 'ocsp_signer' AND ca.status <> 'retired';
-- Internal copilot: "Telemetry summaries (SQL)" from the C4 diagram
CREATE OR REPLACE VIEW v_telemetry_summary AS
SELECT
    (SELECT count(*) FROM certificates WHERE status = 'active'  AND not_after >  now())                        AS certs_active,
    (SELECT count(*) FROM certificates WHERE status = 'active'  AND not_after >  now()
                                                               AND not_after <= now() + interval '30 days')   AS certs_expiring_30d,
    (SELECT count(*) FROM certificates WHERE status = 'active'  AND not_after <= now())                        AS certs_expired,
    (SELECT count(*) FROM certificates WHERE status = 'revoked')                                               AS certs_revoked,
    (SELECT count(*) FROM certificate_requests WHERE status IN ('pending_validation','validated'))             AS requests_open,
    (SELECT count(*) FROM domain_challenges    WHERE status IN ('pending','processing'))                       AS challenges_open,
    (SELECT count(*) FROM ov_applications      WHERE status = 'awaiting_review')                               AS ov_awaiting_review,
    (SELECT count(*) FROM revocations          WHERE published_at IS NULL)                                     AS revocations_unpublished,
    now()                                                                                                      AS as_of;