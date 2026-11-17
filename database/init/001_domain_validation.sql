-- =====================================================================
-- PQ-CA — Domain Validation (Challenge) Schema
-- PostgreSQL 15+   |   database/init/001_domain_validation.sql
--
-- Scope: organizations (minimal), certificate requests + SANs,
--        domain challenges, per-checker attempts, RA policy.
--        domain ownership view, ACME placeholders (stretch, FR41).
-- Source of truth = Postgres (audit). Redis = rate-limit counters only.
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid(), digest()

-- ---------------------------------------------------------------------
-- 1. RA policy (single row) — "we will customize it ourselves"
-- ---------------------------------------------------------------------
CREATE TABLE ra_policy (
    policy_id                     SMALLINT PRIMARY KEY DEFAULT 1 CHECK (policy_id = 1),
    pending_challenge_ttl         INTERVAL NOT NULL DEFAULT '7 days',
    validation_reuse_window       INTERVAL NOT NULL DEFAULT '90 days',
    max_failures_per_domain_hour  INT      NOT NULL DEFAULT 5,
    failure_lockout               INTERVAL NOT NULL DEFAULT '1 hour',
    max_certs_per_domain_week     INT      NOT NULL DEFAULT 50,
    max_certs_per_org_week        INT      NOT NULL DEFAULT 50,
    max_duplicate_certs_week      INT      NOT NULL DEFAULT 5,
    max_redirects                 SMALLINT NOT NULL DEFAULT 10,
    required_perspectives         SMALLINT NOT NULL DEFAULT 3,   -- all must agree
    updated_at                    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by                    UUID                            -- FK → users (later)
);
INSERT INTO ra_policy DEFAULT VALUES;

-- ---------------------------------------------------------------------
-- 2. Organizations (OV columns from Tasks.MD §3.5)
-- ---------------------------------------------------------------------
CREATE TABLE organizations (
    organization_id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    legal_name              TEXT    NOT NULL,
    registration_no         TEXT    NOT NULL,
    address                 TEXT,
    country                 CHAR(2) NOT NULL,                 -- ISO 3166-1 alpha-2
    duns                    CHAR(9),                          -- nullable: Q01 (no-DUNS orgs)
    ov_status               TEXT    NOT NULL DEFAULT 'pending'
                            CHECK (ov_status IN ('pending','manual_review','accepted','rejected')),
    account_key_thumbprint  TEXT,                             -- "key fingerprint" in token.fingerprint
    created_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (country, registration_no)
);

-- ---------------------------------------------------------------------
-- 3. Certificate requests (CSR is NOT the PK — one org, many certs)
-- ---------------------------------------------------------------------
CREATE TABLE certificate_requests (
    request_id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id      UUID  NOT NULL REFERENCES organizations(organization_id),
    csr_der              BYTEA NOT NULL,
    csr_sha256           BYTEA NOT NULL CHECK (octet_length(csr_sha256) = 32),
    signature_algorithm  TEXT  NOT NULL
                         CHECK (signature_algorithm IN ('ML-DSA-44','ML-DSA-65','ML-DSA-87')),
    san_set_hash         BYTEA NOT NULL CHECK (octet_length(san_set_hash) = 32),
                         -- sha256 of sorted, lower-cased SAN list → "5 identical certs / week"
    status               TEXT  NOT NULL DEFAULT 'pending_validation'
                         CHECK (status IN ('pending_validation','validated','issued','rejected','cancelled')),
    rejection_reason     TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    issued_at            TIMESTAMPTZ,
    CHECK (status <> 'issued' OR issued_at IS NOT NULL)
);
CREATE INDEX ix_req_org_issued   ON certificate_requests (organization_id, issued_at) WHERE status = 'issued';
CREATE INDEX ix_req_sanset_issued ON certificate_requests (san_set_hash, issued_at)   WHERE status = 'issued';

-- ---------------------------------------------------------------------
-- 4. Domain challenges — linked to ORGANIZATION + DOMAIN (reusable),
--    not to a single CSR.
-- ---------------------------------------------------------------------
CREATE TABLE domain_challenges (
    challenge_id        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id     UUID NOT NULL REFERENCES organizations(organization_id),
    domain              TEXT NOT NULL
                        CHECK (domain = lower(domain) AND domain !~ '^\*\.' AND length(domain) <= 253),
                        -- stored WITHOUT "*."; wildcard is the flag below
    is_wildcard         BOOLEAN NOT NULL DEFAULT false,
    method              TEXT NOT NULL CHECK (method IN ('http-01','dns-01')),   -- customer chooses
    status              TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending','processing','valid','invalid','expired')),

    -- Token: appears in the public HTTP-01 URL, so it is stored as-is.
    -- Key authorization (token.fingerprint): stored ONLY as SHA-256.
    --   HTTP-01 check: sha256(fetched_body)        = key_auth_sha256
    --   DNS-01  check: base64url_decode(TXT value) = key_auth_sha256
    token               TEXT  NOT NULL UNIQUE CHECK (token ~ '^[A-Za-z0-9_-]{43,}$'),
    key_auth_sha256     BYTEA NOT NULL CHECK (octet_length(key_auth_sha256) = 32),

    -- Same domain, different organization → allowed but flagged for RA officer
    requires_ra_review  BOOLEAN NOT NULL DEFAULT false,
    ra_review_reason    TEXT,
    reviewed_by         UUID,                                 -- FK → users (later)
    reviewed_at         TIMESTAMPTZ,
    ra_decision         TEXT CHECK (ra_decision IN ('approved','denied')),

    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at          TIMESTAMPTZ NOT NULL,                 -- pending deadline (policy TTL)
    validated_at        TIMESTAMPTZ,
    valid_until         TIMESTAMPTZ,                          -- reuse window end
    last_checked_at     TIMESTAMPTZ,
    last_error          TEXT,

    CHECK (expires_at > created_at),
    CHECK (status <> 'valid' OR (validated_at IS NOT NULL AND valid_until IS NOT NULL)),
    CHECK ((reviewed_at IS NULL) = (ra_decision IS NULL))
    -- Industry rule (CA/B BR, Let's Encrypt): wildcards via DNS-01 only.
    -- Team decision currently allows HTTP-01 too. To enforce, uncomment:
    -- , CONSTRAINT wildcard_requires_dns CHECK (NOT is_wildcard OR method = 'dns-01')
);

-- Only one open challenge per org + domain + wildcard
CREATE UNIQUE INDEX ux_chal_open
    ON domain_challenges (organization_id, domain, is_wildcard)
    WHERE status IN ('pending','processing');

-- Reuse lookup
CREATE INDEX ix_chal_reuse
    ON domain_challenges (organization_id, domain, is_wildcard, valid_until)
    WHERE status = 'valid';

-- Cross-org detection
CREATE INDEX ix_chal_domain_active
    ON domain_challenges (domain)
    WHERE status IN ('pending','processing','valid');

-- Expiry sweeper
CREATE INDEX ix_chal_expiry
    ON domain_challenges (expires_at)
    WHERE status IN ('pending','processing');

-- RA officer queue
CREATE INDEX ix_chal_ra_queue
    ON domain_challenges (created_at)
    WHERE requires_ra_review AND reviewed_at IS NULL;

-- ---------------------------------------------------------------------
-- 4b. Domain ownership = a currently valid, RA-cleared challenge.
--     No separate "domains" table: it would duplicate domain_challenges.
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW v_domain_ownership AS
SELECT DISTINCT ON (organization_id, domain, is_wildcard)
       organization_id, domain, is_wildcard, challenge_id, method,
       validated_at, valid_until
FROM domain_challenges
WHERE status = 'valid'
  AND valid_until > now()
  AND (NOT requires_ra_review OR ra_decision = 'approved')
ORDER BY organization_id, domain, is_wildcard, valid_until DESC;

-- ---------------------------------------------------------------------
-- 5. Request SANs — one row per SAN, each pointing at the challenge
--    (new or reused) that proves it.
-- ---------------------------------------------------------------------
CREATE TABLE request_domains (
    request_id    UUID    NOT NULL REFERENCES certificate_requests(request_id) ON DELETE CASCADE,
    domain        TEXT    NOT NULL CHECK (domain = lower(domain) AND domain !~ '^\*\.'),
    is_wildcard   BOOLEAN NOT NULL DEFAULT false,
    challenge_id  UUID    REFERENCES domain_challenges(challenge_id),
    PRIMARY KEY (request_id, domain, is_wildcard)
);
CREATE INDEX ix_reqdom_domain    ON request_domains (domain, is_wildcard);
CREATE INDEX ix_reqdom_challenge ON request_domains (challenge_id);

-- ---------------------------------------------------------------------
-- 5b. ACME placeholders (RFC 8555) — stretch goal FR41, empty in the MVP.
--     An ACME authorization is only a pointer to a domain_challenges row,
--     so ACME cannot bypass the issuance gates (FR40).
--     ACME challenge token = domain_challenges.token;
--     key authorization    = token || '.' || account key thumbprint.
-- ---------------------------------------------------------------------
CREATE TABLE acme_accounts (
    account_id       UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id  UUID NOT NULL REFERENCES organizations(organization_id),
    key_thumbprint   TEXT NOT NULL UNIQUE,                 -- RFC 7638 JWK thumbprint
    jwk              JSONB NOT NULL,
    contact          TEXT[],
    status           TEXT NOT NULL DEFAULT 'valid'
                     CHECK (status IN ('valid','deactivated','revoked')),
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE acme_orders (
    order_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id   UUID NOT NULL REFERENCES acme_accounts(account_id),
    request_id   UUID UNIQUE REFERENCES certificate_requests(request_id),   -- set at finalize
    identifiers  JSONB NOT NULL,                           -- [{"type":"dns","value":"example.com"}]
    status       TEXT NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending','ready','processing','valid','invalid')),
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (expires_at > created_at)
);
CREATE INDEX ix_acme_order_account ON acme_orders (account_id, created_at);

CREATE TABLE acme_authorizations (
    authz_id      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    order_id      UUID NOT NULL REFERENCES acme_orders(order_id),
    domain        TEXT NOT NULL CHECK (domain = lower(domain) AND domain !~ '^\*\.'),
    is_wildcard   BOOLEAN NOT NULL DEFAULT false,
    challenge_id  UUID REFERENCES domain_challenges(challenge_id),
    status        TEXT NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','valid','invalid','deactivated','expired','revoked')),
    expires_at    TIMESTAMPTZ NOT NULL,
    UNIQUE (order_id, domain, is_wildcard)
);
CREATE INDEX ix_acme_authz_challenge ON acme_authorizations (challenge_id);

-- ---------------------------------------------------------------------
-- 6. Challenge attempts — one row per checker (vantage point) per round
-- ---------------------------------------------------------------------
CREATE TABLE challenge_attempts (
    attempt_id             BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    challenge_id           UUID     NOT NULL REFERENCES domain_challenges(challenge_id),
    round_no               INT      NOT NULL CHECK (round_no >= 1),
    vantage_point          TEXT     NOT NULL,                 -- e.g. 'checker-1'
    resolver_ip            INET,                              -- DNS resolver used
    resolved_ip            INET,                              -- target IP connected to
    result                 TEXT     NOT NULL CHECK (result IN (
                               'success','mismatch','not_found','timeout','dns_error',
                               'connection_error','redirect_limit','blocked_ip',
                               'blocked_port','blocked_scheme','error')),
    observed_value_sha256  BYTEA    CHECK (observed_value_sha256 IS NULL OR octet_length(observed_value_sha256) = 32),
    http_status            SMALLINT,
    redirect_count         SMALLINT NOT NULL DEFAULT 0 CHECK (redirect_count >= 0),
    final_url              TEXT,
    error_message          TEXT,
    checked_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (challenge_id, round_no, vantage_point)
);
CREATE INDEX ix_attempt_checked ON challenge_attempts (checked_at);

-- Attempts are audit evidence: append-only
CREATE OR REPLACE FUNCTION forbid_modify() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '% on % is not allowed (audit record)', TG_OP, TG_TABLE_NAME;
END $$;

CREATE TRIGGER trg_attempts_append_only
    BEFORE UPDATE OR DELETE ON challenge_attempts
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- Challenges are kept for audit: no deletes
CREATE TRIGGER trg_challenges_no_delete
    BEFORE DELETE ON domain_challenges
    FOR EACH ROW EXECUTE FUNCTION forbid_modify();

-- ---------------------------------------------------------------------
-- 7. Triggers: policy-driven timestamps + cross-org flag
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION challenge_before_insert() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE
    p ra_policy;
BEGIN
    SELECT * INTO p FROM ra_policy WHERE policy_id = 1;

    IF NEW.expires_at IS NULL THEN
        NEW.expires_at := now() + p.pending_challenge_ttl;
    END IF;

    -- Same domain held/pending by another organization → flag for RA officer
    IF EXISTS (
        SELECT 1 FROM domain_challenges c
        WHERE c.domain = NEW.domain
          AND c.organization_id <> NEW.organization_id
          AND (c.status IN ('pending','processing')
               OR (c.status = 'valid' AND c.valid_until > now()))
    ) THEN
        NEW.requires_ra_review := true;
        NEW.ra_review_reason   := coalesce(NEW.ra_review_reason,
                                  'Domain is pending or validated for another organization');
    END IF;

    RETURN NEW;
END $$;

CREATE TRIGGER trg_challenge_before_insert
    BEFORE INSERT ON domain_challenges
    FOR EACH ROW EXECUTE FUNCTION challenge_before_insert();

CREATE OR REPLACE FUNCTION challenge_before_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- Identity of a challenge never changes
    IF (NEW.organization_id, NEW.domain, NEW.is_wildcard, NEW.method, NEW.token, NEW.key_auth_sha256)
       IS DISTINCT FROM
       (OLD.organization_id, OLD.domain, OLD.is_wildcard, OLD.method, OLD.token, OLD.key_auth_sha256) THEN
        RAISE EXCEPTION 'challenge identity fields are immutable';
    END IF;

    -- Final states are final
    IF OLD.status IN ('invalid','expired') AND NEW.status <> OLD.status THEN
        RAISE EXCEPTION 'challenge % is final (%)', OLD.challenge_id, OLD.status;
    END IF;

    -- On becoming valid: stamp validation + reuse window from policy
    IF NEW.status = 'valid' AND OLD.status <> 'valid' THEN
        NEW.validated_at := coalesce(NEW.validated_at, now());
        NEW.valid_until  := coalesce(NEW.valid_until,
                            NEW.validated_at + (SELECT validation_reuse_window FROM ra_policy WHERE policy_id = 1));
    END IF;

    RETURN NEW;
END $$;

CREATE TRIGGER trg_challenge_before_update
    BEFORE UPDATE ON domain_challenges
    FOR EACH ROW EXECUTE FUNCTION challenge_before_update();

-- ---------------------------------------------------------------------
-- 8. Sweeper (run from cron / Celery) — Postgres has no TTL
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION expire_stale_challenges() RETURNS INT LANGUAGE plpgsql AS $$
DECLARE n INT;
BEGIN
    UPDATE domain_challenges
       SET status = 'expired'
     WHERE (status IN ('pending','processing') AND expires_at  <= now())
        OR (status = 'valid'                  AND valid_until <= now());
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END $$;

-- ---------------------------------------------------------------------
-- 9. Validation gate — every SAN must be proven; OV must be accepted.
--    A failed SAN blocks the request but does NOT touch other SANs'
--    challenges (they stay valid for reuse).
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW v_request_validation AS
SELECT r.request_id,
       r.organization_id,
       o.ov_status,
       count(*)                                                        AS san_count,
       count(*) FILTER (WHERE c.status = 'valid' AND c.valid_until > now()
                          AND (NOT c.requires_ra_review OR c.ra_decision = 'approved'))
                                                                        AS san_valid,
       count(*) FILTER (WHERE c.status IN ('invalid','expired')
                          OR c.ra_decision = 'denied')                 AS san_failed
FROM certificate_requests r
JOIN organizations   o ON o.organization_id = r.organization_id
JOIN request_domains d ON d.request_id      = r.request_id
LEFT JOIN domain_challenges c ON c.challenge_id = d.challenge_id
GROUP BY r.request_id, r.organization_id, o.ov_status;

CREATE OR REPLACE FUNCTION request_is_validated(p_request UUID) RETURNS BOOLEAN
LANGUAGE sql STABLE AS $$
    SELECT coalesce(
        (SELECT ov_status = 'accepted' AND san_valid = san_count
           FROM v_request_validation WHERE request_id = p_request),
        false);
$$;

-- ---------------------------------------------------------------------
-- 10. Rate-limit helpers (Redis is primary; these rebuild/verify it)
-- ---------------------------------------------------------------------
CREATE OR REPLACE VIEW v_domain_failures_last_hour AS
SELECT c.domain,
       count(DISTINCT (a.challenge_id, a.round_no)) AS failed_rounds
FROM challenge_attempts a
JOIN domain_challenges  c ON c.challenge_id = a.challenge_id
WHERE a.result <> 'success'
  AND a.checked_at > now() - interval '1 hour'
GROUP BY c.domain;

CREATE OR REPLACE VIEW v_certs_last_week AS
SELECT 'organization' AS scope, organization_id::text AS key, count(*) AS issued
  FROM certificate_requests
 WHERE status = 'issued' AND issued_at > now() - interval '7 days'
 GROUP BY organization_id
UNION ALL
SELECT 'domain', d.domain, count(DISTINCT r.request_id)
  FROM certificate_requests r JOIN request_domains d USING (request_id)
 WHERE r.status = 'issued' AND r.issued_at > now() - interval '7 days'
 GROUP BY d.domain
UNION ALL
SELECT 'san_set', encode(san_set_hash, 'hex'), count(*)
  FROM certificate_requests
 WHERE status = 'issued' AND issued_at > now() - interval '7 days'
 GROUP BY san_set_hash;