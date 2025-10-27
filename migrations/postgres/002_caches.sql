-- Migration 019: Evidence Pipeline Caches & Events
-- Based on GPT-5 Evidence Pipeline (2025-10-27)
--
-- Tables:
--   1. domain_reputation_cache  - Rolling domain reputation
--   2. doi_registry_cache       - DOI validation cache (offline-friendly)
--   3. link_verification_events - Audit trail for link checks
--   4. nli_validation_events    - NLI consistency logs

BEGIN;

-- ============================================================================
-- 1. DOMAIN_REPUTATION_CACHE (rolling reputation)
-- ============================================================================

CREATE TABLE IF NOT EXISTS domain_reputation_cache (
    domain TEXT PRIMARY KEY,
    reputation REAL CHECK (reputation BETWEEN 0 AND 1),
    last_updated TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_domain_rep_updated ON domain_reputation_cache(last_updated DESC);


-- ============================================================================
-- 2. DOI_REGISTRY_CACHE (offline-friendly)
-- ============================================================================

CREATE TABLE IF NOT EXISTS doi_registry_cache (
    doi TEXT PRIMARY KEY,
    status TEXT CHECK (status IN ('valid','invalid','unknown')) NOT NULL,
    last_checked TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_doi_status ON doi_registry_cache(status);
CREATE INDEX idx_doi_checked ON doi_registry_cache(last_checked DESC);


-- ============================================================================
-- 3. LINK_VERIFICATION_EVENTS (audit trail)
-- ============================================================================

CREATE TABLE IF NOT EXISTS link_verification_events (
    id BIGSERIAL PRIMARY KEY,
    digest CHAR(64) NOT NULL,          -- BLAKE3 content hash
    url TEXT,
    doi TEXT,
    doi_status TEXT,
    url_scheme_ok BOOLEAN NOT NULL,
    https BOOLEAN,
    accessible BOOLEAN,
    status_code INTEGER,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_link_verif_digest ON link_verification_events(digest);
CREATE INDEX idx_link_verif_created ON link_verification_events(created_at DESC);


-- ============================================================================
-- 4. NLI_VALIDATION_EVENTS (per content digest)
-- ============================================================================

CREATE TABLE IF NOT EXISTS nli_validation_events (
    id BIGSERIAL PRIMARY KEY,
    digest CHAR(64) NOT NULL,          -- BLAKE3 content hash
    nli_score REAL CHECK (nli_score BETWEEN 0 AND 1),
    kb_snapshot_hash CHAR(64),         -- Hash of KB state at validation time
    kb_facts_count INTEGER,
    aggregation_method TEXT,           -- max | mean | min
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_nli_val_digest ON nli_validation_events(digest);
CREATE INDEX idx_nli_val_created ON nli_validation_events(created_at DESC);

COMMIT;

-- Done!

