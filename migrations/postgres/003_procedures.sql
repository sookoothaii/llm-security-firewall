-- Migration 019b: Add Stored Procedures for Evidence Pipeline
-- Based on GPT-5 specifications (2025-10-27)
--
-- Functions:
--   1. sp_upsert_domain_reputation  - Upsert domain reputation cache
--   2. sp_upsert_doi_registry       - Upsert DOI validation cache
--   3. sp_record_link_verification  - Record link verification event
--   4. sp_record_nli_validation     - Record NLI validation event

BEGIN;

-- ============================================================================
-- 1. UPSERT DOMAIN REPUTATION
-- ============================================================================

CREATE OR REPLACE FUNCTION sp_upsert_domain_reputation(
  p_domain TEXT,
  p_reputation REAL,
  p_ts TIMESTAMPTZ DEFAULT now()
) RETURNS VOID
LANGUAGE plpgsql AS $$
BEGIN
  IF p_reputation < 0 OR p_reputation > 1 THEN
    RAISE EXCEPTION 'reputation must be in [0,1], got %', p_reputation;
  END IF;
  INSERT INTO domain_reputation_cache(domain, reputation, last_updated)
  VALUES (lower(p_domain), p_reputation, p_ts)
  ON CONFLICT (domain)
  DO UPDATE SET reputation = EXCLUDED.reputation,
                last_updated = EXCLUDED.last_updated;
END;
$$;


-- ============================================================================
-- 2. UPSERT DOI REGISTRY
-- ============================================================================

CREATE OR REPLACE FUNCTION sp_upsert_doi_registry(
  p_doi TEXT,
  p_status TEXT,
  p_ts TIMESTAMPTZ DEFAULT now()
) RETURNS VOID
LANGUAGE plpgsql AS $$
BEGIN
  IF p_status NOT IN ('valid','invalid','unknown') THEN
    RAISE EXCEPTION 'status must be valid|invalid|unknown, got %', p_status;
  END IF;
  INSERT INTO doi_registry_cache(doi, status, last_checked)
  VALUES (lower(p_doi), p_status, p_ts)
  ON CONFLICT (doi)
  DO UPDATE SET status = EXCLUDED.status,
                last_checked = EXCLUDED.last_checked;
END;
$$;


-- ============================================================================
-- 3. RECORD LINK VERIFICATION EVENT
-- ============================================================================

CREATE OR REPLACE FUNCTION sp_record_link_verification(
  p_digest CHAR(64),
  p_url TEXT,
  p_doi TEXT,
  p_doi_status TEXT,
  p_url_scheme_ok BOOLEAN,
  p_ts TIMESTAMPTZ DEFAULT now()
) RETURNS BIGINT
LANGUAGE plpgsql AS $$
DECLARE
  v_id BIGINT;
BEGIN
  INSERT INTO link_verification_events(
    digest, url, doi, doi_status, url_scheme_ok, created_at
  )
  VALUES (p_digest, p_url, p_doi, p_doi_status, p_url_scheme_ok, p_ts)
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$;


-- ============================================================================
-- 4. RECORD NLI VALIDATION EVENT
-- ============================================================================

CREATE OR REPLACE FUNCTION sp_record_nli_validation(
  p_digest CHAR(64),
  p_nli_score REAL,
  p_kb_snapshot_hash CHAR(64),
  p_ts TIMESTAMPTZ DEFAULT now()
) RETURNS BIGINT
LANGUAGE plpgsql AS $$
DECLARE
  v_id BIGINT;
BEGIN
  IF p_nli_score < 0 OR p_nli_score > 1 THEN
    RAISE EXCEPTION 'nli_score must be in [0,1], got %', p_nli_score;
  END IF;
  INSERT INTO nli_validation_events(
    digest, nli_score, kb_snapshot_hash, created_at
  )
  VALUES (p_digest, p_nli_score, p_kb_snapshot_hash, p_ts)
  RETURNING id INTO v_id;
  RETURN v_id;
END;
$$;

COMMIT;

-- Done!

