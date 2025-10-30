-- Migration 006: Transparency Log for Write-Path Policy Engine
-- Purpose: Append-only Merkle log for evidence writes, preventing memory poisoning
-- Creator: Joerg Bollwahn
-- Date: 2025-10-30

-- Main transparency log table (append-only, immutable)
CREATE TABLE IF NOT EXISTS evidence_write_log (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  writer_instance_id UUID NOT NULL,
  content_hash BYTEA NOT NULL,              -- SHA-256 of content
  parent_hash BYTEA,                        -- Previous Merkle node (NULL for genesis)
  source_url TEXT,
  source_trust FLOAT CHECK (source_trust BETWEEN 0 AND 1),
  ttl_expiry TIMESTAMPTZ,
  signature BYTEA,                          -- Writer signature (placeholder for future PKI)
  meta JSONB DEFAULT '{}'::jsonb,           -- {domain, model_id, policy_version, quarantine_reason, ...}
  CONSTRAINT unique_content_hash UNIQUE (content_hash)
);

-- Index for Merkle chain traversal
CREATE INDEX IF NOT EXISTS idx_evidence_write_parent ON evidence_write_log(parent_hash);

-- Index for TTL expiry queries
CREATE INDEX IF NOT EXISTS idx_evidence_write_ttl ON evidence_write_log(ttl_expiry) WHERE ttl_expiry IS NOT NULL;

-- Index for source trust filtering
CREATE INDEX IF NOT EXISTS idx_evidence_write_trust ON evidence_write_log(source_trust);

-- Index for writer instance tracking
CREATE INDEX IF NOT EXISTS idx_evidence_write_writer ON evidence_write_log(writer_instance_id);

-- Index for timestamp range queries
CREATE INDEX IF NOT EXISTS idx_evidence_write_ts ON evidence_write_log(ts DESC);

-- Quarantine queue for suspicious writes (two-man rule candidates)
CREATE TABLE IF NOT EXISTS evidence_quarantine (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  write_log_id BIGINT REFERENCES evidence_write_log(id),
  content_hash BYTEA NOT NULL,
  reason TEXT NOT NULL,                     -- 'low_trust', 'short_ttl', 'circular_ref', 'high_risk_domain'
  first_judge TEXT,                         -- First approval (NULL = pending)
  second_judge TEXT,                        -- Second approval (NULL = pending)
  status TEXT NOT NULL DEFAULT 'pending',   -- 'pending', 'approved', 'rejected', 'expired'
  expires_at TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '7 days'),
  meta JSONB DEFAULT '{}'::jsonb
);

-- Index for pending quarantine items
CREATE INDEX IF NOT EXISTS idx_quarantine_pending ON evidence_quarantine(status, ts) WHERE status = 'pending';

-- Index for expiry cleanup
CREATE INDEX IF NOT EXISTS idx_quarantine_expiry ON evidence_quarantine(expires_at) WHERE status = 'pending';

-- Merkle root tracking (for chain integrity verification)
CREATE TABLE IF NOT EXISTS evidence_merkle_roots (
  id BIGSERIAL PRIMARY KEY,
  ts TIMESTAMPTZ NOT NULL DEFAULT now(),
  root_hash BYTEA NOT NULL,
  leaf_count BIGINT NOT NULL,
  last_write_id BIGINT REFERENCES evidence_write_log(id),
  meta JSONB DEFAULT '{}'::jsonb
);

-- View: Recent write activity
CREATE OR REPLACE VIEW evidence_write_recent AS
SELECT 
  id,
  ts,
  writer_instance_id,
  encode(content_hash, 'hex') AS content_hash_hex,
  source_url,
  source_trust,
  ttl_expiry,
  meta->>'domain' AS domain,
  meta->>'policy_version' AS policy_version
FROM evidence_write_log
ORDER BY ts DESC
LIMIT 100;

-- View: Quarantine dashboard
CREATE OR REPLACE VIEW evidence_quarantine_dashboard AS
SELECT 
  q.id,
  q.ts AS quarantined_at,
  encode(q.content_hash, 'hex') AS content_hash_hex,
  q.reason,
  q.status,
  q.first_judge,
  q.second_judge,
  q.expires_at,
  w.source_url,
  w.source_trust,
  w.meta->>'domain' AS domain
FROM evidence_quarantine q
LEFT JOIN evidence_write_log w ON q.write_log_id = w.id
WHERE q.status = 'pending'
ORDER BY q.ts DESC;

-- View: Trust statistics by domain
CREATE OR REPLACE VIEW evidence_trust_by_domain AS
SELECT 
  meta->>'domain' AS domain,
  COUNT(*) AS total_writes,
  AVG(source_trust) AS avg_trust,
  MIN(source_trust) AS min_trust,
  MAX(source_trust) AS max_trust,
  COUNT(*) FILTER (WHERE source_trust < 0.5) AS low_trust_count,
  COUNT(*) FILTER (WHERE meta->>'quarantine_reason' IS NOT NULL) AS quarantine_count
FROM evidence_write_log
WHERE meta->>'domain' IS NOT NULL
GROUP BY meta->>'domain'
ORDER BY total_writes DESC;

-- Function: Get latest Merkle root
CREATE OR REPLACE FUNCTION get_latest_merkle_root()
RETURNS TABLE (
  root_hash BYTEA,
  leaf_count BIGINT,
  last_write_id BIGINT,
  ts TIMESTAMPTZ
) AS $$
BEGIN
  RETURN QUERY
  SELECT m.root_hash, m.leaf_count, m.last_write_id, m.ts
  FROM evidence_merkle_roots m
  ORDER BY m.id DESC
  LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- Function: Verify Merkle inclusion (placeholder - full implementation needs merkle proof)
CREATE OR REPLACE FUNCTION verify_merkle_inclusion(
  p_content_hash BYTEA,
  p_root_hash BYTEA
)
RETURNS BOOLEAN AS $$
DECLARE
  v_exists BOOLEAN;
BEGIN
  -- Simple existence check (full Merkle proof verification would require proof path)
  SELECT EXISTS(
    SELECT 1 FROM evidence_write_log
    WHERE content_hash = p_content_hash
  ) INTO v_exists;
  
  RETURN v_exists;
END;
$$ LANGUAGE plpgsql;

-- Function: Clean expired quarantine entries
CREATE OR REPLACE FUNCTION clean_expired_quarantine()
RETURNS INTEGER AS $$
DECLARE
  v_deleted INTEGER;
BEGIN
  WITH deleted AS (
    UPDATE evidence_quarantine
    SET status = 'expired'
    WHERE status = 'pending' AND expires_at < now()
    RETURNING id
  )
  SELECT COUNT(*) INTO v_deleted FROM deleted;
  
  RETURN v_deleted;
END;
$$ LANGUAGE plpgsql;

-- Trigger: Prevent updates to write log (append-only enforcement)
CREATE OR REPLACE FUNCTION prevent_write_log_update()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'evidence_write_log is append-only - updates forbidden';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_prevent_write_log_update
  BEFORE UPDATE ON evidence_write_log
  FOR EACH ROW
  EXECUTE FUNCTION prevent_write_log_update();

-- Trigger: Prevent deletes from write log (immutability enforcement)
CREATE OR REPLACE FUNCTION prevent_write_log_delete()
RETURNS TRIGGER AS $$
BEGIN
  RAISE EXCEPTION 'evidence_write_log is immutable - deletes forbidden';
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_prevent_write_log_delete
  BEFORE DELETE ON evidence_write_log
  FOR EACH ROW
  EXECUTE FUNCTION prevent_write_log_delete();

-- Comment for documentation
COMMENT ON TABLE evidence_write_log IS 'Append-only Merkle log for all evidence writes - immutable audit trail';
COMMENT ON TABLE evidence_quarantine IS 'Two-man rule queue for suspicious evidence writes';
COMMENT ON TABLE evidence_merkle_roots IS 'Merkle root snapshots for chain integrity verification';
COMMENT ON COLUMN evidence_write_log.content_hash IS 'SHA-256 hash of evidence content';
COMMENT ON COLUMN evidence_write_log.parent_hash IS 'Previous node in Merkle chain (NULL for genesis block)';
COMMENT ON COLUMN evidence_write_log.signature IS 'Writer signature (placeholder for future PKI integration)';
COMMENT ON COLUMN evidence_write_log.meta IS 'JSONB metadata: domain, model_id, policy_version, quarantine_reason, etc.';



