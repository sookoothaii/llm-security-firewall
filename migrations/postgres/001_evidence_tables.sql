-- Migration 018: Memory Poisoning Defense Tables
-- Based on GPT-5 Policy & Controls (2025-10-27)
--
-- Tables:
--   1. evidence_ledger      - Append-only ledger for all evidence writes
--   2. evidence_snapshots   - Immutable snapshots for rollback
--   3. poison_detections    - Log of detected poisoning attempts
--   4. forensic_traceback   - Influence scores for forensic analysis

-- ============================================================================
-- 1. EVIDENCE_LEDGER (Append-only, tamper-evident)
-- ============================================================================

CREATE TABLE IF NOT EXISTS evidence_ledger (
    entry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    writer_id VARCHAR(255) NOT NULL,          -- User or service ID
    instance_id UUID NOT NULL,                 -- LLM instance that wrote this

    -- Operation type
    op VARCHAR(50) NOT NULL,                   -- CREATE | UPDATE | DELETE | PROMOTE | DEMOTE | QUARANTINE

    -- Content
    content_hash VARCHAR(64) NOT NULL,         -- SHA256 of content
    parent_hash VARCHAR(64),                   -- Previous entry hash (chain)
    content_type VARCHAR(50),                  -- KB_FACT | SUPERMEMORY | RAG_DOC
    content_summary TEXT,                      -- Short summary for audit

    -- Source information
    source_url TEXT,
    source_domain VARCHAR(255),
    source_signature VARCHAR(255),             -- DKIM/PGP/none

    -- Scores
    trust_score FLOAT,                         -- 0-1 composite trust
    nli_score FLOAT,                           -- 0-1 NLI consistency
    domain_trust FLOAT,                        -- 0-1 domain authority

    -- Decision
    decision VARCHAR(50) NOT NULL,             -- PROMOTE | QUARANTINE | REJECT
    reviewers TEXT[],                          -- Array of reviewer IDs
    notes TEXT,                                -- Reason / detector hits

    -- Forensics
    authored_by_this_instance BOOLEAN DEFAULT FALSE,
    excluded_from_evidence BOOLEAN DEFAULT TRUE,

    -- Indexes
    CONSTRAINT valid_decision CHECK (decision IN ('PROMOTE', 'QUARANTINE', 'REJECT')),
    CONSTRAINT valid_op CHECK (op IN ('CREATE', 'UPDATE', 'DELETE', 'PROMOTE', 'DEMOTE', 'QUARANTINE'))
);

CREATE INDEX idx_evidence_ledger_timestamp ON evidence_ledger(timestamp DESC);
CREATE INDEX idx_evidence_ledger_instance ON evidence_ledger(instance_id);
CREATE INDEX idx_evidence_ledger_decision ON evidence_ledger(decision);
CREATE INDEX idx_evidence_ledger_content_hash ON evidence_ledger(content_hash);


-- ============================================================================
-- 2. EVIDENCE_SNAPSHOTS (Immutable snapshots for rollback)
-- ============================================================================

CREATE TABLE IF NOT EXISTS evidence_snapshots (
    snapshot_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
    version INTEGER NOT NULL,                  -- Incremental version number

    -- Snapshot data
    kb_fact_count INTEGER,
    supermemory_count INTEGER,
    rag_doc_count INTEGER,

    -- Merkle root for integrity
    merkle_root VARCHAR(64) NOT NULL,          -- BLAKE3 Merkle root
    previous_merkle_root VARCHAR(64),          -- Chain to previous snapshot

    -- Metadata
    created_by VARCHAR(255),
    notes TEXT,

    -- Rollback info
    rollback_enabled BOOLEAN DEFAULT TRUE,
    immutable BOOLEAN DEFAULT TRUE,

    -- External pin (optional)
    external_pin_tx VARCHAR(255),              -- Blockchain/notary anchor

    CONSTRAINT unique_version UNIQUE (version)
);

CREATE INDEX idx_snapshots_timestamp ON evidence_snapshots(timestamp DESC);
CREATE INDEX idx_snapshots_version ON evidence_snapshots(version DESC);


-- ============================================================================
-- 3. POISON_DETECTIONS (Log of detected poisoning attempts)
-- ============================================================================

CREATE TABLE IF NOT EXISTS poison_detections (
    detection_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Detection info
    detector_name VARCHAR(100),                -- EVIDENCE_VALIDATOR | NLI_GATE | etc.
    detection_method VARCHAR(100),             -- SELF_AUTHORED | CIRCULAR_REF | etc.

    -- Suspect entry
    suspect_entry_id UUID,                     -- Links to evidence_ledger
    suspect_content_hash VARCHAR(64),

    -- Scores
    confidence FLOAT,                          -- 0-1 confidence in detection
    severity VARCHAR(50),                      -- LOW | MEDIUM | HIGH | CRITICAL

    -- Action taken
    action VARCHAR(50),                        -- QUARANTINE | REJECT | ALERT
    contained_within_minutes INTEGER,

    -- Forensics
    influence_score FLOAT,                     -- If available
    gradient_similarity FLOAT,                 -- If available

    -- Response
    reviewer VARCHAR(255),
    confirmed BOOLEAN,
    false_positive BOOLEAN,
    notes TEXT,

    CONSTRAINT valid_severity CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    CONSTRAINT valid_action CHECK (action IN ('QUARANTINE', 'REJECT', 'ALERT', 'ROLLBACK'))
);

CREATE INDEX idx_poison_timestamp ON poison_detections(timestamp DESC);
CREATE INDEX idx_poison_severity ON poison_detections(severity);
CREATE INDEX idx_poison_confirmed ON poison_detections(confirmed);


-- ============================================================================
-- 4. FORENSIC_TRACEBACK (Influence scores for forensic analysis)
-- ============================================================================

CREATE TABLE IF NOT EXISTS forensic_traceback (
    traceback_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),

    -- Decision being analyzed
    decision_id UUID,                          -- Links to honesty_decisions

    -- Evidence influence
    evidence_id UUID,                          -- Links to evidence_ledger
    influence_score FLOAT,                     -- 0-1 influence on decision
    gradient_similarity FLOAT,                 -- UTrace-style metric

    -- Method
    traceback_method VARCHAR(100),             -- UTRACE | TRACIN | ATTRIBUTION

    -- Flagging
    suspicious BOOLEAN DEFAULT FALSE,
    threshold_exceeded BOOLEAN,

    -- Metadata
    analyzed_by VARCHAR(255),
    notes TEXT
);

CREATE INDEX idx_traceback_decision ON forensic_traceback(decision_id);
CREATE INDEX idx_traceback_evidence ON forensic_traceback(evidence_id);
CREATE INDEX idx_traceback_suspicious ON forensic_traceback(suspicious);


-- ============================================================================
-- INITIAL DATA: HAK/GAL Configuration
-- ============================================================================

-- Create first snapshot (Genesis)
INSERT INTO evidence_snapshots (
    version, kb_fact_count, supermemory_count, rag_doc_count,
    merkle_root, previous_merkle_root, created_by, notes
) VALUES (
    0, 8565, 0, 0,
    'genesis', NULL, 'system', 'Initial snapshot - HAK/GAL Bootstrap 2025-10-27'
);

-- Done!
