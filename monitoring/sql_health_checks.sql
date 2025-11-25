-- SQL Health-Checks for Evidence & Safety Stack
-- Version: 2025-10-28
-- Run these queries to monitor system health

-- ===================================================================
-- 1) Decision distribution last 24h
-- ===================================================================
-- Shows how many PROMOTE/QUARANTINE/REJECT decisions were made
SELECT decision, COUNT(*) AS n
FROM evidence_ledger
WHERE created_at >= now() - interval '24 hours'
GROUP BY decision
ORDER BY n DESC;

-- ===================================================================
-- 2) DS conflict mass p95 (approx)
-- ===================================================================
-- Shows 95th percentile of Dempster-Shafer conflict mass
-- High values (>0.65) indicate conflicting evidence requiring review
SELECT percentile_disc(0.95) WITHIN GROUP (ORDER BY conflict_k) AS k_p95
FROM (
    SELECT
        CAST(metadata->>'conflict_k' AS FLOAT) as conflict_k
    FROM evidence_ledger
    WHERE created_at >= now() - interval '24 hours'
      AND metadata->>'conflict_k' IS NOT NULL
) sub;

-- ===================================================================
-- 3) Influence budget alerts in last 24h
-- ===================================================================
-- Shows domains with high influence budget z-scores (>=4.0)
-- Indicates potential slow-roll poison attacks
SELECT
    domain,
    bucket_start,
    z_score,
    ib_sum as total_influence,
    samples
FROM influence_budget_rollup
WHERE z_score >= 4.0
  AND bucket_start >= now() - interval '24 hours'
ORDER BY z_score DESC;

-- ===================================================================
-- 4) Canary failures last 24h (if canary_events table exists)
-- ===================================================================
-- Shows canary test failures by type
-- ANY failures indicate system degradation
SELECT
    COALESCE(type, 'unknown') as canary_type,
    COUNT(*) AS fails
FROM canary_events
WHERE result = 'FAIL'
  AND created_at >= now() - interval '24 hours'
GROUP BY type
ORDER BY fails DESC;

-- ===================================================================
-- 5) Promotion FPR estimate (if feedback available)
-- ===================================================================
-- Estimates false positive rate for promotions
-- Target: <= 1%
WITH decisions AS (
    SELECT
        decision,
        CAST(metadata->>'is_false_positive' AS BOOLEAN) as is_false_positive
    FROM evidence_ledger
    WHERE created_at >= now() - interval '24 hours'
      AND decision = 'PROMOTE'
)
SELECT
    COALESCE(SUM(CASE WHEN is_false_positive THEN 1 ELSE 0 END), 0)::float
    / NULLIF(SUM(1), 0) AS fpr_estimate,
    SUM(1) as total_promotions
FROM decisions;

-- ===================================================================
-- 6) Safety blocks by category last 24h
-- ===================================================================
-- Shows which safety categories triggered blocks
SELECT
    CAST(metadata->>'category' AS TEXT) as category,
    COUNT(*) as block_count
FROM evidence_ledger
WHERE decision = 'BLOCK'
  AND created_at >= now() - interval '24 hours'
  AND metadata->>'category' IS NOT NULL
GROUP BY category
ORDER BY block_count DESC;

-- ===================================================================
-- 7) Evasion detection stats last 24h
-- ===================================================================
-- Shows evasion attempts detected
SELECT
    CAST(metadata->'safety'->'evasion'->>'evasion_count' AS INT) as evasion_count,
    COUNT(*) as occurrences
FROM evidence_ledger
WHERE created_at >= now() - interval '24 hours'
  AND metadata->'safety'->'evasion'->>'evasion_count' IS NOT NULL
GROUP BY evasion_count
ORDER BY evasion_count DESC;

-- ===================================================================
-- 8) Recent high-risk decisions (last 100)
-- ===================================================================
-- Shows recent decisions with high risk scores
SELECT
    decision_id,
    decision,
    CAST(metadata->'safety'->>'risk' AS FLOAT) as risk_score,
    CAST(metadata->'safety'->>'category' AS TEXT) as category,
    created_at
FROM evidence_ledger
WHERE CAST(metadata->'safety'->>'risk' AS FLOAT) >= 0.5
ORDER BY created_at DESC
LIMIT 100;

-- ===================================================================
-- 9) System health summary
-- ===================================================================
-- Overall health metrics
SELECT
    COUNT(*) as total_decisions,
    SUM(CASE WHEN decision = 'PROMOTE' THEN 1 ELSE 0 END) as promotions,
    SUM(CASE WHEN decision = 'QUARANTINE' THEN 1 ELSE 0 END) as quarantines,
    SUM(CASE WHEN decision = 'BLOCK' THEN 1 ELSE 0 END) as blocks,
    ROUND(AVG(CAST(metadata->'safety'->>'risk' AS FLOAT)), 3) as avg_risk_score
FROM evidence_ledger
WHERE created_at >= now() - interval '24 hours';

-- ===================================================================
-- 10) Influence budget rollup summary (all domains)
-- ===================================================================
-- Shows current influence budget state across all domains
SELECT
    domain,
    COUNT(*) as total_buckets,
    MAX(z_score) as max_z_score,
    AVG(z_score) as avg_z_score,
    SUM(CASE WHEN ABS(z_score) >= 4.0 THEN 1 ELSE 0 END) as alert_buckets
FROM influence_budget_rollup
WHERE bucket_start >= now() - interval '24 hours'
GROUP BY domain
ORDER BY max_z_score DESC;
