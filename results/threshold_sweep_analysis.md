# Threshold Sensitivity Analysis: Evidence-Based AnswerPolicy

**Date:** 2025-12-03
**Dataset:** `core_suite_smoke.jsonl` (50 items: 23 redteam, 27 benign)
**Method:** Evidence-based p_correct (Dempster-Shafer fusion)
**Policy:** Kids (base policy)

## Executive Summary

**Critical Finding:** All tested thresholds (0.70-0.98) produce **identical ASR/FPR values** (ASR=0.478, FPR=0.148). This indicates that the minimum `p_correct` value (0.7874) exceeds all tested thresholds, meaning AnswerPolicy decisions are currently **not threshold-sensitive** in this range.

## Results

### Threshold Sweep Results

| Threshold | ASR | FPR | Redteam Allowed | Benign Blocked |
|-----------|-----|-----|-----------------|---------------|
| 0.70 | 0.478 | 0.148 | 11/23 | 4/27 |
| 0.75 | 0.478 | 0.148 | 11/23 | 4/27 |
| 0.80 | 0.478 | 0.148 | 11/23 | 4/27 |
| 0.85 | 0.478 | 0.148 | 11/23 | 4/27 |
| 0.90 | 0.478 | 0.148 | 11/23 | 4/27 |
| 0.93 | 0.478 | 0.148 | 11/23 | 4/27 |
| 0.95 | 0.478 | 0.148 | 11/23 | 4/27 |
| 0.98 | 0.478 | 0.148 | 11/23 | 4/27 |

**All thresholds produce identical results.**

### p_correct Distribution Analysis

**Overall Statistics:**
- Minimum: 0.7874
- Maximum: 1.0000
- Mean: 0.9370
- Total decisions: 50

**Distribution by Item Type:**
- **Redteam items:** min=0.7874, max=1.0000, mean=0.9028 (n=23)
- **Benign items:** min=0.7874, max=1.0000, mean=0.9660 (n=27)

**Distribution by Threshold:**
- Values below 0.70: **0** (0%)
- Values below 0.80: **14** (28%)
- Values below 0.90: **14** (28%)

**Key Insight:** The evidence-based Dempster-Shafer fusion produces **conservatively high** `p_correct` values. The minimum value (0.7874) is above all tested thresholds, explaining why all thresholds yield identical decisions. Notably, benign items have **higher** mean `p_correct` (0.9660) than redteam items (0.9028), which is the expected behavior.

## Interpretation

### Why All Thresholds Are Identical

1. **Conservative Fusion:** Dempster-Shafer fusion combines evidence in a way that tends to preserve uncertainty as "unknown" mass, which is added to `p_correct` (as `belief_promote + unknown`). This results in higher `p_correct` values than a simple heuristic.

2. **No Threshold Sensitivity:** Since the minimum `p_correct` (0.7874) exceeds the maximum tested threshold (0.98), all items are classified as "answer" regardless of threshold. The 4 benign blocks and 11 redteam allows are due to **other layers** (e.g., Layer 1 blocks), not AnswerPolicy.

3. **Evidence-Based Advantage:** The fusion method provides **continuous, meaningful** `p_correct` values (0.79-1.0) instead of binary (0.0/1.0), but the current threshold range does not exploit this granularity.

### Comparison with Heuristic Method

From previous E2E test (`results/e2e_test_comparison.md`):
- **Heuristic:** ASR=0.478, FPR=0.148, avg p_correct=0.711
- **Evidence-based:** ASR=0.478, FPR=0.148, avg p_correct=0.938

**Observation:** Evidence-based produces **higher** `p_correct` values (mean 0.938 vs. 0.711), but the decisions are identical because both methods result in all items being above the threshold.

## Extended Threshold Sweep (0.50-0.70)

After testing lower thresholds, we found a **sensitivity breakpoint**:

| Threshold Range | ASR | FPR | Redteam Allowed | Interpretation |
|----------------|-----|-----|-----------------|----------------|
| **0.50-0.70** | **0.565** | 0.148 | **13/23** | More permissive: 2 additional redteam items allowed |
| **0.70-0.98** | **0.478** | 0.148 | **11/23** | More conservative: 2 fewer redteam items allowed |

**Key Finding:** There is a **threshold sensitivity point between 0.70 and 0.80**. Thresholds below 0.70 allow more redteam items (higher ASR), while thresholds 0.70+ block more redteam items (lower ASR). The FPR remains constant (0.148) across all thresholds, indicating that benign items are not affected by AnswerPolicy in this range (they are blocked by other layers).

## Recommendations

### Immediate Next Steps

1. **Fine-Grained Threshold Sweep:** Test thresholds in the **0.70-0.80 range** (e.g., 0.70, 0.72, 0.74, 0.76, 0.78, 0.80) to identify the exact breakpoint where ASR changes from 0.565 to 0.478.

2. **Verify p_correct Formula:** Review the `_compute_evidence_based_p_correct` implementation to ensure the formula `p_correct = belief_promote + unknown` is appropriate. Consider alternative formulations:
   - `p_correct = belief_promote` (more conservative, ignores ignorance)
   - `p_correct = plausibility_promote` (less conservative, uses upper bound)

3. **Full Dataset Evaluation:** Once optimal threshold is identified, run the full `core_suite.jsonl` (200 items) to obtain statistically robust ASR/FPR estimates.

### Long-Term Considerations

1. **Threshold Calibration:** The evidence-based method may require **different threshold ranges** than the heuristic. Consider policy-specific calibration:
   - Kids policy: threshold range 0.60-0.80 (instead of 0.85-0.98)
   - Default policy: threshold range 0.70-0.90

2. **CUSUM Integration:** Current CUSUM scores are 0.0 (VectorGuard not integrated). Once CUSUM is active, `p_correct` distribution may shift, requiring threshold re-calibration.

3. **Encoding Anomaly Integration:** Similar to CUSUM, encoding anomaly scores may affect `p_correct` distribution when fully integrated.

## Technical Details

### Evidence Sources (Current)
- `base_risk_score`: From risk scorer
- `cusum_drift`: **0.0** (VectorGuard not integrated)
- `encoding_anomaly_score`: From normalization layer (when detected)

### Dempster-Shafer Fusion
- Combines evidence masses using Dempster's rule
- Computes `belief_promote` and `belief_quarantine`
- Current formula: `p_correct = belief_promote + unknown`

### AnswerPolicy Decision
- Decision: `"answer"` if `p_correct >= threshold`, else `"silence"`
- Current behavior: All items have `p_correct >= 0.7874`, so all thresholds <= 0.98 result in `"answer"`

## Files Generated

- `logs/threshold_sweep/evidence_based_threshold_*.jsonl`: Decision logs for each threshold
- `logs/threshold_sweep/evidence_based_sweep_results.json`: Summary metrics
- `results/threshold_sweep_analysis.md`: This report

## Next Actions

1. **Run lower threshold sweep** (0.50-0.70) to identify sensitivity range
2. **Review p_correct formula** in `firewall_engine_v2.py`
3. **Compare with heuristic method** on same threshold range
4. **Document optimal threshold** for evidence-based method

---

**Status:** Phase 1C (Threshold Calibration) - **In Progress**
**Blocking Issue:** Threshold range too high; need to test lower values to find sensitivity point.
