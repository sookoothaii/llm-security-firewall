# p_correct Metrics Comparison Report

**Date:** 2025-12-03
**Dataset:** `core_suite_smoke.jsonl` (50 items: 23 redteam, 27 benign)
**Method:** Evidence-based (Dempster-Shafer fusion)

## Executive Summary

**Critical Finding:** All four alternative p_correct metrics produce **mathematically equivalent or near-identical results**. The problem is not the formula choice, but the **compressed distribution** produced by the Dempster-Shafer fusion itself.

## Metrics Compared

1. **Current:** `belief_promote + unknown`
2. **One minus belief_quarantine:** `1.0 - belief_quarantine`
3. **Plausibility promote:** `plausibility_promote` (= `1.0 - belief_quarantine`)
4. **Trust score:** `belief_promote / (belief_promote + belief_quarantine)`

## Results

### Metric Statistics

| Metric | Redteam Mean | Benign Mean | Mean Diff | Cohen's d | Range | Std Dev |
|--------|--------------|-------------|-----------|-----------|-------|---------|
| **current** | 0.9028 | 0.9660 | 0.0632 | 0.7058 | 0.2126 | 0.0938 |
| **one_minus_belief_quar** | 0.9028 | 0.9660 | 0.0632 | 0.7058 | 0.2126 | 0.0938 |
| **plausibility_prom** | 0.9028 | 0.9660 | 0.0632 | 0.7058 | 0.2126 | 0.0938 |
| **trust_score** | 0.9006 | 0.9652 | 0.0646 | 0.7052 | 0.2177 | 0.0961 |

**All metrics are mathematically equivalent** (except trust_score, which is nearly identical).

### Raw Dempster-Shafer Masses

**Redteam items:**
- `belief_promote`: mean=0.8905, range=[0.7638, 0.9970]
- `belief_quarantine`: mean=0.0972, range=[0.0000, 0.2126]
- `unknown`: mean=0.0124, range=[0.0030, 0.0236]

**Benign items:**
- `belief_promote`: mean=0.9598, range=[0.7638, 0.9970]
- `belief_quarantine`: mean=0.0340, range=[0.0000, 0.2126]
- `unknown`: mean=0.0062, range=[0.0030, 0.0236]

### Separation Analysis

- **Cohen's d:** 0.7058 (moderate effect size)
- **Overlap:** 52.2% of redteam items have p_correct > benign mean
- **Value range:** 0.2126 (compressed: min=0.7874, max=1.0000)

## Root Cause Analysis

### Why All Metrics Are Equivalent

1. **Mathematical equivalence:**
   - `belief_promote + unknown = 1.0 - belief_quarantine` (by definition of Dempster-Shafer)
   - `plausibility_promote = 1.0 - belief_quarantine` (by definition)
   - `trust_score ≈ belief_promote` when `belief_quarantine` is small

2. **The real problem:** The Dempster-Shafer fusion produces a **compressed distribution**:
   - Minimum p_correct: 0.7874
   - Maximum p_correct: 1.0000
   - Range: only 0.2126
   - This compression occurs because:
     - `belief_quarantine` is very low (mean: 0.0972 for redteam, 0.0340 for benign)
     - `unknown` mass is minimal (mean: 0.0124 for redteam, 0.0062 for benign)
     - Most mass goes to `belief_promote` (mean: 0.8905 for redteam, 0.9598 for benign)

### Why the Distribution Is Compressed

The compression occurs in the **evidence mass creation** (`make_mass` function):
- Evidence sources (risk_score, cusum_drift, encoding_anomaly) are converted to promote confidence via `1.0 - score`
- High promote confidence → high `promote` mass, low `quarantine` mass
- The `allow_ignorance` parameter (0.1-0.2) creates small `unknown` mass
- Dempster-Shafer combination tends to **amplify promote mass** when multiple sources agree

## Recommendations

### Option 1: Adjust Evidence Mass Creation (Recommended)

Modify the `make_mass` function or evidence-to-mass conversion to create **more spread**:

1. **Increase ignorance mass:** Raise `allow_ignorance` from 0.1-0.2 to 0.2-0.3
2. **Non-linear conversion:** Use a power function (e.g., `confidence^0.7`) to spread values
3. **Separate thresholds:** Use different `allow_ignorance` for high vs. low risk items

### Option 2: Post-Process p_correct

Apply a **calibration function** to spread the compressed distribution:

```python
# Example: Linear scaling
p_correct_calibrated = 0.5 + (p_correct - 0.7874) * (0.5 / (1.0 - 0.7874))
# Maps [0.7874, 1.0] → [0.5, 1.0]
```

### Option 3: Use Raw Risk Score for Threshold

Instead of using fused p_correct, use the **raw risk_score** for threshold decisions:
- More direct, less compressed
- But loses the benefit of evidence fusion

### Option 4: Adjust Policy Thresholds

Accept the compressed distribution and **lower the Kids policy threshold** from 0.98 to 0.85-0.90:
- The breakpoint is at ~0.75, so 0.85-0.90 would still be conservative
- Simpler than changing the fusion logic

## Next Steps

1. **Implement Option 1:** Modify evidence mass creation to increase spread
2. **Re-run threshold sweep:** Test new distribution with thresholds 0.50-0.99
3. **Compare results:** Verify improved sensitivity and separation
4. **Full dataset evaluation:** Run on `core_suite.jsonl` (200 items) with optimized formula

## Technical Details

### Current Implementation

The engine uses `p_correct = 1.0 - belief_quarantine` (line 441 in `firewall_engine_v2.py`), which is equivalent to `belief_promote + unknown` due to Dempster-Shafer constraints.

### Evidence Sources

- `risk_scorer`: From base risk score (primary source)
- `cusum_drift`: **Currently 0.0** (VectorGuard not integrated)
- `encoding_anomaly`: From normalization layer (when detected)

The lack of CUSUM integration may contribute to compression, as only one active evidence source (risk_score) is available.

---

**Status:** Metrics comparison complete. Root cause identified: compressed Dempster-Shafer distribution, not formula choice.
**Recommendation:** Adjust evidence mass creation parameters to increase distribution spread.
