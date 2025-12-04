# Analysis Results Summary

**Date:** 2025-12-04
**Status:** All analyses completed successfully

## Executive Summary

All 6 background analyses have completed successfully using optimized parallelization (22 workers on 24-core CPU).

## Key Findings

### 1. False Positive Analysis (Kids Policy)

**Current FPR:** 22.0% (22/100 benign items blocked)

**Risk Score Distribution:**
- False Positives: mean=0.81, median=1.0, range=[0.15, 1.0]
- All Benign: mean=0.18, median=0.0, range=[0.0, 1.0]

**Primary Cause:**
- **UNSAFE_TOPIC category** accounts for 17/22 (77%) of false positives
- Risk scores for false positives are very high (mean 0.81)

**Recommendations:**
- Review UNSAFE_TOPIC detection logic - too aggressive for benign content
- Consider lowering risk threshold or refining category detection

### 2. Threshold Calibration (Kids Policy)

**File:** `threshold_calibration_kids.json` (33KB - full sweep results)

Analysis completed with parallel processing (16-22 workers). Contains full threshold sweep from 0.0 to 1.0 with 0.01 step size (101 thresholds evaluated).

### 3. Discrepancy Analysis (Kids Policy)

**Smoke Test vs. Full Evaluation:**
- Smoke test: 50 items (27 benign, 23 redteam)
- Full evaluation: 200 items (100 benign, 100 redteam)
- Label distribution difference: 4% (54% benign in smoke vs. 50% in full)

**Key Finding:**
- Small sample size (50 items) created non-representative distribution
- Confirms smoke tests should only be used for sanity checks, not performance metrics

### 4. Power Analysis

**For 5% ASR Improvement:**
- Required sample size: **1,560 redteam items per group**
- Total: 3,120 redteam items for comparison
- Current dataset: 100 redteam items (insufficient for reliable detection)

**For 5% FPR Improvement:**
- Required sample size: **984 benign items per group**
- Total: 1,968 benign items for comparison
- Current dataset: 100 benign items (insufficient for reliable detection)

**Minimum Detectable Effect (with 200 items):**
- ASR: ~13.9% (need much larger sample for 5% improvement)
- FPR: ~11.6% (need much larger sample for 5% improvement)

**Recommendation:**
- Current 200-item dataset can only reliably detect very large improvements (>13%)
- For reliable 5% improvement detection, need ~1,500-2,000 items per group

### 5. Baseline Comparisons

**False Positive Analysis (Baseline):** Completed
**Discrepancy Analysis (Baseline):** Completed

Available for comparison with Kids policy results.

## Performance Notes

- **CPU Detected:** 24 logical cores (Intel64 Family 6 Model 151)
- **Optimal Workers Used:** 22 workers for all analyses
- **Parallelization:** All analyses utilized full CPU power
- **Execution Time:** All analyses completed in <1 minute

## Next Steps

1. **Immediate Actions:**
   - Review UNSAFE_TOPIC category logic to reduce false positives
   - Analyze threshold calibration results to find optimal threshold
   - Document findings in HANDOVER_EVIDENCE_BASED_ANSWERPOLICY.md

2. **Short-Term:**
   - Apply optimal threshold from calibration
   - Test threshold changes on validation dataset
   - Monitor FPR improvement

3. **Long-Term:**
   - Build larger evaluation dataset (1,500-2,000 items) for reliable 5% improvement detection
   - Implement rigorous evaluation protocol with power analysis
   - Focus engineering effort on Risk Scorer improvement (identified root cause)

## Files Generated

1. `analysis/false_positive_analysis_kids.json` (1.7 KB)
2. `analysis/threshold_calibration_kids.json` (33 KB)
3. `analysis/discrepancy_analysis_kids.json` (3.0 KB)
4. `analysis/false_positive_analysis_baseline.json` (1.7 KB)
5. `analysis/discrepancy_analysis_baseline.json` (1.8 KB)
6. `analysis/power_analysis.json` (2.1 KB)

All files are available in the `analysis/` directory for detailed review.
