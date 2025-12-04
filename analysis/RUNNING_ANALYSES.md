# Running Analyses - Background Jobs

## Started Analyses (Background)

**Timestamp:** 2025-12-04

### 1. False Positive Analysis (Kids Policy)
```bash
python scripts/analyze_false_positives_for_risk_scorer.py \
    --results logs/kids_core_suite_full_core_suite.jsonl \
    --output analysis/false_positive_analysis_kids.json
```
**Status:** Running in background
**Purpose:** Identify false positive patterns to improve risk scorer

### 2. Threshold Calibration (Kids Policy)
```bash
python scripts/calibrate_risk_scorer_thresholds.py \
    --results logs/kids_core_suite_full_core_suite.jsonl \
    --output analysis/threshold_calibration_kids.json \
    --min-threshold 0.0 --max-threshold 1.0 --step 0.01
```
**Status:** Running in background (parallelized with 16-22 workers)
**Purpose:** Find optimal risk score threshold to minimize ASR/FPR

### 3. Discrepancy Analysis (Kids Policy)
```bash
python scripts/analyze_discrepancy_smoke_vs_full.py \
    --smoke-results logs/kids_smoke_test_core_core_suite_smoke.jsonl \
    --full-results logs/kids_core_suite_full_core_suite.jsonl \
    --output analysis/discrepancy_analysis_kids.json
```
**Status:** Running in background
**Purpose:** Analyze why smoke test results differed from full evaluation

### 4. False Positive Analysis (Baseline)
```bash
python scripts/analyze_false_positives_for_risk_scorer.py \
    --results logs/baseline_core_suite_full_core_suite.jsonl \
    --output analysis/false_positive_analysis_baseline.json
```
**Status:** Running in background
**Purpose:** Baseline comparison for false positives

### 5. Discrepancy Analysis (Baseline)
```bash
python scripts/analyze_discrepancy_smoke_vs_full.py \
    --smoke-results logs/baseline_smoke_test_core_core_suite_smoke.jsonl \
    --full-results logs/baseline_core_suite_full_core_suite.jsonl \
    --output analysis/discrepancy_analysis_baseline.json
```
**Status:** Running in background
**Purpose:** Baseline comparison for discrepancy analysis

### 6. Power Analysis
```bash
python scripts/power_analysis_for_experiments.py \
    --baseline-asr 0.56 --baseline-fpr 0.22 \
    --output analysis/power_analysis.json
```
**Status:** Running in background
**Purpose:** Calculate required sample sizes for future experiments

## CPU Configuration Detected

- **Logical Cores:** 24
- **Optimal Workers:**
  - CPU-bound: 22
  - I/O-bound: 22
  - Mixed: 22

## Expected Output Files

All results will be saved to `analysis/` directory:

1. `analysis/false_positive_analysis_kids.json`
2. `analysis/threshold_calibration_kids.json`
3. `analysis/discrepancy_analysis_kids.json`
4. `analysis/false_positive_analysis_baseline.json`
5. `analysis/discrepancy_analysis_baseline.json`
6. `analysis/power_analysis.json`

## Next Steps

After analyses complete:

1. Review false positive patterns to improve risk scorer
2. Apply optimal threshold from calibration
3. Use power analysis for future experiment planning
4. Document findings in HANDOVER_EVIDENCE_BASED_ANSWERPOLICY.md

## Performance Notes

- Threshold calibration is parallelized and will use ~16-22 workers
- Expected completion time: 5-15 minutes for full analyses
- All scripts use auto-detected optimal worker counts
