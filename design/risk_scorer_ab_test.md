# Risk Scorer A/B Test Design

**Date:** 2025-12-04
**Status:** Design Phase
**Owner:** Joerg Bollwahn

---

## Hypothesis

**Primary Hypothesis:**
"Anpassung der UNSAFE_TOPIC-Klassifikationslogik reduziert FPR um 30% ohne ASR-Verschlechterung."

**Null Hypothesis (H0):**
"Die modifizierte Risk-Scorer-Version zeigt keine signifikante FPR-Verbesserung gegenüber der aktuellen Version."

**Alternative Hypothesis (H1):**
"Die modifizierte Risk-Scorer-Version reduziert FPR um mindestens 30% (absolut: von 22% auf 15.4%) ohne ASR-Verschlechterung."

---

## Experimental Design

### Test Type: A/B Test

**Arm A (Control):** Current Risk Scorer with existing UNSAFE_TOPIC logic
**Arm B (Treatment):** Modified Risk Scorer with improved UNSAFE_TOPIC logic

### Randomization

- Random assignment of items to Arm A or Arm B
- Stratified randomization by item type (redteam/benign) to ensure balanced distribution
- Block randomization to ensure equal sample sizes

---

## Required Sample Size

Based on power analysis results (`analysis/power_analysis.json`):

### Primary Metric: FPR Reduction

- **Baseline FPR:** 22% (0.22)
- **Target FPR:** 15.4% (0.22 × 0.70 = 0.154) - 30% reduction
- **Absolute Effect Size:** 6.6 percentage points
- **Relative Effect Size:** 30%

**Power Analysis Results:**
- For 30% FPR reduction (22% → 15.4%):
  - Required sample size: **~984 benign items per group**
  - Total: **1,968 benign items** for comparison
  - Statistical power: 80%
  - Significance level: 5%

### Secondary Metric: ASR (Non-inferiority)

- **Current ASR:** 56-59%
- **Non-inferiority margin:** ≤5% ASR increase acceptable
- Required sample size for non-inferiority test: **~400 redteam items per group**

### Recommended Sample Size

**Minimum viable:**
- 1,000 benign items per arm (2,000 total)
- 400 redteam items per arm (800 total)
- **Total: 2,800 items**

**Ideal (for robust results):**
- 1,500 benign items per arm (3,000 total)
- 500 redteam items per arm (1,000 total)
- **Total: 4,000 items**

---

## Metrics

### Primary Metrics

1. **False Positive Rate (FPR)**
   - Definition: Percentage of benign items incorrectly blocked
   - Measurement: `FP / (FP + TN)`
   - Target: Reduce from 22% to ≤15.4% (30% reduction)
   - Statistical test: Two-proportion z-test
   - Success criterion: p < 0.05 AND absolute reduction ≥6.6%

2. **Attack Success Rate (ASR)**
   - Definition: Percentage of redteam items incorrectly allowed
   - Measurement: `FN / (TP + FN)`
   - Target: Maintain current level (≤59%) or improve
   - Statistical test: Non-inferiority test
   - Success criterion: ASR difference ≤5% (non-inferiority margin)

### Secondary Metrics

1. **True Positive Rate (TPR) / Detection Rate**
   - Definition: Percentage of redteam items correctly blocked
   - Measurement: `TP / (TP + FN)`
   - Target: Maintain or improve

2. **F1 Score**
   - Definition: Harmonic mean of precision and recall
   - Measurement: `2 × (Precision × Recall) / (Precision + Recall)`
   - Target: Improve

3. **Precision**
   - Definition: Percentage of blocked items that are actually threats
   - Measurement: `TP / (TP + FP)`
   - Target: Improve

---

## Experimental Protocol

### Phase 1: Baseline Measurement (Week 1)

1. Run current Risk Scorer on full evaluation dataset
2. Measure baseline FPR and ASR
3. Document current UNSAFE_TOPIC false positive patterns
4. Generate baseline metrics report

### Phase 2: Risk Scorer Modification (Week 2)

1. Analyze 17 UNSAFE_TOPIC false positive cases (from `review/unsafe_topic_fp_review.csv`)
2. Identify root causes:
   - Common linguistic patterns
   - Overly aggressive keyword matching
   - Context-insensitive triggers
3. Implement modifications:
   - Refine keyword lists
   - Add context-aware filtering
   - Adjust category floor values
   - Improve classification logic
4. Code review and testing

### Phase 3: A/B Test Execution (Week 3-4)

1. **Dataset Preparation:**
   - Ensure minimum 2,800 items available
   - Stratified random split: 50% Arm A, 50% Arm B
   - Balance by item type (redteam/benign)

2. **Execution:**
   - Run Arm A (current Risk Scorer) on Arm A dataset
   - Run Arm B (modified Risk Scorer) on Arm B dataset
   - Collect decision metadata for all items

3. **Data Collection:**
   - Store results in separate JSONL files
   - Include: item_id, arm, decision, risk_score, metadata
   - Track execution time and resource usage

### Phase 4: Statistical Analysis (Week 5)

1. **Primary Analysis:**
   - Calculate FPR for Arm A and Arm B
   - Two-proportion z-test for FPR difference
   - Calculate 95% confidence intervals
   - Non-inferiority test for ASR

2. **Secondary Analysis:**
   - Compare TPR, Precision, F1 Score
   - Analyze category-level patterns
   - Identify any new false positives in Arm B

3. **Report Generation:**
   - Statistical significance results
   - Effect sizes and confidence intervals
   - Recommendations for deployment

---

## Success Criteria

### Primary Success Criteria (Must Meet All)

1. **FPR Reduction:**
   - Absolute FPR reduction ≥6.6% (22% → ≤15.4%)
   - Statistical significance: p < 0.05
   - 95% confidence interval for difference does not include zero

2. **ASR Non-Inferiority:**
   - ASR difference ≤5% (non-inferiority margin)
   - 95% confidence interval for difference does not exceed 5%

### Secondary Success Criteria (Should Meet)

1. TPR maintained or improved
2. F1 Score improved
3. No significant increase in latency (>10% overhead)

---

## Risk Mitigation

### Risks

1. **Sample Size Insufficient:**
   - Risk: Results not statistically significant
   - Mitigation: Use power analysis to ensure adequate sample size before test

2. **ASR Degradation:**
   - Risk: Modified Risk Scorer allows more attacks
   - Mitigation: Non-inferiority test with strict margin; immediate rollback if ASR increases >5%

3. **New False Positive Categories:**
   - Risk: Fixing UNSAFE_TOPIC creates new false positives
   - Mitigation: Monitor all false positive categories, not just UNSAFE_TOPIC

4. **Implementation Bugs:**
   - Risk: Modified Risk Scorer has bugs
   - Mitigation: Comprehensive code review and unit tests before A/B test

---

## Timeline

- **Week 1:** Baseline measurement and analysis
- **Week 2:** Risk Scorer modification and testing
- **Week 3-4:** A/B test execution
- **Week 5:** Statistical analysis and reporting

**Total Duration:** 5 weeks

---

## Resources Required

1. **Dataset:**
   - Minimum 2,800 items (1,400 per arm)
   - Ideal: 4,000 items (2,000 per arm)

2. **Compute:**
   - Parallel processing for both arms
   - Estimated time: 1-2 hours per arm with 18 workers

3. **Analysis Tools:**
   - Statistical analysis scripts (already created)
   - Power analysis tools (already created)

---

## Dependencies

1. Completion of UNSAFE_TOPIC false positive analysis (`review/unsafe_topic_fp_review.csv`)
2. Risk Scorer modification based on analysis findings
3. Dataset preparation (ensure sufficient sample size)

---

## Next Steps

1. **Immediate:**
   - Complete manual review of 17 UNSAFE_TOPIC false positives
   - Document root causes and propose modifications

2. **Short-term:**
   - Implement Risk Scorer modifications
   - Build evaluation dataset with required sample size

3. **Medium-term:**
   - Execute A/B test following this protocol
   - Analyze results and make go/no-go decision

---

**Last Updated:** 2025-12-04
**Review Status:** Ready for execution after Risk Scorer modifications
