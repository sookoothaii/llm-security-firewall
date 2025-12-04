# Evaluation Protocol - Binding Rules

**Version:** 1.0
**Date:** 2025-12-04
**Status:** MANDATORY - All experiments must follow these rules

---

## Purpose

This protocol establishes mandatory rules for all experimental evaluations in the llm-security-firewall project. These rules prevent the issues identified in the Evidence-Based AnswerPolicy evaluation, where misleading smoke test results led to incorrect performance claims.

---

## MANDATORY RULES

### Rule 1: Smoke Tests are ONLY for Sanity Checks

**Statement:** Smoke tests (10-50 items) are **ONLY** for catching catastrophic failures. Performance metrics from smoke tests **SHALL NOT** be reported or used for decision-making.

**Rationale:**
- Smoke tests have insufficient sample size for reliable performance estimation
- Small-sample volatility creates misleading results (as demonstrated in Evidence-Based AnswerPolicy evaluation)
- Smoke test ASR/FPR metrics are statistically unreliable

**Implementation:**
- Smoke tests may report: "System operational" / "System broken"
- Smoke tests **MUST NOT** report: ASR, FPR, or any performance comparison metrics
- All performance claims **MUST** be based on full, representative dataset evaluation

**Violation Example (FORBIDDEN):**
```
❌ "Smoke test shows 47.8% ASR improvement"
❌ "FPR reduced to 14.8% in smoke test"
```

**Correct Usage:**
```
✅ "Smoke test: All 50 items processed successfully, no crashes"
✅ "Smoke test: System operational, proceeding to full evaluation"
```

---

### Rule 2: Power Analysis Required Before Experiments

**Statement:** Every experiment **SHALL** perform power analysis **BEFORE** data collection to determine required sample size. A `power_analysis.json` file **MUST** exist before experiment execution.

**Rationale:**
- Prevents experiments with insufficient sample size
- Ensures reliable detection of desired effect sizes
- Prevents wasted effort on underpowered experiments

**Implementation:**
- Use `scripts/power_analysis_for_experiments.py` to calculate required sample size
- Define:
  - Baseline performance (ASR, FPR)
  - Target effect size (e.g., 5% improvement)
  - Statistical power (default: 80%)
  - Significance level (default: 5%)
- Save results to `power_analysis.json`
- Document in experiment plan

**Required Before Experiment:**
```bash
python scripts/power_analysis_for_experiments.py \
    --baseline-asr 0.56 \
    --baseline-fpr 0.22 \
    --effect-size 0.05 \
    --output power_analysis.json
```

**Sample Size Requirements (from power analysis):**
- For 5% ASR improvement: ~1,560 redteam items per group
- For 5% FPR improvement: ~984 benign items per group
- Current 200-item dataset can only detect ~13-14% improvements reliably

**Violation Example (FORBIDDEN):**
```
❌ Running experiment on 50 items without power analysis
❌ Claiming "5% improvement" with sample size that can only detect 13%+
```

---

### Rule 3: Statistical Significance Required for Performance Comparisons

**Statement:** For any performance comparison (ASR, FPR, or other metrics), statistical significance (p < 0.05) **MUST** be demonstrated. Overlapping confidence intervals **SHALL** be interpreted as "no significant difference."

**Rationale:**
- Prevents false claims of improvement from random variation
- Ensures scientific rigor in evaluation
- Prevents deployment of non-validated improvements

**Implementation:**
- Calculate confidence intervals for **difference** between methods (not just individual methods)
- Use appropriate statistical tests:
  - Two-proportion z-test for ASR/FPR comparisons
  - Agresti-Coull confidence intervals for proportional data
  - Bootstrap confidence intervals (1000+ samples) for validation
- Report: Effect size, p-value, confidence intervals

**Required Reporting Format:**
```markdown
**Statistical Validation:**
- Absolute difference: +3.0% (ASR)
- 95% Confidence Interval for Difference: (-8.4%, +14.4%)
- **Conclusion:** CI crosses zero → NOT STATISTICALLY SIGNIFICANT
- p-value: 0.15 (> 0.05 threshold)
```

**Success Criteria:**
- ✅ p < 0.05 AND confidence interval for difference does NOT cross zero
- ❌ p >= 0.05 OR confidence interval crosses zero = NO SIGNIFICANT DIFFERENCE

**Violation Example (FORBIDDEN):**
```
❌ "22.7% FPR improvement" (without significance test)
❌ "5.4% ASR reduction" (with overlapping CIs)
❌ "Improved performance" (without statistical validation)
```

**Correct Reporting:**
```
✅ "FPR: 17.0% vs. 22.0% baseline. Difference: -5.0% (95% CI: -15.6% to +5.6%).
    CI crosses zero → NOT STATISTICALLY SIGNIFICANT (p = 0.28)"
```

---

## Implementation Checklist

Before starting any experiment, verify:

- [ ] Power analysis completed and documented
- [ ] Sample size meets power analysis requirements
- [ ] Smoke test plan specifies: sanity checks only, no performance metrics
- [ ] Statistical methods defined before data collection
- [ ] Success criteria defined (including significance thresholds)

After experiment completion:

- [ ] Full dataset evaluation completed (not just smoke test)
- [ ] Confidence intervals calculated for difference (not just individual metrics)
- [ ] Statistical significance tested (p-value reported)
- [ ] Results interpreted correctly (overlapping CIs = no significant difference)
- [ ] Smoke test vs. full evaluation discrepancy analyzed (if applicable)

---

## Examples

### Correct Experiment Flow

1. **Planning Phase:**
   ```bash
   # Define hypothesis
   Hypothesis: "Modified Risk Scorer reduces FPR by 30%"

   # Power analysis
   python scripts/power_analysis_for_experiments.py \
       --baseline-fpr 0.22 \
       --target-fpr 0.154 \
       --power 0.80 \
       --output power_analysis.json

   # Result: Need 984 benign items per group (1,968 total)
   ```

2. **Smoke Test (Sanity Check):**
   ```bash
   # Run on 50 items
   python scripts/run_answerpolicy_experiment.py \
       --input datasets/smoke_test.jsonl \
       --output logs/smoke_test.jsonl

   # Report: "Smoke test passed - all items processed successfully"
   # DO NOT report ASR/FPR from smoke test
   ```

3. **Full Evaluation:**
   ```bash
   # Run on full dataset (1,968+ items)
   python scripts/run_answerpolicy_experiment.py \
       --input datasets/full_evaluation.jsonl \
       --output logs/full_evaluation.jsonl
   ```

4. **Statistical Analysis:**
   ```bash
   # Calculate confidence intervals for difference
   python scripts/compute_answerpolicy_effectiveness.py \
       --baseline logs/baseline_results.jsonl \
       --treatment logs/modified_results.jsonl \
       --output analysis/statistical_validation.json

   # Check: p < 0.05? CI does not cross zero?
   ```

5. **Reporting:**
   ```markdown
   **Results:**
   - FPR: 15.4% (treatment) vs. 22.0% (baseline)
   - Difference: -6.6% (95% CI: -10.2% to -3.0%)
   - p-value: 0.003
   - **Conclusion:** STATISTICALLY SIGNIFICANT (p < 0.05, CI does not cross zero)
   ```

### Incorrect Experiment Flow (FORBIDDEN)

1. ❌ Run smoke test, report "47.8% ASR improvement"
2. ❌ Start experiment without power analysis
3. ❌ Use 200 items to claim "5% improvement"
4. ❌ Report "22.7% FPR reduction" without significance test
5. ❌ Deploy based on overlapping confidence intervals

---

## Enforcement

**These rules are MANDATORY for all experiments.** Violations result in:

1. Results cannot be used for deployment decisions
2. Experiment must be repeated with proper protocol
3. Documentation must be corrected

**Review Points:**
- Pre-experiment review: Verify power analysis exists
- Post-experiment review: Verify statistical significance demonstrated
- Deployment review: Verify all three rules followed

---

## Related Documents

- `docs/HANDOVER_EVIDENCE_BASED_ANSWERPOLICY.md` - Section 10: Evaluation Protocol Recommendations
- `analysis/power_analysis.json` - Power analysis results
- `scripts/power_analysis_for_experiments.py` - Power analysis tool
- `PROJECT_STATUS.md` - Current project status

---

**Last Updated:** 2025-12-04
**Authority:** Joerg Bollwahn
**Review Frequency:** After each major experiment
